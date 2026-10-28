//! Bitcoin PSBTs: what one does, in the manager's own words, the sighash each input signs, and the
//! signed PSBT built from a signer's answer. Ported from keystore_module's K0 reading; the manager
//! holds no key, so the account's signer signs the sighashes and the manager checks every one.

use std::str::FromStr;

use bitcoin::bip32::DerivationPath;
use bitcoin::consensus::Encodable;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, UntweakedPublicKey};
use bitcoin::psbt::{self as bpsbt, Psbt};
use bitcoin::secp256k1::{ecdsa, schnorr, Message, Secp256k1, Verification};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Address, Amount, EcdsaSighashType, Network, ScriptBuf, TapSighashType, TxIn, TxOut};
use logos_signer_interface::{HashItem, Scheme, Signature};

use crate::btc::{self, AccountPublic, Family};
use crate::error::{ManagerError, Result};

fn bad(msg: impl Into<String>) -> ManagerError {
    ManagerError::InvalidParams(format!("psbt: {}", msg.into()))
}

/// A PSBT the manager has read and accepts to sign, and what it found in it.
#[derive(Debug)]
pub struct Checked {
    /// What the signer shows, verbatim; the first line names the network and the wallet.
    pub lines: Vec<String>,
    /// The bytes the approval commitment covers: the transaction and what the lines say about it.
    pub canonical: Vec<u8>,
    pub fee: Amount,
    /// Each input's `<change>/<index>` under the account, proved by derivation.
    pub keys: Vec<(u32, u32)>,
    /// Each input's previous output, as checked.
    pub prevouts: Vec<TxOut>,
}

pub fn parse(s: &str) -> Result<Psbt> {
    Psbt::from_str(s.trim()).map_err(|e| bad(e.to_string()))
}

/// Read a PSBT against one account, refusing anything this wallet would not sign.
pub fn check<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    network: Network,
    wallet: &str,
    psbt: &Psbt,
) -> Result<Checked> {
    let tx = &psbt.unsigned_tx;
    if tx.input.is_empty() || tx.output.is_empty() {
        return Err(bad("a transaction needs inputs and outputs"));
    }
    // A coin spent twice would be counted twice in the fee shown.
    let mut spent = std::collections::BTreeSet::new();
    if !tx.input.iter().all(|i| spent.insert(i.previous_output)) {
        return Err(bad("a coin is spent twice"));
    }
    let mut canonical = b"psbt\n".to_vec();
    canonical.extend_from_slice(network.to_core_arg().as_bytes());
    canonical.push(b'\n');
    tx.consensus_encode(&mut canonical).expect("writing to a Vec cannot fail");

    let mut total_in = Amount::ZERO;
    let mut witness = 0usize;
    let mut rbf = false;
    let (mut keys, mut prevouts) = (Vec::new(), Vec::new());
    for (i, (txin, input)) in tx.input.iter().zip(&psbt.inputs).enumerate() {
        refuse_unsignable(i, input)?;
        let prev = previous_output(i, acct.family, txin, input)?;
        check_sighash(i, acct.family, input)?;
        let (change, index) = owned_input(secp, acct, i, input, &prev.script_pubkey)?;
        total_in = total_in.checked_add(prev.value).ok_or_else(|| bad("input amounts overflow"))?;
        // Largest signature each can carry: DER plus sighash byte, or 64 bytes of Schnorr.
        witness += match acct.family {
            Family::Segwit => 1 + 1 + 73 + 1 + 33,
            Family::Taproot => 1 + 1 + 64 + usize::from(input.sighash_type.is_some()),
        };
        rbf |= txin.sequence.is_rbf();
        canonical.extend_from_slice(&prev.value.to_sat().to_le_bytes());
        prev.script_pubkey.consensus_encode(&mut canonical).expect("writing to a Vec cannot fail");
        canonical.extend_from_slice(&change.to_le_bytes());
        canonical.extend_from_slice(&index.to_le_bytes());
        canonical.push(input.sighash_type.map_or(0xff, |t| t.to_u32() as u8));
        keys.push((change, index));
        prevouts.push(prev);
    }

    let origin = acct.origin();
    let mut total_out = Amount::ZERO;
    let mut out_lines = Vec::new();
    for (txout, output) in tx.output.iter().zip(&psbt.outputs) {
        total_out = total_out.checked_add(txout.value).ok_or_else(|| bad("output amounts overflow"))?;
        match owned_output(secp, acct, output, &txout.script_pubkey) {
            Some((change, index)) => {
                let what = if change == 1 { "Change" } else { "Receive" };
                out_lines.push(format!(
                    "{what} {} BTC back to this wallet (m/{}/{change}/{index}, checked)",
                    btc_amount(txout.value),
                    origin.to_string().trim_start_matches("m/")
                ));
                canonical.push(1);
                canonical.extend_from_slice(&change.to_le_bytes());
                canonical.extend_from_slice(&index.to_le_bytes());
            }
            None => {
                out_lines.push(describe_payment(txout, network));
                canonical.push(0);
            }
        }
    }
    let fee = total_in.checked_sub(total_out).ok_or_else(|| bad("the outputs spend more than the inputs hold"))?;

    // The signed size, at the largest each signature can be, so the rate shown is never above the real one.
    let weight = tx.base_size() * 4 + 2 + witness;
    let vsize = weight.div_ceil(4) as u64;
    let tenths = (fee.to_sat() * 10 + vsize / 2) / vsize;
    let n = tx.input.len();

    let mut lines = vec![format!(
        "Bitcoin {} · wallet {wallet}, {}, account {}",
        btc::network_name(network),
        acct.family.describe(),
        acct.account
    )];
    lines.extend(out_lines);
    lines.push(format!(
        "Fee {} sats, about {}.{} sat/vB, computed from the inputs",
        grouped(fee.to_sat()),
        tenths / 10,
        tenths % 10
    ));
    lines.push(format!(
        "Spends {n} coin{} worth {} BTC{}",
        if n == 1 { "" } else { "s" },
        btc_amount(total_in),
        if rbf { " · replaceable (RBF)" } else { "" }
    ));
    Ok(Checked { lines, canonical, fee, keys, prevouts })
}

fn tap_sighash_type(input: &bpsbt::Input) -> TapSighashType {
    match input.sighash_type.map(|t| t.taproot_hash_ty()) {
        Some(Ok(TapSighashType::All)) => TapSighashType::All,
        _ => TapSighashType::Default,
    }
}

/// What the account's signer signs: one sighash per input, at the input's own path.
pub fn hash_items(acct: &AccountPublic, psbt: &Psbt, checked: &Checked) -> Result<Vec<HashItem>> {
    let mut cache = SighashCache::new(&psbt.unsigned_tx);
    let origin = acct.origin_string();
    let mut items = Vec::with_capacity(checked.keys.len());
    for (i, ((change, index), prev)) in checked.keys.iter().zip(&checked.prevouts).enumerate() {
        let (scheme, digest) = match acct.family {
            Family::Segwit => {
                let h = cache
                    .p2wpkh_signature_hash(i, &prev.script_pubkey, prev.value, EcdsaSighashType::All)
                    .map_err(|e| bad(format!("input {i}: {e}")))?;
                (Scheme::Ecdsa, h.to_byte_array())
            }
            Family::Taproot => {
                let ty = tap_sighash_type(&psbt.inputs[i]);
                let h = cache
                    .taproot_key_spend_signature_hash(i, &Prevouts::All(&checked.prevouts), ty)
                    .map_err(|e| bad(format!("input {i}: {e}")))?;
                (Scheme::Bip86, h.to_byte_array())
            }
        };
        items.push(HashItem { path: Some(format!("{origin}/{change}/{index}")), scheme, digest: hex::encode(digest) });
    }
    Ok(items)
}

/// Put each signature into its input once it verifies against the key at that input's path, over
/// the sighash this module computed. One for every input, or nothing is added.
pub fn insert_signatures<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    psbt: &mut Psbt,
    checked: &Checked,
    items: &[HashItem],
    sigs: &[Signature],
) -> Result<()> {
    let wrong = |i: usize, why: &str| ManagerError::Signing(format!("psbt: input {i}: {why}"));
    let mut placed = vec![false; items.len()];
    let mut out = psbt.clone();
    for sig in sigs {
        let i = sig.item;
        let (item, &(change, index)) = match (items.get(i), checked.keys.get(i)) {
            (Some(item), Some(at)) => (item, at),
            _ => return Err(wrong(i, "a signature for an input this request doesn't have")),
        };
        if std::mem::replace(&mut placed[i], true) {
            return Err(wrong(i, "two signatures"));
        }
        let bytes = hex::decode(&sig.signature).map_err(|_| wrong(i, "a signature that isn't hex"))?;
        let digest: [u8; 32] = hex::decode(&item.digest).ok().and_then(|d| d.try_into().ok()).ok_or_else(|| wrong(i, "digest"))?;
        let msg = Message::from_digest(digest);
        let key = acct.key_at(secp, change, index)?;
        match acct.family {
            Family::Segwit => {
                let s = ecdsa::Signature::from_compact(&bytes).map_err(|_| wrong(i, "not an ECDSA signature"))?;
                let mut low = s;
                low.normalize_s();
                if low != s {
                    return Err(wrong(i, "a high-S signature"));
                }
                secp.verify_ecdsa(&msg, &s, &key.0).map_err(|_| wrong(i, "the signature does not verify"))?;
                out.inputs[i].partial_sigs.insert(
                    bitcoin::PublicKey::new(key.0),
                    bitcoin::ecdsa::Signature { signature: s, sighash_type: EcdsaSighashType::All },
                );
            }
            Family::Taproot => {
                let s = schnorr::Signature::from_slice(&bytes).map_err(|_| wrong(i, "not a BIP340 signature"))?;
                let (output, _) = UntweakedPublicKey::from(key.0).tap_tweak(secp, None);
                secp.verify_schnorr(&s, &msg, &output.to_x_only_public_key())
                    .map_err(|_| wrong(i, "the signature does not verify"))?;
                let sighash_type = tap_sighash_type(&psbt.inputs[i]);
                out.inputs[i].tap_key_sig = Some(bitcoin::taproot::Signature { signature: s, sighash_type });
            }
        }
    }
    if let Some(i) = placed.iter().position(|p| !p) {
        return Err(wrong(i, "no signature"));
    }
    *psbt = out;
    Ok(())
}

/// Already signed, a script path, or a multi-key script: none of it is a single-key spend this wallet signs.
fn refuse_unsignable(i: usize, input: &bpsbt::Input) -> Result<()> {
    if !input.partial_sigs.is_empty()
        || input.tap_key_sig.is_some()
        || !input.tap_script_sigs.is_empty()
        || input.final_script_sig.is_some()
        || input.final_script_witness.is_some()
    {
        return Err(bad(format!("input {i} is already signed")));
    }
    if !input.tap_scripts.is_empty() || input.tap_merkle_root.is_some() {
        return Err(bad(format!("input {i} spends a taproot script path, which this wallet doesn't sign")));
    }
    if input.redeem_script.is_some() || input.witness_script.is_some() {
        return Err(bad(format!("input {i} spends a script, not a single key")));
    }
    Ok(())
}

/// The output an input spends, checked against its whole previous transaction where there is one.
fn previous_output(i: usize, family: Family, txin: &TxIn, input: &bpsbt::Input) -> Result<TxOut> {
    let from_tx = match &input.non_witness_utxo {
        Some(prev) => {
            if prev.compute_txid() != txin.previous_output.txid {
                return Err(bad(format!("input {i}'s previous transaction is not the one it spends")));
            }
            let out = prev.output.get(txin.previous_output.vout as usize).cloned();
            Some(out.ok_or_else(|| bad(format!("input {i} spends an output its previous transaction doesn't have")))?)
        }
        None => None,
    };
    match (family, from_tx, &input.witness_utxo) {
        // A segwit v0 signature commits only to its own input's amount: the 2020 fee attack.
        (Family::Segwit, None, _) => Err(bad(format!(
            "input {i} has no previous transaction, which a native segwit input needs so its amount can be checked"
        ))),
        (_, Some(full), Some(w)) if full != *w => {
            Err(bad(format!("input {i}'s amount disagrees with its previous transaction")))
        }
        (_, Some(full), _) => Ok(full),
        (Family::Taproot, None, Some(w)) => Ok(w.clone()),
        (Family::Taproot, None, None) => Err(bad(format!("input {i} has no previous output"))),
    }
}

fn check_sighash(i: usize, family: Family, input: &bpsbt::Input) -> Result<()> {
    let Some(ty) = input.sighash_type else { return Ok(()) };
    let ok = match family {
        Family::Segwit => matches!(ty.ecdsa_hash_ty(), Ok(EcdsaSighashType::All)),
        Family::Taproot => matches!(ty.taproot_hash_ty(), Ok(TapSighashType::Default | TapSighashType::All)),
    };
    if ok {
        Ok(())
    } else {
        Err(bad(format!("input {i} asks for sighash {ty}; this wallet signs only ALL")))
    }
}

/// `<change>/<index>` of the one key of this account an input names, proved by deriving it.
fn owned_input<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    i: usize,
    input: &bpsbt::Input,
    script: &ScriptBuf,
) -> Result<(u32, u32)> {
    let mut found = None;
    let mut claim = |path: &DerivationPath| -> Result<(u32, u32)> {
        let at = acct.relative(path).ok_or_else(|| bad(format!("input {i} names a path outside this wallet's account: {path}")))?;
        if found.replace(at).is_some() {
            return Err(bad(format!("input {i} names this wallet's keys twice")));
        }
        Ok(at)
    };
    match acct.family {
        Family::Segwit => {
            for (pk, (fp, path)) in &input.bip32_derivation {
                if *fp != acct.fingerprint {
                    continue;
                }
                let (c, idx) = claim(path)?;
                if acct.key_at(secp, c, idx)?.0 != *pk {
                    return Err(bad(format!("input {i}'s key is not the one at {path}")));
                }
            }
        }
        Family::Taproot => {
            let internal = input.tap_internal_key;
            for (xonly, (leaves, (fp, path))) in &input.tap_key_origins {
                if *fp != acct.fingerprint {
                    continue;
                }
                if !leaves.is_empty() {
                    return Err(bad(format!("input {i} asks for a script-path signature")));
                }
                let (c, idx) = claim(path)?;
                let key = UntweakedPublicKey::from(acct.key_at(secp, c, idx)?.0);
                if key != *xonly || Some(key) != internal {
                    return Err(bad(format!("input {i}'s key is not the one at {path}")));
                }
            }
        }
    }
    let (c, idx) = found.ok_or_else(|| bad(format!("input {i} is not this wallet's to sign")))?;
    if acct.script_at(secp, c, idx)? != *script {
        return Err(bad(format!("input {i} spends a script this wallet's key doesn't control")));
    }
    Ok((c, idx))
}

/// An output is this wallet's only if deriving the path it claims gives its script. Change is checked, not trusted.
fn owned_output<C: Verification>(
    secp: &Secp256k1<C>,
    acct: &AccountPublic,
    output: &bpsbt::Output,
    script: &ScriptBuf,
) -> Option<(u32, u32)> {
    let claimed: Vec<(u32, u32)> = match acct.family {
        Family::Segwit => output
            .bip32_derivation
            .values()
            .filter(|(fp, _)| *fp == acct.fingerprint)
            .filter_map(|(_, path)| acct.relative(path))
            .collect(),
        Family::Taproot => output
            .tap_key_origins
            .values()
            .filter(|(leaves, (fp, _))| leaves.is_empty() && *fp == acct.fingerprint)
            .filter_map(|(_, (_, path))| acct.relative(path))
            .collect(),
    };
    claimed.into_iter().find(|(c, i)| acct.script_at(secp, *c, *i).is_ok_and(|s| s == *script))
}

fn describe_payment(out: &TxOut, network: Network) -> String {
    let amount = btc_amount(out.value);
    if out.script_pubkey.is_op_return() {
        return format!("Data output (OP_RETURN, {} bytes) carrying {amount} BTC", out.script_pubkey.len());
    }
    match Address::from_script(&out.script_pubkey, network) {
        Ok(addr) => format!("Send {amount} BTC to {addr}"),
        Err(_) => format!("Send {amount} BTC to a script with no address: {}", hex::encode(out.script_pubkey.as_bytes())),
    }
}

fn btc_amount(a: Amount) -> String {
    let sats = a.to_sat();
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

fn grouped(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}


#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bip32::{DerivationPath as Bip32Path, Prefix, XPrv};
    use bitcoin::bip32::ChildNumber;
    use bitcoin::absolute::LockTime;
    use bitcoin::psbt::PsbtSighashType;
    use bitcoin::transaction::Version;
    use bitcoin::{OutPoint, Sequence, Transaction, Witness};
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Account, Family as WireFamily, Payload, SignRequest, Signer};
    use std::str::FromStr;

    /// The mock signer and its account of `family`, as the manager reads it from the listing.
    pub(crate) fn ours(family: Family) -> (MockSigner, Account, AccountPublic) {
        let mut signer = MockSigner::new(MockOptions::default());
        let want = if family == Family::Segwit { WireFamily::Bitcoin } else { WireFamily::BitcoinTaproot };
        let listed = signer.accounts().unwrap().into_iter().find(|a| a.family == want).unwrap();
        let acct = AccountPublic::from_account(&listed).unwrap();
        (signer, listed, acct)
    }

    /// Someone else's wallet of the same family, from another seed.
    fn theirs(family: Family) -> AccountPublic {
        let path = format!("m/{}'/1'/0'", family.purpose());
        let key = XPrv::derive_from_path([7u8; 64], &Bip32Path::from_str(&path).unwrap()).unwrap();
        let listed = Account {
            id: "theirs".into(),
            family: if family == Family::Segwit { WireFamily::Bitcoin } else { WireFamily::BitcoinTaproot },
            chain: Some(logos_signer_interface::Chain::Test),
            path: Some(path),
            fingerprint: Some("0badc0de".into()),
            address: None,
            xpub: Some(key.public_key().to_string(Prefix::TPUB)),
            label: None,
            available: true,
            key: None,
            seed: None,
        };
        AccountPublic::from_account(&listed).unwrap()
    }

    fn funding(script: ScriptBuf, sats: u64, salt: u32) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(salt),
            input: vec![TxIn { previous_output: OutPoint::null(), ..Default::default() }],
            output: vec![TxOut { value: Amount::from_sat(sats), script_pubkey: script }],
        }
    }

    fn mark(acct: &AccountPublic, change: u32, index: u32) -> (bitcoin::secp256k1::PublicKey, DerivationPath) {
        let key = acct.key_at(&Secp256k1::new(), change, index).unwrap();
        let path = acct.origin().extend([ChildNumber::Normal { index: change }, ChildNumber::Normal { index }]);
        (key.0, path)
    }

    fn mark_input(acct: &AccountPublic, input: &mut bpsbt::Input, change: u32, index: u32) {
        let (key, path) = mark(acct, change, index);
        match acct.family {
            Family::Segwit => {
                input.bip32_derivation.insert(key, (acct.fingerprint, path));
            }
            Family::Taproot => {
                let x = UntweakedPublicKey::from(key);
                input.tap_internal_key = Some(x);
                input.tap_key_origins.insert(x, (vec![], (acct.fingerprint, path)));
            }
        }
    }

    fn mark_output(acct: &AccountPublic, output: &mut bpsbt::Output, change: u32, index: u32) {
        let (key, path) = mark(acct, change, index);
        match acct.family {
            Family::Segwit => {
                output.bip32_derivation.insert(key, (acct.fingerprint, path));
            }
            Family::Taproot => {
                let x = UntweakedPublicKey::from(key);
                output.tap_internal_key = Some(x);
                output.tap_key_origins.insert(x, (vec![], (acct.fingerprint, path)));
            }
        }
    }

    /// Two coins of ours (0/0 and 0/1), a payment to someone else, and change to 1/0, as BDK builds it.
    pub(crate) fn sample(acct: &AccountPublic) -> Psbt {
        let secp = Secp256k1::new();
        let other = theirs(acct.family);
        let prev_a = funding(acct.script_at(&secp, 0, 0).unwrap(), 100_000, 1);
        let prev_b = funding(acct.script_at(&secp, 0, 1).unwrap(), 50_000, 2);
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::from_consensus(150),
            input: [&prev_a, &prev_b]
                .iter()
                .map(|p| TxIn {
                    previous_output: OutPoint { txid: p.compute_txid(), vout: 0 },
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    script_sig: ScriptBuf::new(),
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![
                TxOut { value: Amount::from_sat(120_000), script_pubkey: other.script_at(&secp, 0, 0).unwrap() },
                TxOut { value: Amount::from_sat(28_810), script_pubkey: acct.script_at(&secp, 1, 0).unwrap() },
            ],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).unwrap();
        for (k, (prev, index)) in [(&prev_a, 0), (&prev_b, 1)].into_iter().enumerate() {
            psbt.inputs[k].witness_utxo = Some(prev.output[0].clone());
            if acct.family == Family::Segwit {
                psbt.inputs[k].non_witness_utxo = Some(prev.clone());
            }
            mark_input(acct, &mut psbt.inputs[k], 0, index);
        }
        mark_output(acct, &mut psbt.outputs[1], 1, 0);
        psbt
    }

    fn checked(acct: &AccountPublic, psbt: &Psbt) -> Result<Checked> {
        check(&Secp256k1::new(), acct, Network::Regtest, "\"Savings\"", psbt)
    }

    #[test]
    fn the_lines_name_the_payment_the_change_and_the_fee_the_manager_computed() {
        for family in [Family::Segwit, Family::Taproot] {
            let (_, _, acct) = ours(family);
            let psbt = sample(&acct);
            let c = checked(&acct, &psbt).unwrap();
            assert_eq!(c.fee, psbt.fee().unwrap(), "{family:?}");
            assert_eq!(c.fee.to_sat(), 1_190);
            let all = c.lines.join("\n");
            let purpose = family.purpose();
            assert!(all.starts_with(&format!("Bitcoin regtest · wallet \"Savings\", {}, account 0", family.describe())), "{all}");
            assert!(all.contains("Send 0.00120000 BTC to bcrt1"), "{all}");
            assert!(all.contains(&format!("Change 0.00028810 BTC back to this wallet (m/{purpose}'/1'/0'/1/0, checked)")), "{all}");
            assert!(all.contains("Fee 1,190 sats, about "), "{all}");
            assert!(all.contains("Spends 2 coins worth 0.00150000 BTC · replaceable (RBF)"), "{all}");
            assert_eq!(c.keys, vec![(0, 0), (0, 1)]);
        }
    }

    #[test]
    fn change_that_pays_a_key_outside_the_wallet_is_shown_as_a_send() {
        let (_, _, acct) = ours(Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.output[1].script_pubkey = theirs(Family::Segwit).script_at(&Secp256k1::new(), 1, 0).unwrap();
        let all = checked(&acct, &psbt).unwrap().lines.join("\n");
        assert!(!all.contains("back to this wallet"), "{all}");
        assert_eq!(all.matches("Send ").count(), 2, "{all}");
    }

    #[test]
    fn a_false_input_amount_is_refused_before_anything_is_shown() {
        let (_, _, acct) = ours(Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[0].witness_utxo.as_mut().unwrap().value = Amount::from_sat(10_000);
        assert!(checked(&acct, &psbt).unwrap_err().to_string().contains("amount disagrees"));
    }

    #[test]
    fn a_native_segwit_input_without_its_previous_transaction_is_refused() {
        let (_, _, acct) = ours(Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[1].non_witness_utxo = None;
        assert!(checked(&acct, &psbt).unwrap_err().to_string().contains("no previous transaction"));
        let mut psbt = sample(&acct);
        psbt.inputs[1].non_witness_utxo = psbt.inputs[0].non_witness_utxo.clone();
        assert!(checked(&acct, &psbt).is_err());
    }

    #[test]
    fn a_foreign_input_is_refused() {
        let (_, _, acct) = ours(Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.inputs[1].bip32_derivation.clear();
        assert!(checked(&acct, &psbt).unwrap_err().to_string().contains("not this wallet's"));
        assert!(checked(&theirs(Family::Segwit), &sample(&acct)).is_err());
    }

    #[test]
    fn a_sighash_other_than_all_is_refused() {
        for family in [Family::Segwit, Family::Taproot] {
            let (_, _, acct) = ours(family);
            let mut psbt = sample(&acct);
            psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::SinglePlusAnyoneCanPay));
            assert!(checked(&acct, &psbt).is_err(), "{family:?}");
            let mut psbt = sample(&acct);
            psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(EcdsaSighashType::All));
            assert!(checked(&acct, &psbt).is_ok(), "{family:?}");
        }
    }

    #[test]
    fn a_coin_spent_twice_is_refused() {
        let (_, _, acct) = ours(Family::Segwit);
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.input[1].previous_output = psbt.unsigned_tx.input[0].previous_output;
        psbt.inputs[1] = psbt.inputs[0].clone();
        assert!(checked(&acct, &psbt).unwrap_err().to_string().contains("spent twice"));
    }

    #[test]
    fn outputs_spending_more_than_the_inputs_are_refused() {
        let (_, _, acct) = ours(Family::Taproot);
        let mut psbt = sample(&acct);
        psbt.unsigned_tx.output[0].value = Amount::from_sat(200_000);
        assert!(checked(&acct, &psbt).unwrap_err().to_string().contains("more than the inputs"));
    }

    /// Sign `psbt` through the signer the way the manager does, and return the hash items.
    fn sign_through(signer: &mut MockSigner, listed: &Account, acct: &AccountPublic, psbt: &mut Psbt) -> Result<()> {
        let c = checked(acct, psbt)?;
        let items = hash_items(acct, psbt, &c)?;
        let job = signer
            .sign(SignRequest { account: listed.id.clone(), payload: Payload::Hash { items: items.clone() }, secret: None, xpub: None })
            .unwrap();
        let sigs = signer.result(&job).unwrap();
        insert_signatures(&Secp256k1::new(), acct, psbt, &c, &items, &sigs)
    }

    #[test]
    fn signatures_from_the_signer_verify_against_the_sighash_computed_independently() {
        let secp = Secp256k1::new();
        for family in [Family::Segwit, Family::Taproot] {
            let (mut signer, listed, acct) = ours(family);
            let mut psbt = sample(&acct);
            sign_through(&mut signer, &listed, &acct, &mut psbt).unwrap();
            let prevouts: Vec<TxOut> = psbt.inputs.iter().map(|i| i.witness_utxo.clone().unwrap()).collect();
            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            for (i, index) in [0u32, 1].into_iter().enumerate() {
                let key = acct.key_at(&secp, 0, index).unwrap();
                match family {
                    Family::Segwit => {
                        let h = cache
                            .p2wpkh_signature_hash(i, &prevouts[i].script_pubkey, prevouts[i].value, EcdsaSighashType::All)
                            .unwrap();
                        let sig = psbt.inputs[i].partial_sigs[&bitcoin::PublicKey::new(key.0)];
                        secp.verify_ecdsa(&Message::from_digest(h.to_byte_array()), &sig.signature, &key.0).unwrap();
                    }
                    Family::Taproot => {
                        let h = cache
                            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
                            .unwrap();
                        let sig = psbt.inputs[i].tap_key_sig.unwrap();
                        let (output, _) = UntweakedPublicKey::from(key.0).tap_tweak(&secp, None);
                        secp.verify_schnorr(&sig.signature, &Message::from_digest(h.to_byte_array()), &output.to_x_only_public_key())
                            .unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn a_signature_over_anything_else_adds_nothing() {
        for family in [Family::Segwit, Family::Taproot] {
            let (mut signer, listed, acct) = ours(family);
            let psbt = sample(&acct);
            let c = checked(&acct, &psbt).unwrap();
            let items = hash_items(&acct, &psbt, &c).unwrap();
            // Signatures for the inputs swapped: each verifies, but over the other input's sighash.
            let job = signer
                .sign(SignRequest { account: listed.id.clone(), payload: Payload::Hash { items: items.clone() }, secret: None, xpub: None })
                .unwrap();
            let mut sigs = signer.result(&job).unwrap();
            sigs[0].item = 1;
            sigs[1].item = 0;
            let mut target = psbt.clone();
            assert!(insert_signatures(&Secp256k1::new(), &acct, &mut target, &c, &items, &sigs).is_err(), "{family:?}");
            assert_eq!(target, psbt, "nothing added");
            // One missing signature adds none of them.
            sigs.truncate(1);
            sigs[0].item = 0;
            let mut target = psbt.clone();
            let _ = insert_signatures(&Secp256k1::new(), &acct, &mut target, &c, &items, &sigs);
            assert_eq!(target, psbt, "{family:?}: nothing added");
        }
    }
}
