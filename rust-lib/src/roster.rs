//! One account as every signer that holds it. Signers name the same account differently (a
//! Bitcoin wallet is `g_…` in the keystore, `keycard-…` on a card), so holders are grouped by what
//! the account is: its address, or a Bitcoin account's key.

use logos_signer_interface::unlock::roster_key;
use logos_signer_interface::{Account, Family};
use serde::Serialize;

use crate::registry::Found;

/// The keystore's module: the only signer that signs inside an unlock.
pub const KEYSTORE: &str = "keystore_module";

/// What makes two signers' accounts one: an EVM address without case, or a Bitcoin account's roster
/// key (`btc_` and 32 hex of a hash over its family, chain, chain code and key), as its signer lists
/// it or worked out from its xpub.
pub fn key_of(a: &Account) -> Option<String> {
    if a.family == Family::Evm {
        let address = a.address.as_deref().unwrap_or(&a.id).trim();
        return (!address.is_empty()).then(|| address.to_ascii_lowercase());
    }
    let listed = a.key.as_deref().map(str::trim).filter(|k| {
        k.len() == 36 && k.starts_with("btc_") && k[4..].bytes().all(|b| b.is_ascii_hexdigit())
    });
    match listed {
        Some(k) => Some(k.to_ascii_lowercase()),
        None => roster_key(a.family, a.chain, a.xpub.as_deref()?).ok(),
    }
}

/// How a signer reaches its keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Keystore,
    /// A Keycard in a smart-card reader.
    Reader,
    /// A device over USB: the Keycard Shell, a Ledger or a Trezor.
    Usb,
    /// A wallet that reads and shows QR codes.
    Qr,
    Other,
}

/// Whether a holder can sign now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    /// Keys on this machine.
    Local,
    Connected,
    /// Needs no connection: a QR wallet is reached through the camera when asked.
    OnDemand,
    Absent,
}

/// By the kind the signer says it is, else by its module's name, as a stand-in reports.
pub fn transport(found: &Found) -> Transport {
    match (found.info.kind.as_str(), found.name.as_str()) {
        ("keystore", _) | (_, "keystore_module") => Transport::Keystore,
        ("keycard", _) | (_, "keycard_module") => Transport::Reader,
        ("keycard_shell" | "ledger" | "trezor", _) | (_, "keycard_shell_module") => Transport::Usb,
        ("qr", _) | (_, "qr_signer_module") => Transport::Qr,
        _ => Transport::Other,
    }
}

pub fn presence(found: &Found) -> Presence {
    match (transport(found), found.account.available) {
        (_, false) => Presence::Absent,
        (Transport::Keystore, true) => Presence::Local,
        (Transport::Qr, true) => Presence::OnDemand,
        _ => Presence::Connected,
    }
}

/// What a message calls a holder: its model, else its module.
pub fn device_name(f: &Found) -> String {
    let model = f.info.model.trim();
    if model.is_empty() { f.name.clone() } else { model.to_string() }
}

/// The keystore first, then connected devices (a reader before USB), then QR, then what isn't
/// connected; within each, the configured signer order.
pub fn rank(holders: &mut [Found]) {
    holders.sort_by_key(|f| {
        let within = match (presence(f), transport(f)) {
            (Presence::Connected, Transport::Reader) => 0,
            (Presence::Connected, Transport::Usb) => 1,
            (Presence::Connected, _) => 2,
            _ => 0,
        };
        (presence(f), within, f.signer)
    });
}

/// The account's name: the first given in configured signer order, and every distinct one when
/// holders disagree.
pub fn names(holders: &[Found]) -> (Option<String>, Vec<String>) {
    let mut by_order: Vec<&Found> = holders.iter().collect();
    by_order.sort_by_key(|f| f.signer);
    let mut all: Vec<String> = Vec::new();
    for f in by_order {
        if let Some(l) = f.account.label.as_deref().map(str::trim).filter(|l| !l.is_empty()) {
            if !all.iter().any(|seen| seen == l) {
                all.push(l.to_string());
            }
        }
    }
    let first = all.first().cloned();
    if all.len() < 2 {
        all.clear();
    }
    (first, all)
}

/// The wallet an account comes from: the master fingerprint any holder reports, and the first
/// wallet name in configured signer order, read off each signer's `origin`.
pub fn wallet(holders: &[Found], origin_of: impl Fn(&Found) -> Option<serde_json::Value>) -> serde_json::Value {
    let mut by_order: Vec<&Found> = holders.iter().collect();
    by_order.sort_by_key(|f| f.signer);
    let fingerprint = by_order.iter().find_map(|f| f.account.fingerprint.clone());
    let name = by_order.iter().find_map(|f| {
        let origin = origin_of(f)?;
        origin["phrase"]["name"].as_str().map(str::trim).filter(|n| !n.is_empty()).map(str::to_string)
    });
    if fingerprint.is_none() && name.is_none() {
        return serde_json::Value::Null;
    }
    serde_json::json!({ "fingerprint": fingerprint, "name": name })
}

/// One account of `roster()`: what it is, its names, its wallet and every holder, ranked. Public,
/// and no xpub: it would show a Bitcoin wallet's whole history.
pub fn entry_json(key: &str, holders: &[Found], origin_of: impl Fn(&Found) -> Option<serde_json::Value>) -> serde_json::Value {
    let Some(first) = holders.first() else { return serde_json::Value::Null };
    let (label, labels) = names(holders);
    serde_json::json!({
        "key": key, "family": first.account.family, "chain": first.account.chain,
        "address": first.account.address, "path": holders.iter().find_map(|f| f.account.path.clone()),
        "label": label, "labels": (!labels.is_empty()).then_some(labels),
        "wallet": wallet(holders, origin_of),
        "holders": holders.iter().map(holder_json).collect::<Vec<_>>(),
    })
}

/// A holder as apps see it: public, and no xpub.
pub fn holder_json(f: &Found) -> serde_json::Value {
    serde_json::json!({
        "signer": f.name, "accountId": f.account.id, "kind": f.info.kind, "model": f.info.model,
        "transport": transport(f), "presence": presence(f), "available": f.account.available,
        "collects": f.info.collects, "showsRequest": f.info.shows_request, "requestKinds": f.info.request_kinds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::bip32::Xpub;
    use logos_signer_interface::{Chain, Collects, SignerInfo};
    use std::str::FromStr;

    pub fn found(signer: usize, name: &str, kind: &str, account: Account) -> Found {
        Found {
            signer,
            name: name.into(),
            info: SignerInfo {
                interface: logos_signer_interface::INTERFACE.into(),
                kind: kind.into(),
                model: String::new(),
                families: vec![account.family],
                request_kinds: vec![],
                shows_request: false,
                collects: Collects::Nothing,
                unlock_key: false,
            },
            account,
        }
    }

    fn evm(id: &str, available: bool) -> Account {
        Account {
            id: id.into(),
            family: Family::Evm,
            chain: None,
            path: None,
            fingerprint: None,
            address: Some(id.into()),
            xpub: None,
            label: None,
            available,
            key: None,
            seed: None,
        }
    }

    #[test]
    fn an_evm_account_is_its_address_whatever_its_case() {
        assert_eq!(key_of(&evm("0xAbC", true)), key_of(&evm("0xabc", true)));
    }

    #[test]
    fn a_bitcoin_account_is_its_key_not_its_xpubs_metadata() {
        let (_, mut a, _) = crate::psbt::tests::ours(crate::btc::Family::Segwit);
        assert_eq!(a.chain, Some(Chain::Test));
        let listed = a.key.take();
        assert_eq!(key_of(&a), listed, "the key a signer lists is the one its xpub gives");
        let mut other = Xpub::from_str(a.xpub.as_deref().unwrap()).unwrap();
        other.parent_fingerprint = Default::default();
        let mut b = a.clone();
        (b.id, b.xpub) = ("keycard-1".into(), Some(other.to_string()));
        assert_ne!(a.xpub, b.xpub);
        assert_eq!(key_of(&a), key_of(&b));
        assert!(key_of(&a).unwrap().starts_with("btc_") && key_of(&a).unwrap().len() == 36);
        b.family = Family::BitcoinTaproot;
        assert_ne!(key_of(&a), key_of(&b), "the same key under another script is another account");
        // A signer that lists no xpub is known by the key it lists; a malformed one is ignored.
        let (key, mut c) = (listed.clone().unwrap(), a.clone());
        (c.xpub, c.key) = (None, Some(key.to_ascii_uppercase().replace("BTC_", "btc_")));
        assert_eq!(key_of(&c), listed);
        c.key = Some("btc_nothex".into());
        assert_eq!(key_of(&c), None);
    }

    #[test]
    fn the_keystore_comes_first_then_connected_devices_then_qr_then_the_unplugged() {
        let a = "0xa";
        let mut holders = vec![
            found(0, "keycard_shell_module", "keycard_shell", evm(a, false)),
            found(1, "qr_signer_module", "qr", evm(a, true)),
            found(2, "keycard_shell_module", "keycard_shell", evm(a, true)),
            found(3, "keycard_module", "keycard", evm(a, true)),
            found(4, "keystore_module", "keystore", evm(a, true)),
        ];
        rank(&mut holders);
        let order: Vec<usize> = holders.iter().map(|f| f.signer).collect();
        assert_eq!(order, vec![4, 3, 2, 1, 0]);
        assert_eq!(presence(&holders[3]), Presence::OnDemand);
        assert_eq!(presence(&holders[4]), Presence::Absent);
    }

    #[test]
    fn the_name_is_the_first_given_in_signer_order_and_disagreements_are_kept() {
        let mut first = evm("0xa", true);
        first.label = Some("Savings".into());
        let mut second = evm("0xa", true);
        second.label = Some("Cold".into());
        let holders = vec![found(1, "b", "mock", second), found(0, "a", "mock", first)];
        assert_eq!(names(&holders), (Some("Savings".into()), vec!["Savings".into(), "Cold".into()]));
        assert_eq!(names(&holders[..1]), (Some("Cold".into()), vec![]));
    }

    #[test]
    fn the_wallet_is_named_by_the_first_signer_that_names_it() {
        let mut a = evm("0xa", true);
        a.fingerprint = Some("73c5da0a".into());
        let holders = vec![found(0, "keystore_module", "keystore", a.clone()), found(1, "qr_signer_module", "qr", a)];
        let w = wallet(&holders, |f| {
            (f.name == "qr_signer_module").then(|| serde_json::json!({ "phrase": { "name": "Shell" } }))
        });
        assert_eq!(w, serde_json::json!({ "fingerprint": "73c5da0a", "name": "Shell" }));
        assert!(wallet(&[found(0, "k", "keystore", evm("0xb", true))], |_| None).is_null(), "an imported key");
    }

    #[test]
    fn a_roster_entry_carries_no_xpub() {
        let (_, mut a, _) = crate::psbt::tests::ours(crate::btc::Family::Segwit);
        a.label = Some("Savings".into());
        let e = entry_json("btc_1", &[found(0, "keystore_module", "keystore", a)], |_| None);
        assert!(!e.to_string().contains("pub"), "{e}");
        assert_eq!((e["label"].as_str(), e["holders"][0]["transport"].as_str()), (Some("Savings"), Some("keystore")));
        assert_eq!(e["path"], "m/84'/1'/0'");
        assert!(e["labels"].is_null());
    }
}
