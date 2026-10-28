//! Bitcoin accounts as the manager sees them: public material only, from a signer's listing.
//! The BIP84 and BIP86 paths, keys below an account, scripts and descriptors. Ported from keystore_module.

use std::str::FromStr;

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::key::{CompressedPublicKey, UntweakedPublicKey};
use bitcoin::secp256k1::{Secp256k1, Verification};
use bitcoin::{Network, NetworkKind, ScriptBuf};

use crate::error::{bad, Result};

/// The two Bitcoin families a group can be. Each has one fixed purpose level.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Family {
    /// Native segwit, P2WPKH, BIP84.
    Segwit,
    /// Taproot key path, P2TR, BIP86.
    Taproot,
}

impl Family {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "bitcoin" => Ok(Self::Segwit),
            "bitcoin_taproot" => Ok(Self::Taproot),
            other => Err(bad(format!("family must be \"bitcoin\" or \"bitcoin_taproot\", got {other:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Segwit => "bitcoin",
            Self::Taproot => "bitcoin_taproot",
        }
    }

    pub fn purpose(self) -> u32 {
        match self {
            Self::Segwit => 84,
            Self::Taproot => 86,
        }
    }

    pub fn describe(self) -> &'static str {
        match self {
            Self::Segwit => "native segwit",
            Self::Taproot => "taproot",
        }
    }
}

/// Mainnet, or the test networks, which BIP44 gives coin type 1 together.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Chain {
    Main,
    Test,
}

impl Chain {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim() {
            "main" => Ok(Self::Main),
            "test" => Ok(Self::Test),
            other => Err(bad(format!("network must be \"main\" or \"test\", got {other:?}"))),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Main => "main",
            Self::Test => "test",
        }
    }

    pub fn coin_type(self) -> u32 {
        match self {
            Self::Main => 0,
            Self::Test => 1,
        }
    }

    pub fn kind(self) -> NetworkKind {
        match self {
            Self::Main => NetworkKind::Main,
            Self::Test => NetworkKind::Test,
        }
    }

    /// A network a request names. It has to belong to this chain: a test wallet never signs for mainnet.
    pub fn network(self, name: &str) -> Result<Network> {
        let net = match name.trim() {
            "bitcoin" | "main" | "mainnet" => Network::Bitcoin,
            "testnet" | "testnet3" => Network::Testnet,
            "testnet4" => Network::Testnet4,
            "signet" => Network::Signet,
            "regtest" => Network::Regtest,
            other => return Err(bad(format!("unknown Bitcoin network {other:?}"))),
        };
        if NetworkKind::from(net) != self.kind() {
            return Err(bad(format!("this wallet is on the {} chain and can't sign for {net}", self.as_str())));
        }
        Ok(net)
    }
}

/// How the signer names a network.
pub fn network_name(net: Network) -> &'static str {
    match net {
        Network::Bitcoin => "mainnet",
        Network::Testnet => "testnet",
        Network::Testnet4 => "testnet4",
        Network::Signet => "signet",
        Network::Regtest => "regtest",
    }
}

const HARDENED: u32 = 0x8000_0000;

/// `m/<purpose>'/<coin>'/<account>'`, the deepest key a Bitcoin group keeps.
pub fn account_path(family: Family, chain: Chain, account: u32) -> Result<DerivationPath> {
    if account >= HARDENED {
        return Err(bad(format!("account must be below 2^31, got {account}")));
    }
    let level = |i: u32| ChildNumber::from_hardened_idx(i).map_err(|e| bad(e.to_string()));
    Ok(DerivationPath::from(vec![level(family.purpose())?, level(chain.coin_type())?, level(account)?]))
}

/// Parse a stored account path and return its account. Anything but this family's and chain's prefix is refused.
pub fn parse_account_path(s: &str, family: Family, chain: Chain) -> Result<u32> {
    if !s.starts_with("m/") {
        return Err(bad(format!("path {s:?} must start with \"m/\"")));
    }
    let path = DerivationPath::from_str(s).map_err(|e| bad(format!("path {s:?}: {e}")))?;
    let levels: Vec<ChildNumber> = path.into_iter().copied().collect();
    let [p, c, ChildNumber::Hardened { index: a }] = levels.as_slice() else {
        return Err(bad(format!("path {s:?} is not m/{}'/{}'/<account>'", family.purpose(), chain.coin_type())));
    };
    if *p != (ChildNumber::Hardened { index: family.purpose() }) || *c != (ChildNumber::Hardened { index: chain.coin_type() }) {
        return Err(bad(format!("path {s:?} is not m/{}'/{}'/<account>'", family.purpose(), chain.coin_type())));
    }
    Ok(*a)
}

/// A Bitcoin account key, live only for the caller's scope.
///
/// rust-bitcoin's `Xpriv` is `Copy` and can't be zeroized, so this wipes its own copy on drop and no more.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountPublic {
    pub family: Family,
    pub chain: Chain,
    pub account: u32,
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
}

impl AccountPublic {
    /// `m/<purpose>'/<coin>'/<account>'`, the key origin in every descriptor and PSBT.
    pub fn origin(&self) -> DerivationPath {
        account_path(self.family, self.chain, self.account).expect("account checked on construction")
    }

    /// The descriptor of one branch: 0 receives, 1 is change.
    pub fn descriptor(&self, change: u32) -> String {
        let origin = self.origin().to_string();
        let key = format!("[{}/{}]{}/{change}/*", self.fingerprint, origin.trim_start_matches("m/"), self.xpub);
        let body = match self.family {
            Family::Segwit => format!("wpkh({key})"),
            Family::Taproot => format!("tr({key})"),
        };
        let sum = descriptor_checksum(&body).expect("descriptors use only checksum characters");
        format!("{body}#{sum}")
    }

    /// The key at `<change>/<index>` below the account, both unhardened.
    pub fn key_at<C: Verification>(&self, secp: &Secp256k1<C>, change: u32, index: u32) -> Result<CompressedPublicKey> {
        if change > 1 || index >= HARDENED {
            return Err(bad(format!("{change}/{index} is not a receive or change index")));
        }
        let child = self
            .xpub
            .derive_pub(secp, &[ChildNumber::Normal { index: change }, ChildNumber::Normal { index }])
            .map_err(|e| bad(format!("bip32: {e}")))?;
        Ok(CompressedPublicKey(child.public_key))
    }

    /// The output script this wallet pays to at `<change>/<index>`.
    pub fn script_at<C: Verification>(&self, secp: &Secp256k1<C>, change: u32, index: u32) -> Result<ScriptBuf> {
        let key = self.key_at(secp, change, index)?;
        Ok(match self.family {
            Family::Segwit => ScriptBuf::new_p2wpkh(&key.wpubkey_hash()),
            Family::Taproot => ScriptBuf::new_p2tr(secp, UntweakedPublicKey::from(key.0), None),
        })
    }

    /// `<change>/<index>` when `path` is this account's origin followed by those two levels, unhardened.
    pub fn relative(&self, path: &DerivationPath) -> Option<(u32, u32)> {
        let origin = self.origin();
        let levels: Vec<ChildNumber> = path.into_iter().copied().collect();
        let (head, tail) = levels.split_at_checked(origin.len())?;
        if head != origin.as_ref() {
            return None;
        }
        match tail {
            [ChildNumber::Normal { index: c }, ChildNumber::Normal { index: i }] if *c <= 1 => Some((*c, *i)),
            _ => None,
        }
    }
}

const INPUT_CHARSET: &str =
    "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(symbols: &[u64]) -> u64 {
    const GENERATOR: [u64; 5] = [0xf5dee51989, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd];
    let mut chk = 1u64;
    for value in symbols {
        let top = chk >> 35;
        chk = ((chk & 0x7ffffffff) << 5) ^ value;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

/// The BIP380 descriptor checksum, ported from the BIP's own Python. `None` for a character it can't encode.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    let mut symbols = Vec::new();
    let mut groups = Vec::new();
    for c in desc.chars() {
        let v = INPUT_CHARSET.find(c)? as u64;
        symbols.push(v & 31);
        groups.push(v >> 5);
        if groups.len() == 3 {
            symbols.push(groups[0] * 9 + groups[1] * 3 + groups[2]);
            groups.clear();
        }
    }
    match groups.as_slice() {
        [g] => symbols.push(*g),
        [g0, g1] => symbols.push(g0 * 3 + g1),
        _ => {}
    }
    symbols.extend([0; 8]);
    let sum = polymod(&symbols) ^ 1;
    Some((0..8).map(|i| CHECKSUM_CHARSET[((sum >> (5 * (7 - i))) & 31) as usize] as char).collect())
}


impl AccountPublic {
    /// A signer's Bitcoin account, read from its listing; refused unless every field agrees.
    /// Its family and chain, which an account lists without its xpub.
    pub fn kind_of(a: &logos_signer_interface::Account) -> Result<(Family, Chain)> {
        use logos_signer_interface::{Chain as WireChain, Family as WireFamily};
        let family = match a.family {
            WireFamily::Bitcoin => Family::Segwit,
            WireFamily::BitcoinTaproot => Family::Taproot,
            WireFamily::Evm => return Err(bad(format!("{} is not a Bitcoin account", a.id))),
        };
        let chain = match a.chain {
            Some(WireChain::Main) => Chain::Main,
            Some(WireChain::Test) => Chain::Test,
            None => return Err(bad(format!("{} names no chain", a.id))),
        };
        Ok((family, chain))
    }

    pub fn from_account(a: &logos_signer_interface::Account) -> Result<Self> {
        let (family, chain) = Self::kind_of(a)?;
        let path = a.path.as_deref().ok_or_else(|| bad(format!("{} names no path", a.id)))?;
        let account = parse_account_path(path, family, chain)?;
        let fingerprint = a
            .fingerprint
            .as_deref()
            .and_then(|f| Fingerprint::from_str(f).ok())
            .ok_or_else(|| bad(format!("{} names no fingerprint", a.id)))?;
        let xpub = a
            .xpub
            .as_deref()
            .and_then(|x| Xpub::from_str(x).ok())
            .filter(|x| x.depth == 3 && x.network == chain.kind())
            .ok_or_else(|| bad(format!("{} carries no account xpub for its chain", a.id)))?;
        Ok(AccountPublic { family, chain, account, fingerprint, xpub })
    }

    /// The account path as text, `m/…`.
    pub fn origin_string(&self) -> String {
        format!("m/{}", self.origin().to_string().trim_start_matches("m/"))
    }
}
#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::base58;
    use bitcoin::key::UntweakedPublicKey;
    use bitcoin::Address;

    // Every expected value below is from bitcoin/bips at 927b6de9915c (2026-10-02): BIP84's and BIP86's
    // test vectors and BIP380's checksum vector, for "abandon … about", master fingerprint 73c5da0a.
    const BIP84_ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
    const BIP86_XPUB: &str = "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ";

    /// BIP84 writes its key with SLIP-132 version bytes; the key data is the same as an xpub's.
    fn as_xpub(slip132: &str) -> Xpub {
        let mut data = base58::decode_check(slip132).unwrap();
        data[..4].copy_from_slice(&[0x04, 0x88, 0xb2, 0x1e]);
        Xpub::from_str(&base58::encode_check(&data)).unwrap()
    }

    pub(crate) fn account(family: Family) -> AccountPublic {
        let xpub = match family {
            Family::Segwit => as_xpub(BIP84_ZPUB),
            Family::Taproot => Xpub::from_str(BIP86_XPUB).unwrap(),
        };
        AccountPublic { family, chain: Chain::Main, account: 0, fingerprint: Fingerprint::from_str("73c5da0a").unwrap(), xpub }
    }

    #[test]
    fn bip84_published_vectors_reproduce_keys_and_addresses() {
        let secp = Secp256k1::verification_only();
        let public = account(Family::Segwit);
        for (change, index, pubkey, address) in [
            (0, 0, "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c", "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"),
            (0, 1, "03e775fd51f0dfb8cd865d9ff1cca2a158cf651fe997fdc9fee9c1d3b5e995ea77", "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"),
            (1, 0, "03025324888e429ab8e3dbaf1f7802648b9cd01e9b418485c5fa4c1b9b5700e1a6", "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el"),
        ] {
            assert_eq!(public.key_at(&secp, change, index).unwrap().to_string(), pubkey, "{change}/{index}");
            let script = public.script_at(&secp, change, index).unwrap();
            assert_eq!(Address::from_script(&script, Network::Bitcoin).unwrap().to_string(), address);
        }
    }

    #[test]
    fn bip86_published_vectors_reproduce_keys_and_addresses() {
        let secp = Secp256k1::verification_only();
        let public = account(Family::Taproot);
        for (change, index, internal, address) in [
            (0, 0, "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"),
            (0, 1, "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145", "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh"),
        ] {
            let key = public.key_at(&secp, change, index).unwrap();
            assert_eq!(UntweakedPublicKey::from(key.0).to_string(), internal, "{change}/{index}");
            let script = public.script_at(&secp, change, index).unwrap();
            assert_eq!(Address::from_script(&script, Network::Bitcoin).unwrap().to_string(), address);
        }
    }

    #[test]
    fn the_descriptor_checksum_matches_bip380() {
        assert_eq!(descriptor_checksum("raw(deadbeef)").unwrap(), "89f8spxm");
        assert!(descriptor_checksum("raw(Ü)").is_none());
        assert_ne!(descriptor_checksum("raw(deedbeef)").unwrap(), "89f8spxm");
    }

    #[test]
    fn descriptors_carry_the_key_origin_and_a_valid_checksum() {
        let public = account(Family::Segwit);
        let d = public.descriptor(0);
        assert!(d.starts_with("wpkh([73c5da0a/84'/0'/0']xpub"), "{d}");
        let (body, sum) = d.split_once('#').unwrap();
        assert_eq!(descriptor_checksum(body).unwrap(), sum);
        assert!(public.descriptor(1).contains("/1/*)#"));
        assert!(account(Family::Taproot).descriptor(0).starts_with("tr([73c5da0a/86'/0'/0']xpub"));
    }

    #[test]
    fn a_chain_signs_only_for_its_own_networks() {
        assert_eq!(Chain::Test.network("signet").unwrap(), Network::Signet);
        assert_eq!(Chain::Test.network("regtest").unwrap(), Network::Regtest);
        assert!(Chain::Test.network("bitcoin").is_err());
        assert!(Chain::Main.network("signet").is_err());
        assert!(Chain::Main.network("litecoin").is_err());
    }

    #[test]
    fn a_path_is_relative_only_below_this_account() {
        let public = account(Family::Segwit);
        let p = |s: &str| DerivationPath::from_str(s).unwrap();
        assert_eq!(public.relative(&p("m/84'/0'/0'/1/7")), Some((1, 7)));
        for other in ["m/84'/0'/1'/0/0", "m/84'/0'/0'/2/0", "m/84'/0'/0'/0'/0", "m/84'/0'/0'/0", "m/86'/0'/0'/0/0"] {
            assert_eq!(public.relative(&p(other)), None, "{other}");
        }
    }

    #[test]
    fn a_listing_becomes_an_account_only_when_every_field_agrees() {
        use logos_signer_interface::{Account, Chain as WireChain, Family as WireFamily};
        let public = account(Family::Taproot);
        let listed = Account {
            id: "g".into(),
            family: WireFamily::BitcoinTaproot,
            chain: Some(WireChain::Main),
            path: Some("m/86'/0'/0'".into()),
            fingerprint: Some("73c5da0a".into()),
            address: None,
            xpub: Some(BIP86_XPUB.into()),
            label: None,
            available: true,
            key: None,
            seed: None,
        };
        assert_eq!(AccountPublic::from_account(&listed).unwrap(), public);
        for broken in [
            Account { chain: Some(WireChain::Test), ..listed.clone() },
            Account { path: Some("m/84'/0'/0'".into()), ..listed.clone() },
            Account { fingerprint: None, ..listed.clone() },
            Account { family: WireFamily::Evm, ..listed.clone() },
        ] {
            assert!(AccountPublic::from_account(&broken).is_err(), "{broken:?}");
        }
    }
}
