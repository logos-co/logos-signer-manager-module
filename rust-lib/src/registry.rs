//! The signers the manager consults, in order, and the accounts they offer. A signer is anything
//! behind `logos.signer/1`: a module over IPC in production, a mock or a test double in tests.

use std::time::{Duration, Instant};

use logos_signer_interface::unlock::{evm_path_ok, is_reserved};
use logos_signer_interface::{Account, Family, Signer, SignerInfo};

use crate::error::{ManagerError, Result};
use crate::roster;

/// How long a signer that didn't answer is left alone. A module that isn't installed, such as a
/// default device module, costs the transport's wait of about a second at each ask.
const RESTING: Duration = Duration::from_secs(30);

struct Entry {
    name: String,
    signer: Box<dyn Signer + Send>,
    info: Option<SignerInfo>,
    accounts: Option<Vec<Account>>,
    /// When it last didn't answer.
    missed: Option<Instant>,
}

/// An account and the signer that holds it.
#[derive(Clone, Debug)]
pub struct Found {
    pub signer: usize,
    pub name: String,
    pub info: SignerInfo,
    pub account: Account,
}

#[derive(Default)]
pub struct Registry {
    entries: Vec<Entry>,
}

fn same_id(a: &Account, id: &str) -> bool {
    match a.family {
        Family::Evm => a.id.eq_ignore_ascii_case(id.trim()),
        _ => a.id == id.trim(),
    }
}

/// Nothing under the reserved purpose, where unlock keys live, and an EVM account under m/44'/60':
/// a listing that says otherwise was edited, and the account is not offered.
fn admissible(a: &Account) -> bool {
    match a.path.as_deref() {
        Some(p) if is_reserved(p) => false,
        Some(p) if a.family == Family::Evm => evm_path_ok(p),
        _ => true,
    }
}

// A reader reports its current seed; USB presence alone cannot identify a Shell's card.
fn preferred(name: &str, a: &Account, old_name: &str, old: &Account) -> bool {
    (a.available && !old.available)
        || (a.available && old.available && name == "keycard_module" && old_name == "keycard_shell_module")
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Signers are consulted in the order added: available signers take priority; a matching reader precedes a candidate Shell.
    pub fn add(&mut self, name: impl Into<String>, signer: Box<dyn Signer + Send>) {
        self.entries.push(Entry { name: name.into(), signer, info: None, accounts: None, missed: None });
    }

    pub fn names(&self) -> Vec<String> {
        self.entries.iter().map(|e| e.name.clone()).collect()
    }

    /// Drop these signers' listings and ask them again, resting or not: they said their accounts
    /// changed. Every other signer keeps its listing, and one that is resting keeps resting.
    pub fn forget(&mut self, names: &[String]) {
        for e in self.entries.iter_mut().filter(|e| names.contains(&e.name)) {
            e.info = None;
            e.accounts = None;
            e.missed = None;
        }
    }

    /// Read every listing again, except from a signer still resting: it was asked moments ago.
    fn reread(&mut self) {
        for e in &mut self.entries {
            e.info = None;
            e.accounts = None;
        }
    }

    /// Read a signer's info and accounts once. One that doesn't answer offers nothing, and rests.
    fn load(&mut self, i: usize) {
        let e = &mut self.entries[i];
        if e.info.is_none() {
            if e.missed.is_some_and(|t| t.elapsed() < RESTING) {
                return;
            }
            e.info = e.signer.info_checked();
            e.missed = e.info.is_none().then(Instant::now);
        }
        if e.accounts.is_none() && e.info.is_some() {
            e.accounts = e.signer.accounts().ok().map(|all| all.into_iter().filter(admissible).collect());
        }
    }

    fn lookup(&self, id: &str) -> Option<Found> {
        let mut first = None;
        for (i, e) in self.entries.iter().enumerate() {
            let (Some(info), Some(accounts)) = (&e.info, &e.accounts) else { continue };
            if let Some(a) = accounts.iter().find(|a| same_id(a, id)) {
                let found = Found { signer: i, name: e.name.clone(), info: info.clone(), account: a.clone() };
                if first.as_ref().is_none_or(|old: &Found| preferred(&e.name, a, &old.name, &old.account)) { first = Some(found); }
            }
        }
        first
    }

    /// The account `id` and its signer, reading the signers again once if it isn't known.
    pub fn find(&mut self, id: &str) -> Result<Found> {
        for i in 0..self.entries.len() {
            self.load(i);
        }
        if let Some(f) = self.lookup(id) {
            return Ok(f);
        }
        self.reread();
        for i in 0..self.entries.len() {
            self.load(i);
        }
        self.lookup(id).ok_or_else(|| ManagerError::NotFound(format!("no signer offers the account {}", id.trim())))
    }

    /// Every holder of the account an id or roster key names, ranked; empty when none offers it.
    fn holders_known(&self, id_or_key: &str) -> Vec<Found> {
        let wanted = id_or_key.trim();
        let key = self.entries.iter().flat_map(|e| e.accounts.iter().flatten()).find_map(|a| {
            let key = roster::key_of(a)?;
            (same_id(a, wanted) || key == wanted.to_ascii_lowercase()).then_some(key)
        });
        let Some(key) = key else { return Vec::new() };
        let mut out = Vec::new();
        for (i, e) in self.entries.iter().enumerate() {
            let (Some(info), Some(accounts)) = (&e.info, &e.accounts) else { continue };
            // One per signer: a signer listing an account twice still signs it one way.
            if let Some(a) = accounts.iter().find(|a| roster::key_of(a).as_deref() == Some(key.as_str())) {
                out.push(Found { signer: i, name: e.name.clone(), info: info.clone(), account: a.clone() });
            }
        }
        roster::rank(&mut out);
        out
    }

    /// Every signer holding the account `id_or_key` names, ranked, reading the signers again once
    /// if none is known.
    pub fn holders(&mut self, id_or_key: &str) -> Result<Vec<Found>> {
        for i in 0..self.entries.len() {
            self.load(i);
        }
        let found = self.holders_known(id_or_key);
        if !found.is_empty() {
            return Ok(found);
        }
        self.reread();
        for i in 0..self.entries.len() {
            self.load(i);
        }
        let found = self.holders_known(id_or_key);
        if found.is_empty() {
            return Err(ManagerError::NotFound(format!("no signer offers the account {}", id_or_key.trim())));
        }
        Ok(found)
    }

    /// The account as one signer holds it.
    pub fn holder(&mut self, id_or_key: &str, signer: &str) -> Result<Found> {
        self.holders(id_or_key)?
            .into_iter()
            .find(|f| f.name == signer)
            .ok_or_else(|| ManagerError::NotFound(format!("{signer} does not hold the account {}", id_or_key.trim())))
    }

    /// Every account once, by roster key, with all its holders ranked, in the order first listed.
    pub fn roster(&mut self) -> Vec<(String, Vec<Found>)> {
        for i in 0..self.entries.len() {
            self.load(i);
        }
        let mut keys: Vec<String> = Vec::new();
        for a in self.entries.iter().flat_map(|e| e.accounts.iter().flatten()) {
            if let Some(key) = roster::key_of(a).filter(|k| !keys.contains(k)) {
                keys.push(key);
            }
        }
        keys.into_iter().map(|k| {
            let holders = self.holders_known(&k);
            (k, holders)
        }).collect()
    }

    /// The signer that lists an account, by id or address, and the seed as it names it: from
    /// what is already loaded, never asking a signer.
    pub fn seed_of_account(&self, id: &str) -> Option<(String, String)> {
        let id = id.trim();
        self.entries.iter().find_map(|e| {
            let a = e.accounts.iter().flatten().find(|a| {
                a.seed.is_some()
                    && (same_id(a, id) || a.address.as_deref().is_some_and(|ad| ad.eq_ignore_ascii_case(id)))
            })?;
            Some((e.name.clone(), a.seed.clone()?))
        })
    }

    /// Every account once, under its preferred available signer.
    pub fn accounts(&mut self) -> Vec<(String, Account)> {
        let mut out: Vec<(String, Account)> = Vec::new();
        for i in 0..self.entries.len() {
            self.load(i);
            let e = &self.entries[i];
            for a in e.accounts.iter().flatten() {
                if let Some(index) = out.iter().position(|(_, seen)| same_id(seen, &a.id)) {
                    if preferred(&e.name, a, &out[index].0, &out[index].1) { out[index] = (e.name.clone(), a.clone()); }
                } else { out.push((e.name.clone(), a.clone())); }
            }
        }
        out
    }

    /// Each signer's info, or `None` for one that doesn't answer.
    pub fn infos(&mut self) -> Vec<(String, Option<SignerInfo>)> {
        (0..self.entries.len())
            .map(|i| {
                self.load(i);
                (self.entries[i].name.clone(), self.entries[i].info.clone())
            })
            .collect()
    }

    pub fn signer(&mut self, i: usize) -> &mut (dyn Signer + Send) {
        self.entries[i].signer.as_mut()
    }
}

/// `info` is infallible on the trait; a signer over IPC reports an unreachable module as an empty interface.
trait InfoChecked {
    fn info_checked(&self) -> Option<SignerInfo>;
}

impl<S: Signer + ?Sized> InfoChecked for S {
    fn info_checked(&self) -> Option<SignerInfo> {
        let info = self.info();
        (info.interface == logos_signer_interface::INTERFACE).then_some(info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Collects, JobStatus, SignRequest, Signature};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Arc;

    /// A module that isn't installed: it never answers, and counts the asks.
    struct Absent(Arc<AtomicUsize>);

    impl Signer for Absent {
        fn info(&self) -> SignerInfo {
            self.0.fetch_add(1, SeqCst);
            SignerInfo {
                interface: String::new(),
                kind: String::new(),
                model: String::new(),
                families: Vec::new(),
                request_kinds: Vec::new(),
                shows_request: false,
                collects: Collects::Nothing,
                unlock_key: false,
            }
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
            unreachable!("asked only after it answers")
        }
        fn sign(&mut self, _: SignRequest) -> logos_signer_interface::Result<String> {
            unreachable!()
        }
        fn status(&mut self, _: &str) -> logos_signer_interface::Result<JobStatus> {
            unreachable!()
        }
        fn result(&mut self, _: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            unreachable!()
        }
        fn cancel(&mut self, _: &str) -> logos_signer_interface::Result<()> {
            unreachable!()
        }
    }

    #[test]
    fn a_signer_that_does_not_answer_rests_until_it_announces_a_change_itself() {
        let asks = Arc::new(AtomicUsize::new(0));
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        r.add("keycard_module", Box::new(Absent(asks.clone())));
        assert_eq!(r.accounts().len(), 3);
        assert_eq!(r.accounts().len(), 3);
        assert!(r.find("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").is_ok());
        assert_eq!(asks.load(SeqCst), 1, "asked once, then left alone");
        // The keystore announces at every import; each cost a second per absent module, under the lock.
        r.forget(&["keystore_module".to_string()]);
        r.accounts();
        assert!(r.find("0x0000000000000000000000000000000000000001").is_err());
        assert_eq!(asks.load(SeqCst), 1, "another signer's news, and an unknown account, leave it resting");
        r.forget(&["keycard_module".to_string()]);
        r.accounts();
        assert_eq!(asks.load(SeqCst), 2, "asked again once it announces a change itself");
    }

    #[test]
    fn an_accounts_seed_comes_from_what_is_loaded_without_asking() {
        let asks = Arc::new(AtomicUsize::new(0));
        let mut r = Registry::new();
        r.add("keycard_module", Box::new(Absent(asks.clone())));
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        assert_eq!(r.seed_of_account("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"), None, "nothing loaded yet");
        assert_eq!(asks.load(SeqCst), 0);
        let bitcoin = r.accounts().into_iter().find(|(_, a)| a.family != Family::Evm).unwrap().1.id;
        let (holder, seed) = r.seed_of_account("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();
        assert_eq!(holder, "keystore_module");
        assert_eq!(r.seed_of_account(&bitcoin).map(|(_, s)| s), Some(seed));
        assert_eq!(r.seed_of_account("0x0000000000000000000000000000000000000001"), None);
    }

    #[test]
    fn an_account_is_found_under_the_first_signer_that_offers_it() {
        let mut r = Registry::new();
        r.add("first", Box::new(MockSigner::new(MockOptions::default())));
        r.add("second", Box::new(MockSigner::new(MockOptions::default())));
        let f = r.find("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").unwrap();
        assert_eq!(f.name, "first");
        assert_eq!(r.accounts().len(), 3, "the second signer's copies are not offered twice");
        assert!(r.find("0x0000000000000000000000000000000000000001").is_err());
        assert!(r.find("MOCK-SEGWIT").is_err(), "a Bitcoin id is exact");
    }

    #[test]
    fn signers_holding_one_phrase_hold_one_account_each_ranked() {
        let mock = |kind: &str, available: bool| {
            Box::new(MockSigner::new(MockOptions { kind: kind.into(), available, ..Default::default() }))
        };
        let mut r = Registry::new();
        r.add("keycard_shell_module", mock("keycard_shell", false));
        r.add("qr_signer_module", mock("qr", true));
        r.add("keystore_module", mock("keystore", true));
        let roster = r.roster();
        assert_eq!(roster.len(), 3, "its EVM, native segwit and taproot accounts, once each");
        for (_, holders) in &roster {
            let names: Vec<_> = holders.iter().map(|f| f.name.as_str()).collect();
            assert_eq!(names, ["keystore_module", "qr_signer_module", "keycard_shell_module"]);
        }
        let evm = &roster.iter().find(|(_, h)| h[0].account.family == Family::Evm).unwrap().0;
        assert_eq!(r.holders("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266").unwrap().len(), 3, "by address");
        assert_eq!(r.holders(evm).unwrap().len(), 3, "by key");
        let (segwit, holders) = roster.iter().find(|(_, h)| h[0].account.family == Family::Bitcoin).unwrap();
        assert_eq!(r.holders(&holders[0].account.id).unwrap().len(), 3, "by any holder's id");
        assert_eq!(r.holder(segwit, "qr_signer_module").unwrap().name, "qr_signer_module");
        assert!(r.holder(segwit, "keycard_module").is_err());
        assert!(r.holders("btc_00").is_err());
    }

    /// A signer whose files were edited: its rows point at an open key and off the EVM paths.
    struct Edited(MockSigner);

    impl Signer for Edited {
        fn info(&self) -> SignerInfo {
            self.0.info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
            let mut out = self.0.accounts()?;
            let mut evm = out.iter().find(|a| a.family == Family::Evm).unwrap().clone();
            let mut btc = out.iter().find(|a| a.family == Family::Bitcoin).unwrap().clone();
            (evm.id, evm.address, evm.path) = ("0x01".into(), Some("0x01".into()), Some("m/44'/0'/0'/0/0".into()));
            (btc.id, btc.key, btc.path) = ("open-key".into(), Some(format!("btc_{}", "0".repeat(32))), Some("m/1280263247'/0'".into()));
            out.extend([evm, btc]);
            Ok(out)
        }
        fn sign(&mut self, r: SignRequest) -> logos_signer_interface::Result<String> {
            self.0.sign(r)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.0.result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.cancel(job)
        }
    }

    #[test]
    fn no_row_under_the_open_keys_purpose_nor_an_evm_row_off_44_60_is_offered() {
        let mut r = Registry::new();
        r.add("keycard_module", Box::new(Edited(MockSigner::new(MockOptions::default()))));
        assert_eq!(r.accounts().len(), 3, "only the mock's own three");
        assert!(r.find("0x01").is_err());
        assert!(r.find("open-key").is_err());
    }
}
