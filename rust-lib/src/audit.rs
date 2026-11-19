//! What was signed under an allowance, or past one with the password, kept across restarts: one
//! sealed record per line, written before the signature exists. An unlocked wallet is needed to
//! write or read it.

use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::allowance::Asked;
use crate::error::{ManagerError, Result};
use crate::unlock::{seal, unseal, write_private, Key};

const FILE: &str = "unattended.jsonl";
const AAD: &[u8] = b"unattended";
/// The newest records kept. The file grows to twice this before it is cut back.
const KEEP: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    /// Written ahead of the signature, so a crash counts as signed.
    Signed,
    /// The signer refused after the record was written: nothing was signed.
    Failed,
}

/// How a signature came to be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum How {
    /// Inside an allowance, shown to nobody.
    Unattended,
    /// Inside an allowance, confirmed by a person with no password.
    Reviewed,
    /// Past an allowance's limits, approved with the password. It uses none of the allowance.
    Password,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub handle: String,
    pub requester: String,
    pub account: String,
    pub at_ms: u64,
    #[serde(default)]
    pub spend_sat: Option<u64>,
    #[serde(default)]
    pub txid: Option<String>,
    pub outcome: Outcome,
    pub how: How,
    #[serde(default)]
    pub allowance: Option<String>,
    /// Why an allowance didn't cover it.
    #[serde(default)]
    pub reason: Option<String>,
}

impl Entry {
    pub fn signed(handle: &str, asked: &Asked, how: How, allowance: Option<&str>, reason: Option<String>) -> Self {
        Entry {
            handle: handle.to_string(),
            requester: asked.requester.clone(),
            account: asked.account.clone(),
            at_ms: now_ms(),
            spend_sat: asked.spend.as_ref().map(|s| s.sat),
            txid: asked.spend.as_ref().map(|s| s.txid.clone()),
            outcome: Outcome::Signed,
            how,
            allowance: allowance.map(str::to_string),
            reason,
        }
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// The records, oldest first, and how many could not be opened.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Listing {
    pub entries: Vec<Entry>,
    pub unreadable: usize,
}

#[derive(Default)]
pub struct Audit {
    dir: Option<PathBuf>,
    lines: usize,
    /// This run's records, for listing while every wallet is locked.
    session: Vec<Entry>,
}

fn io(e: std::io::Error) -> ManagerError {
    ManagerError::Signing(format!("writing the signing record: {e}"))
}

/// A later record of the same request settles how it ended.
fn merged(all: impl IntoIterator<Item = Entry>) -> Vec<Entry> {
    let mut at: HashMap<String, usize> = HashMap::new();
    let mut out: Vec<Entry> = Vec::new();
    for e in all {
        match at.get(&e.handle) {
            Some(&i) => out[i].outcome = e.outcome,
            None => {
                at.insert(e.handle.clone(), out.len());
                out.push(e);
            }
        }
    }
    out
}

impl Audit {
    /// A line torn by a crash is closed off, so the next record starts on its own line.
    pub fn load(dir: PathBuf) -> Self {
        let path = dir.join(FILE);
        let text = std::fs::read(&path).unwrap_or_default();
        if text.last().is_some_and(|b| *b != b'\n') {
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(&path) {
                let _ = f.write_all(b"\n").and_then(|()| f.sync_all());
            }
        }
        let lines = text.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count();
        Audit { dir: Some(dir), lines, session: Vec::new() }
    }

    /// On disk and synced when it returns.
    pub fn append(&mut self, key: &Key, entry: Entry) -> Result<()> {
        let dir = self.dir.as_ref().ok_or_else(|| ManagerError::Signing("the module has not started yet".into()))?;
        let plain = serde_json::to_vec(&entry).map_err(|e| ManagerError::Signing(e.to_string()))?;
        std::fs::create_dir_all(dir).map_err(io)?;
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
            opts.mode(0o600);
        }
        let mut f = opts.open(dir.join(FILE)).map_err(io)?;
        f.write_all(format!("{}\n", seal(key, &plain, AAD)).as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
        self.lines += 1;
        self.session.push(entry);
        if self.session.len() > KEEP {
            self.session.drain(..KEEP / 2);
        }
        if self.lines > 2 * KEEP {
            self.cut_back();
        }
        Ok(())
    }

    /// Lines move as they are, so this needs no key. If it fails the next record tries again.
    fn cut_back(&mut self) {
        let Some(dir) = &self.dir else { return };
        let Ok(text) = std::fs::read_to_string(dir.join(FILE)) else { return };
        let all: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
        let kept = &all[all.len().saturating_sub(KEEP)..];
        if write_private(dir, FILE, format!("{}\n", kept.join("\n")).as_bytes()).is_ok() {
            self.lines = kept.len();
        }
    }

    /// With no key, this run's records and a count of the rest.
    pub fn read(&self, key: Option<&Key>) -> Listing {
        let Some(key) = key else {
            let unreadable = self.lines.saturating_sub(self.session.len());
            return Listing { entries: merged(self.session.clone()), unreadable };
        };
        let text = self.dir.as_ref().and_then(|d| std::fs::read_to_string(d.join(FILE)).ok()).unwrap_or_default();
        let mut unreadable = 0;
        let opened = text.lines().filter(|l| !l.is_empty()).filter_map(|line| {
            let entry = unseal(key, line, AAD).and_then(|plain| serde_json::from_slice::<Entry>(&plain).ok());
            unreadable += usize::from(entry.is_none());
            entry
        });
        let entries = merged(opened.collect::<Vec<_>>());
        Listing { entries, unreadable }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::allowance::BtcSpend;
    use rand::RngCore;
    use zeroize::Zeroizing;

    fn dir() -> PathBuf {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let d = std::env::temp_dir().join(format!("signer-audit-{}", hex::encode(salt)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key(b: u8) -> Key {
        Zeroizing::new([b; 32])
    }

    fn entry(handle: &str) -> Entry {
        let spend = BtcSpend { network: "regtest".into(), sat: 1_190, fee_sat: 10, txid: "ab".into(), destinations: vec![] };
        let asked = Asked { account: "acct".into(), requester: "wallet".into(), on_behalf: None, digest: false, spend: Some(spend) };
        Entry::signed(handle, &asked, How::Unattended, Some("alw_1"), None)
    }

    #[test]
    fn records_survive_a_restart_and_a_failure_settles_its_request() {
        let d = dir();
        let mut a = Audit::load(d.clone());
        a.append(&key(1), entry("one")).unwrap();
        a.append(&key(1), entry("two")).unwrap();
        a.append(&key(1), Entry { outcome: Outcome::Failed, ..entry("two") }).unwrap();

        let got = Audit::load(d.clone()).read(Some(&key(1)));
        assert_eq!(got.unreadable, 0);
        let ends: Vec<_> = got.entries.iter().map(|e| (e.handle.as_str(), e.outcome)).collect();
        assert_eq!(ends, [("one", Outcome::Signed), ("two", Outcome::Failed)]);
        assert_eq!((got.entries[0].spend_sat, got.entries[0].txid.as_deref()), (Some(1_190), Some("ab")));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn nothing_is_readable_on_disk_or_under_another_key() {
        let d = dir();
        let mut a = Audit::load(d.clone());
        a.append(&key(1), entry("secret-handle")).unwrap();
        let raw = std::fs::read_to_string(d.join(FILE)).unwrap();
        assert!(!raw.contains("secret-handle") && !raw.contains("wallet"), "{raw}");

        let other = Audit::load(d.clone()).read(Some(&key(2)));
        assert_eq!((other.entries.len(), other.unreadable), (0, 1));
        let locked = Audit::load(d.clone()).read(None);
        assert_eq!((locked.entries.len(), locked.unreadable), (0, 1), "a new run knows only the count");
        assert_eq!(a.read(None).entries.len(), 1, "this run's records stay listed while locked");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_torn_last_line_costs_only_itself() {
        let d = dir();
        let mut a = Audit::load(d.clone());
        a.append(&key(1), entry("whole")).unwrap();
        let mut f = std::fs::OpenOptions::new().append(true).open(d.join(FILE)).unwrap();
        f.write_all(b"deadbeef").unwrap();
        drop(f);

        let mut again = Audit::load(d.clone());
        again.append(&key(1), entry("after")).unwrap();
        let got = again.read(Some(&key(1)));
        let names: Vec<_> = got.entries.iter().map(|e| e.handle.as_str()).collect();
        assert_eq!((names, got.unreadable), (vec!["whole", "after"], 1));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn the_file_is_cut_back_to_the_newest_records() {
        let d = dir();
        let mut a = Audit::load(d.clone());
        a.lines = 2 * KEEP;
        a.append(&key(1), entry("kept")).unwrap();
        assert_eq!(a.lines, 1);
        assert_eq!(a.read(Some(&key(1))).entries[0].handle, "kept");
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn before_the_module_starts_nothing_can_be_recorded() {
        assert!(Audit::default().append(&key(1), entry("early")).is_err());
    }
}
