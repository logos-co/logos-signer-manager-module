//! Opening and unlocking accounts: requests a person decides in the Signer app (an approver) or the
//! keys app (the custodian), the grants they leave, and the scope of each unlock.
//!
//! An open request connects one Bitcoin wallet to one module for this session. An approver gives
//! consent once the wallet is unlocked: the module collects the wallet's descriptors and its seed
//! with its receipt, and takes its database key from `data_key`. The custodian's older path hands
//! over a database key from the keystore. The module may read the descriptors again until it
//! closes the wallet. An unlock request asks for an
//! account's key to stay unlocked on terms; the person decides the terms. The keystore holds the key
//! and enforces the time and the count; this module enforces which apps an unlock covers and
//! whether each signature is still confirmed. Nothing here is written down.

use std::time::{Duration, Instant};

use rand::RngCore;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use logos_signer_interface::Family;

use crate::btc::AccountPublic;
use crate::error::{bad, ManagerError, Result};
use crate::evm::check_displayable;
use crate::registry::{Found, Registry};
use crate::unlock::Unlock;

pub const MAX_PENDING_PER_REQUESTER: usize = 2;
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);
pub const ABANDONED_OFFER_TTL: Duration = Duration::from_secs(300);

/// What the keystore hands over when a wallet opens: its database key, and where its history can start.
pub struct OpenedWallet {
    pub database_key: Zeroizing<String>,
    /// `created` or `restored`.
    pub origin: String,
    /// The wallet's first possible day, `YYYY-MM-DD`, when known.
    pub birthday: Option<String>,
}

// The signer whose Bitcoin wallets keep their database key in their own vault; any other is a device.
use crate::roster::KEYSTORE;

/// What the keystore does for an open or an unlock, beyond the signer interface.
pub trait KeyHolder {
    fn database_key(&mut self, group: &str, password: Option<&str>) -> Result<OpenedWallet>;
    /// A device account's database key, made at its first open under the password the person set.
    fn device_database_key(&mut self, signer: &str, account: &str, password: &str, birthday: Option<&str>)
        -> Result<OpenedWallet>;
    /// The device wallets that have a database key, as `(signer, account)`.
    fn device_wallets(&mut self) -> Result<Vec<(String, String)>>;
    fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> Result<Unlocked>;
    fn lock(&mut self, account: Option<&str>) -> Result<usize>;
    fn unlocked(&mut self) -> Result<Vec<Unlocked>>;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Unlocked {
    pub account: String,
    #[serde(default)]
    pub expires_in_ms: Option<u64>,
    #[serde(default)]
    pub count_left: Option<u32>,
}

/// An unlock's terms. `apps` empty means the module that asked; `confirm` false means its requests
/// are signed without being shown.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Terms {
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub apps: Vec<String>,
    /// Each signature is still confirmed in the signer. True unless the person chooses otherwise.
    #[serde(default = "yes")]
    pub confirm: bool,
}

fn yes() -> bool {
    true
}

impl Terms {
    fn describe(&self, requester: &str) -> String {
        let time = self.ttl_ms.map_or("until locked".to_string(), |ms| format!("for {}", duration(ms)));
        let count = self.count.map_or(String::new(), |n| format!(", up to {n} signature request(s)"));
        let apps = if self.apps.is_empty() { requester.to_string() } else { self.apps.join(", ") };
        let how = if self.confirm { "each one confirmed in the signer" } else { "WITHOUT showing them to you" };
        format!("{time}{count}, for {apps}, {how}")
    }

    /// "Any app" is offered only with confirmation: without it every module could sign.
    fn check(&self) -> Result<()> {
        if !self.confirm && self.apps.iter().any(|a| a == "*") {
            return Err(bad("unlock: signing without asking must name the apps it covers"));
        }
        for a in &self.apps {
            check_displayable(a, "app")?;
        }
        if self.count == Some(0) || self.ttl_ms == Some(0) {
            return Err(bad("unlock: terms that allow nothing"));
        }
        Ok(())
    }
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    match s {
        0..=119 => format!("{s} seconds"),
        120..=7199 => format!("{} minutes", s / 60),
        _ => format!("{} hours", s / 3600),
    }
}

/// How an unlock covers a request from one module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cover {
    No,
    /// Approved with a confirmation, no password.
    Confirmed,
    /// Signed as it arrives, unseen.
    WithoutAsking,
}

/// What the manager keeps of an unlock: whose it is and which apps it covers. The key and the time
/// and count are the keystore's.
#[derive(Debug, Clone)]
struct Scope {
    account: String,
    apps: Vec<String>,
    confirm: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OpenParams {
    #[serde(default)]
    pub group: Option<String>,
    #[serde(default)]
    pub family: Option<Family>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub unlock: Option<Terms>,
    /// The wallet's seed, as an earlier open handed it over: names a wallet whose seed is locked,
    /// so its signers list it no more until it is unlocked.
    #[serde(default)]
    pub seed: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// `{ account, ttlMs?, count?, apps?, confirm?, reason? }`: an account and the terms asked for.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UnlockParams {
    pub account: String,
    #[serde(default)]
    pub ttl_ms: Option<u64>,
    #[serde(default)]
    pub count: Option<u32>,
    #[serde(default)]
    pub apps: Vec<String>,
    #[serde(default = "yes")]
    pub confirm: bool,
    #[serde(default)]
    pub reason: String,
}

impl UnlockParams {
    pub fn terms(&self) -> Terms {
        Terms { ttl_ms: self.ttl_ms, count: self.count, apps: self.apps.clone(), confirm: self.confirm }
    }
}

#[derive(Debug)]
enum Kind {
    Open(OpenParams),
    Unlock(UnlockParams),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Offered,
    Rendered,
    Settled(&'static str),
}

struct Record {
    handle: String,
    receipt_hash: [u8; 32],
    requester: String,
    kind: Kind,
    bundle_id: [u8; 32],
    lines: Vec<String>,
    state: State,
    offered_at: Instant,
    settled_at: Option<Instant>,
    result: Option<serde_json::Value>,
    /// Who claimed it for display; only they decide it.
    shown_by: Option<String>,
}

/// Who shows and decides a request: an approver gives consent to opens; the custodian decides
/// opens the older way, and unlocks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Approver,
    Custodian,
}

pub struct Gate<'a> {
    pub caller: &'a str,
    pub role: Role,
}

/// What the custodian decided: the wallet picked, its password, and the terms it granted.
#[derive(Debug)]
pub struct Decision {
    pub group: Option<String>,
    pub password: String,
    pub unlock: Option<Terms>,
    /// A device wallet's first day of use, given at its first open.
    pub birthday: Option<String>,
}

pub struct Shown {
    pub handle: String,
    pub requester: String,
    pub kind: &'static str,
    pub bundle_id: String,
    pub lines: Vec<String>,
    /// What was asked, for the app to offer: the wallet or the family and network to pick from,
    /// and the terms an app wants. Never the reason, which is in `lines` as a claim.
    pub asked: serde_json::Value,
    /// The named wallet's seed, when the manager knows it: the Signer app shows the open beside it.
    pub seed: Option<String>,
}

pub struct Summary {
    pub handle: String,
    pub requester: String,
    pub kind: &'static str,
    pub state: &'static str,
    pub age_ms: u128,
    /// The wallet an open names, when the manager knows it: the Signer app lists it there.
    pub seed: Option<String>,
}

#[derive(Default)]
pub struct Access {
    records: Vec<Record>,
    /// (module, group): a wallet open for a module.
    grants: Vec<(String, String)>,
    scopes: Vec<Scope>,
    seq: u64,
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

fn token(seq: u64) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{}{:x}", hex::encode(b), seq)
}

fn lower(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}

impl Access {
    pub fn new() -> Self {
        Self::default()
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        for r in &mut self.records {
            if r.state == State::Offered && now.duration_since(r.offered_at) > ABANDONED_OFFER_TTL {
                r.state = State::Settled("expired_no_ack");
            }
            if matches!(r.state, State::Settled(_)) && r.settled_at.is_none() {
                r.settled_at = Some(now);
            }
        }
        self.records.retain(|r| {
            let Some(at) = r.settled_at else { return true };
            r.result.is_some() || now.duration_since(at) < SETTLED_RETENTION
        });
    }

    pub fn owns(&self, handle: &str) -> bool {
        self.records.iter().any(|r| r.handle == handle)
    }

    fn by_receipt(&mut self, handle: &str, receipt: &str) -> Result<&mut Record> {
        let want = sha256(receipt.as_bytes());
        self.records
            .iter_mut()
            .find(|r| r.handle == handle && r.receipt_hash == want)
            .ok_or_else(|| ManagerError::NotFound(handle.to_string()))
    }

    fn admit(&mut self, requester: &str) -> Result<()> {
        self.sweep();
        let live = self.records.iter().filter(|r| !matches!(r.state, State::Settled(_)) && r.requester == requester).count();
        if live >= MAX_PENDING_PER_REQUESTER {
            return Err(bad("too many pending open or unlock requests for this requester"));
        }
        Ok(())
    }

    fn push(&mut self, requester: &str, kind: Kind, lines: Vec<String>) -> (String, String) {
        self.seq += 1;
        let handle = format!("sma_{}", token(self.seq));
        let receipt = format!("smr_{}", token(self.seq));
        let mut h = Sha256::new();
        h.update(b"logos-signer-manager-access-v1\n");
        h.update(requester.as_bytes());
        for l in &lines {
            h.update(b"\n");
            h.update(l.as_bytes());
        }
        self.records.push(Record {
            handle: handle.clone(),
            receipt_hash: sha256(receipt.as_bytes()),
            requester: requester.to_string(),
            kind,
            bundle_id: h.finalize().into(),
            lines,
            state: State::Offered,
            offered_at: Instant::now(),
            settled_at: None,
            result: None,
            shown_by: None,
        });
        (handle, receipt)
    }

    /// May this caller show and decide the record? An approver only opens, and once one caller
    /// claims a record, only that caller.
    fn may(&self, r: &Record, gate: &Gate) -> bool {
        let role = gate.role == Role::Custodian || matches!(r.kind, Kind::Open(_));
        role && r.shown_by.as_deref().is_none_or(|by| by == gate.caller)
    }

    /// A module asks for a Bitcoin wallet: one it names, or any of a family and network the person
    /// picks, creates or restores.
    pub fn request_open(
        &mut self,
        signers: &mut Registry,
        wallets: &Unlock,
        requester: &str,
        params_json: &str,
    ) -> Result<(String, String)> {
        self.admit(requester)?;
        let p: OpenParams = serde_json::from_str(params_json).map_err(|e| bad(format!("open: {e}")))?;
        check_displayable(&p.reason, "reason")?;
        if let Some(t) = &p.unlock {
            t.check()?;
        }
        let mut lines = vec![format!("{requester} asks to open a Bitcoin wallet")];
        match (&p.group, &p.family, &p.network) {
            (Some(g), None, n) if signers.find(g).is_err() && p.seed.as_deref().is_some_and(|s| !wallets.is_unlocked(s)) => {
                // Its seed is locked, so no signer lists it: it is checked once unlocked.
                let seed = p.seed.as_deref().unwrap_or_default();
                let name = wallets.wallets().into_iter().find(|w| w.seed == seed.trim()).map(|w| w.name);
                let name = name.ok_or_else(|| ManagerError::NotFound(format!("no wallet {}", seed.trim())))?;
                check_displayable(g, "group")?;
                let on = match n {
                    Some(n) => {
                        check_displayable(n, "network")?;
                        format!(" on {n}")
                    }
                    None => String::new(),
                };
                lines.push(format!("A Bitcoin wallet of {name}, locked{on}: unlock {name} to open it"));
            }
            (Some(g), None, n) => {
                let found = signers.find(g)?;
                let acct = AccountPublic::from_account(&found.account)?;
                let name = found.account.label.clone().unwrap_or_else(|| found.account.id.clone());
                let on = match n {
                    Some(n) => {
                        check_displayable(n, "network")?;
                        acct.chain.network(n)?;
                        format!(" on {n}")
                    }
                    None => String::new(),
                };
                lines.push(format!("Wallet: {name} ({}, {} chain){on}", acct.family.describe(), acct.chain.as_str()));
            }
            (None, Some(f), Some(n)) if f.is_bitcoin() => {
                let family = if *f == Family::Bitcoin { "native segwit" } else { "taproot" };
                check_displayable(n, "network")?;
                lines.push(format!("Any {family} wallet on {n}: pick one, create one or restore one"));
            }
            _ => return Err(bad("open: name a Bitcoin group, or a Bitcoin family and a network")),
        }
        lines.push("It will see every address and transaction of that wallet, and can ask you to sign.".into());
        if let Some(t) = &p.unlock {
            lines.push(format!("It also asks to unlock it: {}", t.describe(requester)));
        }
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Open(p), lines))
    }

    /// A module asks for an account to stay unlocked on terms the person decides.
    pub fn request_unlock(&mut self, signers: &mut Registry, requester: &str, params_json: &str) -> Result<(String, String)> {
        self.admit(requester)?;
        let p: UnlockParams = serde_json::from_str(params_json).map_err(|e| bad(format!("unlock: {e}")))?;
        p.terms().check()?;
        check_displayable(&p.reason, "reason")?;
        let found = signers.find(&p.account)?;
        if found.name != KEYSTORE {
            return Err(bad("unlock: a device account signs on its device; there is nothing to unlock"));
        }
        let name = found.account.label.clone().unwrap_or_else(|| found.account.id.clone());
        let mut lines = vec![
            format!("{requester} asks to unlock {name}"),
            format!("Terms asked: {}", p.terms().describe(requester)),
        ];
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Unlock(p), lines))
    }

    /// The wallet an open names: the seed it brings, if the manager knows it, else its group's.
    fn seed_of(r: &Record, signers: &mut Registry, wallets: &Unlock) -> Option<String> {
        let Kind::Open(p) = &r.kind else { return None };
        p.seed.clone().filter(|s| wallets.holders(s).is_ok()).or_else(|| {
            let found = signers.find(p.group.as_deref()?).ok()?;
            wallets.seed_of(&found.name, found.account.seed.as_deref()?)
        })
    }

    pub fn queue(&mut self, signers: &mut Registry, wallets: &Unlock, role: Role) -> Vec<Summary> {
        self.sweep();
        let now = Instant::now();
        self.records
            .iter()
            .filter(|r| !matches!(r.state, State::Settled(_)))
            .filter(|r| role == Role::Custodian || matches!(r.kind, Kind::Open(_)))
            .map(|r| Summary {
                seed: Self::seed_of(r, signers, wallets),
                handle: r.handle.clone(),
                requester: r.requester.clone(),
                kind: match r.kind {
                    Kind::Open(_) => "open",
                    Kind::Unlock(_) => "unlock",
                },
                state: if r.state == State::Rendered { "rendered" } else { "offered" },
                age_ms: now.duration_since(r.offered_at).as_millis(),
            })
            .collect()
    }

    pub fn acknowledge(&mut self, signers: &mut Registry, wallets: &Unlock, handle: &str, gate: &Gate) -> Result<Shown> {
        self.sweep();
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(&self.records[idx], gate) {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        for r in &mut self.records {
            if r.state == State::Rendered && r.handle != handle && r.shown_by.as_deref() == Some(gate.caller) {
                r.state = State::Offered;
            }
        }
        let seed = Self::seed_of(&self.records[idx], signers, wallets);
        let r = &mut self.records[idx];
        if let State::Settled(o) = r.state {
            return Err(bad(format!("already settled: {o}")));
        }
        r.state = State::Rendered;
        r.shown_by = Some(gate.caller.to_string());
        Ok(Shown {
            seed,
            handle: r.handle.clone(),
            requester: r.requester.clone(),
            kind: match r.kind {
                Kind::Open(_) => "open",
                Kind::Unlock(_) => "unlock",
            },
            bundle_id: hex::encode(r.bundle_id),
            lines: r.lines.clone(),
            asked: match &r.kind {
                Kind::Open(p) => serde_json::json!({ "group": p.group, "family": p.family, "network": p.network,
                                                     "unlock": p.unlock, "seed": p.seed }),
                Kind::Unlock(p) => serde_json::json!({ "account": p.account, "terms": p.terms() }),
            },
        })
    }

    /// The record being shown to this caller, with what was shown.
    fn shown(&mut self, handle: &str, bundle_id_echo: &str, gate: &Gate) -> Result<usize> {
        self.sweep();
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        let r = &self.records[idx];
        if !self.may(r, gate) {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        if r.state != State::Rendered {
            return Err(bad("approve_access: this handle was not the one being shown"));
        }
        if bundle_id_echo.trim().trim_start_matches("0x") != hex::encode(r.bundle_id) {
            return Err(bad("approve_access: bundle_id does not match what was shown"));
        }
        Ok(idx)
    }

    /// An approver's consent to an open, given in the Signer app once the wallet is unlocked: the
    /// module collects its descriptors and seed, and takes its database key from `data_key`.
    pub fn consent(
        &mut self,
        signers: &mut Registry,
        wallets: &Unlock,
        handle: &str,
        bundle_id_echo: &str,
        group: Option<String>,
        gate: &Gate,
    ) -> Result<()> {
        let idx = self.shown(handle, bundle_id_echo, gate)?;
        let r = &self.records[idx];
        let Kind::Open(p) = &r.kind else { return Err(ManagerError::Refused("not authorized".into())) };
        let group = match (&p.group, &group) {
            (Some(asked), Some(picked)) if asked != picked => return Err(bad("approve_access: this request names its wallet")),
            (Some(g), _) | (None, Some(g)) => g.clone(),
            (None, None) => return Err(bad("approve_access: pick the wallet to open")),
        };
        let locked = |name: &str| {
            ManagerError::Signer(logos_signer_interface::SignerError::new(
                logos_signer_interface::ErrorCode::Locked,
                format!("unlock {name} to open it"),
            ))
        };
        let found = match signers.find(&group) {
            Ok(f) => f,
            Err(e) => {
                let named = p.seed.as_deref().and_then(|s| wallets.wallets().into_iter().find(|w| w.seed == s.trim()));
                return Err(match named {
                    Some(w) if w.locked => locked(&w.name),
                    _ => e,
                });
            }
        };
        let seed = found
            .account
            .seed
            .as_deref()
            .and_then(|s| wallets.seed_of(&found.name, s))
            .ok_or_else(|| bad("approve_access: this wallet's signer doesn't unlock by seed; open it in the keys app"))?;
        if p.seed.as_deref().is_some_and(|asked| asked.trim() != seed) {
            return Err(bad("approve_access: the wallet named isn't of the seed named"));
        }
        if !wallets.is_unlocked(&seed) {
            let name = wallets.wallets().into_iter().find(|w| w.seed == seed).map(|w| w.name).unwrap_or_default();
            return Err(locked(&name));
        }
        let acct = AccountPublic::from_account(&found.account)?;
        if let Some(f) = &p.family {
            if found.account.family != *f {
                return Err(bad("approve_access: the wallet picked is not the family asked for"));
            }
        }
        if let Some(n) = &p.network {
            acct.chain.network(n)?;
        }
        let about = wallets.about(&seed)?;
        let result = serde_json::json!({
            "group": group, "family": found.account.family, "chain": acct.chain.as_str(), "network": p.network,
            "external": acct.descriptor(0), "internal": acct.descriptor(1),
            "fingerprint": acct.fingerprint.to_string(), "seed": seed,
            "origin": about.origin, "birthday": about.birthday,
        });
        let requester = r.requester.clone();
        self.grants.retain(|(m, g)| !(m == &requester && g == &group));
        self.grants.push((requester, group));
        let r = &mut self.records[idx];
        r.result = Some(result);
        r.state = State::Settled("approved");
        Ok(())
    }

    /// The person decided in the keys app: the wallet, its password, and any unlock terms.
    pub fn approve(
        &mut self,
        signers: &mut Registry,
        keys: &mut dyn KeyHolder,
        handle: &str,
        bundle_id_echo: &str,
        decision: Decision,
        gate: &Gate,
    ) -> Result<()> {
        if gate.role != Role::Custodian {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let idx = self.shown(handle, bundle_id_echo, gate)?;
        let r = &self.records[idx];
        let requester = r.requester.clone();
        let password = Zeroizing::new(decision.password);
        let (result, scope) = match &r.kind {
            Kind::Open(p) => {
                let group = match (&p.group, &decision.group) {
                    (Some(asked), Some(picked)) if asked != picked => {
                        return Err(bad("approve_access: this request names its wallet"));
                    }
                    (Some(g), _) | (None, Some(g)) => g.clone(),
                    (None, None) => return Err(bad("approve_access: pick the wallet to open")),
                };
                let found = signers.find(&group)?;
                let acct = AccountPublic::from_account(&found.account)?;
                if let (Some(f), Some(n)) = (&p.family, &p.network) {
                    if found.account.family != *f {
                        return Err(bad("approve_access: the wallet picked is not the family asked for"));
                    }
                    acct.chain.network(n)?;
                }
                // A device account signs on its device, and its database key has a vault of its own.
                let on_device = found.name != KEYSTORE;
                if on_device && decision.unlock.is_some() {
                    return Err(bad("approve_access: a device account signs on its device; there is nothing to unlock"));
                }
                if !on_device && decision.birthday.is_some() {
                    return Err(bad("approve_access: a keystore wallet's birthday was set when it was made"));
                }
                let terms = if on_device { None } else { decision.unlock.or_else(|| p.unlock.clone()) };
                let opened = if on_device {
                    let (signer, account) = database_holder(signers, keys, &found)?;
                    keys.device_database_key(&signer, &account, &password, decision.birthday.as_deref())?
                } else {
                    keys.database_key(&group, Some(&password))?
                };
                let scope = match &terms {
                    Some(t) => {
                        t.check()?;
                        keys.unlock(&group, &password, t.ttl_ms, t.count)?;
                        Some(scope_for(&group, t, &requester))
                    }
                    None => None,
                };
                let result = serde_json::json!({
                    "group": group, "family": found.account.family, "chain": acct.chain.as_str(), "network": p.network,
                    "external": acct.descriptor(0), "internal": acct.descriptor(1),
                    "fingerprint": acct.fingerprint.to_string(), "databaseKey": opened.database_key.as_str(),
                    "origin": opened.origin, "birthday": opened.birthday, "unlocked": terms,
                });
                self.grants.retain(|(m, g)| !(m == &requester && g == &group));
                self.grants.push((requester.clone(), group));
                (result, scope)
            }
            Kind::Unlock(p) => {
                let terms = decision.unlock.unwrap_or_else(|| p.terms());
                terms.check()?;
                let found = signers.find(&p.account)?;
                let u = keys.unlock(&found.account.id, &password, terms.ttl_ms, terms.count)?;
                let result = serde_json::json!({ "account": found.account.id, "terms": terms,
                                                 "expiresInMs": u.expires_in_ms, "countLeft": u.count_left });
                (result, Some(scope_for(&found.account.id, &terms, &requester)))
            }
        };
        if let Some(s) = scope {
            self.scopes.retain(|x| x.account != s.account);
            self.scopes.push(s);
        }
        let r = &mut self.records[idx];
        r.result = Some(result);
        r.state = State::Settled("approved");
        Ok(())
    }

    pub fn reject(&mut self, handle: &str, gate: &Gate) -> Result<()> {
        let idx = self.records.iter().position(|r| r.handle == handle).ok_or_else(|| ManagerError::NotFound(handle.into()))?;
        if !self.may(&self.records[idx], gate) {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let r = &mut self.records[idx];
        if let State::Settled(o) = r.state {
            return Err(bad(format!("already settled: {o}")));
        }
        r.state = State::Settled("rejected");
        Ok(())
    }

    pub fn status(&mut self, handle: &str, receipt: &str) -> Result<(&'static str, Option<&'static str>)> {
        self.sweep();
        Ok(match self.by_receipt(handle, receipt)?.state {
            State::Offered => ("offered", None),
            State::Rendered => ("rendered", None),
            State::Settled(o) => ("settled", Some(o)),
        })
    }

    /// The open's descriptors and database key, or the unlock's granted terms. Repeatable until acked.
    pub fn fetch(&mut self, handle: &str, receipt: &str) -> Result<serde_json::Value> {
        self.sweep();
        self.by_receipt(handle, receipt)?.result.clone().ok_or_else(|| bad("no result for this handle"))
    }

    pub fn ack(&mut self, handle: &str, receipt: &str) -> Result<()> {
        self.by_receipt(handle, receipt)?.result = None;
        self.sweep();
        Ok(())
    }

    pub fn cancel(&mut self, handle: &str, receipt: &str) -> Result<()> {
        let r = self.by_receipt(handle, receipt)?;
        if !matches!(r.state, State::Settled(_)) {
            r.state = State::Settled("cancelled");
        }
        r.result = None;
        self.sweep();
        Ok(())
    }

    /// A wallet's descriptors again, for a module it is open for.
    pub fn descriptors(&self, signers: &mut Registry, module: &str, group: &str) -> Result<(String, String)> {
        if !self.grants.iter().any(|(m, g)| m == module && g == group.trim()) {
            return Err(ManagerError::Refused("this wallet is not open for this module".into()));
        }
        let found = signers.find(group)?;
        let acct = AccountPublic::from_account(&found.account)?;
        Ok((acct.descriptor(0), acct.descriptor(1)))
    }

    /// Close a wallet for a module; an unlock scoped to that module alone ends with it.
    pub fn close(&mut self, keys: &mut dyn KeyHolder, module: &str, group: &str) -> Result<bool> {
        let before = self.grants.len();
        self.grants.retain(|(m, g)| !(m == module && g == group.trim()));
        let closed = self.grants.len() != before;
        let account = lower(group);
        if closed && self.scopes.iter().any(|s| s.account == account && s.apps == [module.to_string()]) {
            self.scopes.retain(|s| s.account != account);
            keys.lock(Some(group.trim()))?;
        }
        Ok(closed)
    }

    pub fn open_accounts(&self) -> Vec<(String, String)> {
        self.grants.clone()
    }

    /// The person's own unlock from the keys app, with nobody asking.
    pub fn unlock(&mut self, signers: &mut Registry, keys: &mut dyn KeyHolder, account: &str, password: &str, terms: &Terms) -> Result<Unlocked> {
        terms.check()?;
        if terms.apps.is_empty() {
            return Err(bad("unlock: name the apps it covers"));
        }
        let found = signers.find(account)?;
        let u = keys.unlock(&found.account.id, password, terms.ttl_ms, terms.count)?;
        let s = scope_for(&found.account.id, terms, "");
        self.scopes.retain(|x| x.account != s.account);
        self.scopes.push(s);
        Ok(u)
    }

    pub fn lock(&mut self, keys: &mut dyn KeyHolder, account: Option<&str>) -> Result<usize> {
        match account {
            Some(a) => self.scopes.retain(|s| s.account != lower(a)),
            None => self.scopes.clear(),
        }
        keys.lock(account)
    }

    /// The keystore's unlocks, with the apps and confirmation this module keeps for each.
    pub fn unlocked(&mut self, keys: &mut dyn KeyHolder) -> Result<Vec<(Unlocked, Vec<String>, bool)>> {
        let held = keys.unlocked()?;
        self.scopes.retain(|s| held.iter().any(|u| lower(&u.account) == s.account));
        Ok(held
            .into_iter()
            .map(|u| {
                let s = self.scopes.iter().find(|s| s.account == lower(&u.account));
                let (apps, confirm) = s.map_or((Vec::new(), true), |s| (s.apps.clone(), s.confirm));
                (u, apps, confirm)
            })
            .collect())
    }

    /// Does an unlock of `account` cover a request from `requester`, and how?
    pub fn covers(&self, account: &str, requester: &str) -> Cover {
        let Some(s) = self.scopes.iter().find(|s| s.account == lower(account)) else { return Cover::No };
        let named = s.apps.iter().any(|a| a == requester);
        match (named, s.apps.iter().any(|a| a == "*"), s.confirm) {
            (true, _, false) => Cover::WithoutAsking,
            (true, _, true) | (false, true, true) => Cover::Confirmed,
            _ => Cover::No,
        }
    }

    /// The keystore answered `locked` for an account this module thought unlocked: its time or count ran out.
    pub fn expired(&mut self, account: &str) {
        self.scopes.retain(|s| s.account != lower(account));
    }
}

/// Whose name a device wallet's database key is kept under: the holder that already has one,
/// else the first in configured order. So reopening it through the Shell instead of the reader
/// finds the same key, and the wallet's database with it.
fn database_holder(signers: &mut Registry, keys: &mut dyn KeyHolder, found: &Found) -> Result<(String, String)> {
    let mut holders: Vec<Found> =
        signers.holders(&found.account.id)?.into_iter().filter(|f| f.name != KEYSTORE).collect();
    holders.sort_by_key(|f| f.signer);
    let kept = keys.device_wallets()?;
    let pick = holders
        .iter()
        .find(|f| kept.iter().any(|(s, a)| *s == f.name && *a == f.account.id))
        .or(holders.first())
        .unwrap_or(found);
    Ok((pick.name.clone(), pick.account.id.clone()))
}

fn scope_for(account: &str, terms: &Terms, requester: &str) -> Scope {
    let apps = if terms.apps.is_empty() { vec![requester.to_string()] } else { terms.apps.clone() };
    Scope { account: lower(account), apps, confirm: terms.confirm }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};

    /// The keystore's extras, in memory: password "pw", a fixed database key, unlocks by account.
    #[derive(Default)]
    pub(crate) struct FakeKeys {
        pub unlocks: Vec<Unlocked>,
        /// Device wallets by signer and account: their password, key and birthday.
        pub devices: std::collections::HashMap<(String, String), (String, String, Option<String>)>,
    }

    impl KeyHolder for FakeKeys {
        fn database_key(&mut self, _: &str, password: Option<&str>) -> Result<OpenedWallet> {
            match password {
                Some("pw") => Ok(OpenedWallet {
                    database_key: Zeroizing::new("ab".repeat(32)),
                    origin: "restored".into(),
                    birthday: Some("2021-11-14".into()),
                }),
                _ => Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this account is not correct",
                ))),
            }
        }
        fn device_database_key(&mut self, signer: &str, account: &str, password: &str, birthday: Option<&str>)
            -> Result<OpenedWallet> {
            let n = self.devices.len() + 1;
            let (pw, key, day) = self.devices.entry((signer.into(), account.into())).or_insert_with(|| {
                (password.into(), format!("{n:02x}").repeat(32), birthday.map(str::to_string))
            });
            if pw != password {
                return Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this wallet's database key is not correct",
                )));
            }
            Ok(OpenedWallet { database_key: Zeroizing::new(key.clone()), origin: "restored".into(), birthday: day.clone() })
        }
        fn device_wallets(&mut self) -> Result<Vec<(String, String)>> {
            Ok(self.devices.keys().cloned().collect())
        }
        fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> Result<Unlocked> {
            self.database_key(account, Some(password))?;
            let u = Unlocked { account: account.to_ascii_lowercase(), expires_in_ms: ttl_ms, count_left: count };
            self.unlocks.retain(|x| x.account != u.account);
            self.unlocks.push(u.clone());
            Ok(u)
        }
        fn lock(&mut self, account: Option<&str>) -> Result<usize> {
            let before = self.unlocks.len();
            match account {
                Some(a) => self.unlocks.retain(|u| u.account != a.to_ascii_lowercase()),
                None => self.unlocks.clear(),
            }
            Ok(before - self.unlocks.len())
        }
        fn unlocked(&mut self) -> Result<Vec<Unlocked>> {
            Ok(self.unlocks.clone())
        }
    }

    fn fixture() -> (Registry, FakeKeys, Access) {
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions::default())));
        (r, FakeKeys::default(), Access::new())
    }

    /// The keys app.
    pub(crate) const KEYS: Gate<'static> = Gate { caller: "evm_keystore_ui", role: Role::Custodian };
    /// The Signer app.
    const SIGNER: Gate<'static> = Gate { caller: "evm_signer_ui", role: Role::Approver };

    #[test]
    fn reopening_a_wallet_may_name_its_network_and_a_wrong_one_is_refused_up_front() {
        let (mut s, mut k, mut a) = fixture();
        let req = |n: &str| format!(r#"{{"group":"mock-segwit","network":"{n}"}}"#);
        assert!(a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", &req("bitcoin")).is_err(), "a test wallet on mainnet");
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", &req("regtest")).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        assert!(shown.lines.iter().any(|l| l.ends_with("test chain) on regtest")), "{:?}", shown.lines);
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["network"], "regtest");
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &KEYS).unwrap();
        assert!(a.fetch(&h, &r).unwrap()["network"].is_null(), "named nothing, echoes nothing");
    }

    fn decide(group: Option<&str>, password: &str, unlock: Option<Terms>) -> Decision {
        Decision { group: group.map(str::to_string), password: password.into(), unlock, birthday: None }
    }

    /// A device's module offering the mock's accounts, and no keystore.
    fn device_fixture() -> (Registry, FakeKeys, Access) {
        let mut r = Registry::new();
        r.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        (r, FakeKeys::default(), Access::new())
    }

    #[test]
    fn a_device_wallet_opens_with_a_password_set_at_its_first_open_and_has_nothing_to_unlock() {
        let (mut s, mut k, mut a) = device_fixture();
        let ask = r#"{"group":"mock-segwit","network":"regtest","unlock":{"ttlMs":60000}}"#;
        let open = |a: &mut Access, s: &mut Registry| {
            let (h, r) = a.request_open(s, &Unlock::in_memory(), "bitcoin_wallet_core_module", ask).unwrap();
            let bundle = a.acknowledge(s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
            (h, r, bundle)
        };
        let decision = |pw: &str, unlock: Option<Terms>, birthday: Option<&str>| Decision {
            group: None,
            password: pw.into(),
            unlock,
            birthday: birthday.map(str::to_string),
        };
        let (h, r, b) = open(&mut a, &mut s);
        let terms = Terms { ttl_ms: Some(1000), confirm: true, ..Default::default() };
        assert!(a.approve(&mut s, &mut k, &h, &b, decision("data-pw", Some(terms), None), &KEYS).is_err(), "nothing to unlock");
        a.approve(&mut s, &mut k, &h, &b, decision("data-pw", None, Some("2021-11-14")), &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!((got["origin"].as_str(), got["birthday"].as_str()), (Some("restored"), Some("2021-11-14")));
        assert_eq!(got["unlocked"], serde_json::Value::Null, "the app asked for terms; a device grants none");
        assert!(k.devices.contains_key(&("keycard_shell_module".to_string(), "mock-segwit".to_string())));
        let first = got["databaseKey"].as_str().unwrap().to_string();

        // Opened again: the same key, behind the password set the first time.
        let (h, r, b) = open(&mut a, &mut s);
        assert!(a.approve(&mut s, &mut k, &h, &b, decision("nope", None, None), &KEYS).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &b, decision("data-pw", None, None), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some(first.as_str()));

        // And an unlock is refused before anything is shown.
        let unlock = r#"{"account":"mock-segwit","ttlMs":60000}"#;
        assert!(a.request_unlock(&mut s, "bitcoin_wallet_core_module", unlock).is_err());
    }

    #[test]
    fn a_device_wallet_keeps_its_database_key_whichever_transport_opens_it() {
        let mut s = Registry::new();
        s.add("keycard_module", Box::new(MockSigner::new(MockOptions::default())));
        s.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        // First opened through the Shell; now the card is in a reader, which is preferred.
        let shell = ("keycard_shell_module".to_string(), "mock-segwit".to_string());
        k.devices.insert(shell.clone(), ("data-pw".into(), "cd".repeat(32), None));
        assert_eq!(s.find("mock-segwit").unwrap().name, "keycard_module");
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let bundle = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
        a.approve(&mut s, &mut k, &h, &bundle, decide(None, "data-pw", None), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some("cd".repeat(32).as_str()));
        assert_eq!(k.devices.keys().collect::<Vec<_>>(), vec![&shell], "no second key, no second database");
    }

    #[test]
    fn a_keystore_wallet_takes_no_birthday_at_open() {
        let (mut s, mut k, mut a) = fixture();
        let (h, _) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"group":"mock-segwit","network":"regtest"}"#).unwrap();
        let bundle = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
        let d = Decision { group: None, password: "pw".into(), unlock: None, birthday: Some("2021-11-14".into()) };
        assert!(a.approve(&mut s, &mut k, &h, &bundle, d, &KEYS).is_err(), "it was set when the wallet was made");
    }

    #[test]
    fn an_open_request_gives_the_requester_its_wallet_and_nobody_else_its_descriptors() {
        let (mut s, mut k, mut a) = fixture();
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"family":"bitcoin","network":"signet"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        assert!(shown.lines.join("\n").contains("Any native segwit wallet on signet"), "{:?}", shown.lines);
        assert_eq!(shown.asked, serde_json::json!({ "group": null, "family": "bitcoin", "network": "signet", "unlock": null, "seed": null }));
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &KEYS).is_err(), "no wallet picked");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-taproot"), "pw", None), &KEYS).is_err(), "wrong family");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "nope", None), &KEYS).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "pw", None), &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["group"], "mock-segwit");
        assert_eq!((got["chain"].as_str(), got["network"].as_str()), (Some("test"), Some("signet")));
        assert_eq!(got["databaseKey"], "ab".repeat(32));
        assert_eq!((got["origin"].as_str(), got["birthday"].as_str()), (Some("restored"), Some("2021-11-14")));
        assert!(got["external"].as_str().unwrap().starts_with("wpkh(["));
        let (ext, _) = a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").unwrap();
        assert_eq!(ext, got["external"].as_str().unwrap());
        assert!(a.descriptors(&mut s, "someone_else", "mock-segwit").is_err());
        a.ack(&h, &r).unwrap();
        assert!(a.fetch(&h, &r).is_err());
        assert!(a.close(&mut k, "bitcoin_wallet_core_module", "mock-segwit").unwrap());
        assert!(a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").is_err());
    }

    #[test]
    fn an_open_with_unlock_terms_unlocks_for_the_requester_and_closing_locks_it() {
        let (mut s, mut k, mut a) = fixture();
        let (h, _) = a
            .request_open(&mut s, &Unlock::in_memory(), "wallet_core", r#"{"group":"mock-taproot","unlock":{"ttlMs":3600000}}"#)
            .unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        assert!(shown.lines.join("\n").contains("for 60 minutes, for wallet_core, each one confirmed"), "{:?}", shown.lines);
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &KEYS).unwrap();
        assert_eq!(a.covers("mock-taproot", "wallet_core"), Cover::Confirmed);
        assert_eq!(a.covers("mock-taproot", "another_app"), Cover::No);
        assert_eq!(k.unlocks.len(), 1);
        a.close(&mut k, "wallet_core", "mock-taproot").unwrap();
        assert_eq!(a.covers("mock-taproot", "wallet_core"), Cover::No);
        assert!(k.unlocks.is_empty(), "an unlock scoped to the wallet ends when it closes");
    }

    #[test]
    fn the_person_decides_the_terms_not_the_app() {
        let (mut s, mut k, mut a) = fixture();
        let (h, r) = a
            .request_unlock(&mut s, "game", r#"{"account":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","count":50,"ttlMs":1800000,"confirm":false,"apps":["game"]}"#)
            .unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        assert!(shown.lines.join("\n").contains("WITHOUT showing them to you"), "{:?}", shown.lines);
        // The person keeps confirmation on and allows ten.
        let granted = Terms { ttl_ms: Some(600_000), count: Some(10), apps: vec!["game".into()], confirm: true };
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", Some(granted)), &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["terms"]["count"], 10);
        assert_eq!(got["terms"]["confirm"], true);
        assert_eq!(a.covers("0xF39FD6E51AAD88F6F4CE6AB8827279CFFFB92266", "game"), Cover::Confirmed);
    }

    #[test]
    fn signing_without_asking_names_its_apps_and_any_app_needs_confirmation() {
        let (mut s, mut k, mut a) = fixture();
        let acct = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let any_unseen = Terms { ttl_ms: None, count: None, apps: vec!["*".into()], confirm: false };
        assert!(a.unlock(&mut s, &mut k, acct, "pw", &any_unseen).is_err());
        let named = Terms { ttl_ms: Some(60_000), count: Some(3), apps: vec!["game".into()], confirm: false };
        a.unlock(&mut s, &mut k, acct, "pw", &named).unwrap();
        assert_eq!(a.covers(acct, "game"), Cover::WithoutAsking);
        assert_eq!(a.covers(acct, "wallet"), Cover::No);
        let any_confirmed = Terms { ttl_ms: None, count: None, apps: vec!["*".into()], confirm: true };
        a.unlock(&mut s, &mut k, acct, "pw", &any_confirmed).unwrap();
        assert_eq!(a.covers(acct, "wallet"), Cover::Confirmed);
        assert_eq!(a.lock(&mut k, None).unwrap(), 1);
        assert_eq!(a.covers(acct, "wallet"), Cover::No);
    }

    #[test]
    fn an_unlock_ends_here_when_the_keystore_ends_it_and_one_lock_leaves_the_rest() {
        let (mut s, mut k, mut a) = fixture();
        let acct = "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266";
        let terms = Terms { ttl_ms: Some(60_000), count: Some(2), apps: vec!["game".into()], confirm: true };
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        // The keystore answered `locked`: its time or count ran out first.
        a.expired(acct);
        assert_eq!(a.covers(acct, "game"), Cover::No);
        // The keystore dropped it on its own: the next listing drops this module's terms too.
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        k.unlocks.clear();
        assert!(a.unlocked(&mut k).unwrap().is_empty());
        assert_eq!(a.covers(acct, "game"), Cover::No);
        // Locking one account leaves the others unlocked.
        a.unlock(&mut s, &mut k, acct, "pw", &terms).unwrap();
        a.unlock(&mut s, &mut k, "mock-segwit", "pw", &terms).unwrap();
        assert_eq!(a.lock(&mut k, Some(acct)).unwrap(), 1);
        assert_eq!((a.covers(acct, "game"), a.covers("mock-segwit", "game")), (Cover::No, Cover::Confirmed));
    }

    #[test]
    fn a_requester_cannot_flood_the_custodian() {
        let (mut s, _, mut a) = fixture();
        for _ in 0..MAX_PENDING_PER_REQUESTER {
            a.request_open(&mut s, &Unlock::in_memory(), "noisy", r#"{"group":"mock-segwit"}"#).unwrap();
        }
        assert!(a.request_open(&mut s, &Unlock::in_memory(), "noisy", r#"{"group":"mock-segwit"}"#).is_err());
        assert!(a.request_open(&mut s, &Unlock::in_memory(), "quiet", r#"{"group":"mock-segwit"}"#).is_ok());
        assert!(a.request_open(&mut s, &Unlock::in_memory(), "x", r#"{"group":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}"#).is_err(), "an EVM account is no wallet");
    }

    /// A card in a reader holding the mock's seed, and the manager's record of that seed, locked.
    fn enrolled() -> (Registry, Unlock, String, Vec<u8>) {
        use logos_signer_interface::{Signer, UnlockKeyRequest};
        let mut card = MockSigner::new(MockOptions::default());
        let recogniser = card.accounts().unwrap()[0].seed.clone().unwrap();
        let job = card.unlock_key(UnlockKeyRequest { seed: recogniser.clone(), index: 0, secret: None }).unwrap();
        let key = hex::decode(card.unlock_key_result(&job).unwrap().key.expose()).unwrap();
        let mut w = Unlock::in_memory();
        let holder = crate::unlock::Holder { signer: "keycard_module".into(), seed: recogniser, kind: "keycard".into() };
        let about = crate::unlock::About { origin: Some("restored".into()), birthday: Some("2021-11-14".into()), private_name: None };
        let seed = w.enroll(holder, Some(&key), "Card", about).unwrap().seed;
        w.lock(None);
        let mut r = Registry::new();
        r.add("keycard_module", Box::new(card));
        (r, w, seed, key)
    }

    fn unlock(w: &mut Unlock, seed: &str, key: &[u8]) {
        let way = w.wallets()[0].ways[0].0.clone();
        let secrets = crate::unlock::Secrets { device: Some(Zeroizing::new(key.to_vec())), ..Default::default() };
        w.unlock(seed, &way, &secrets).unwrap();
    }

    #[test]
    fn an_approver_opens_an_unlocked_wallet_with_its_seed_and_no_database_key() {
        let (mut s, mut w, seed, key) = enrolled();
        let mut a = Access::new();
        let (h, r) = a.request_open(&mut s, &w, "bitcoin_wallet_core_module", OPEN).unwrap();
        assert_eq!(a.queue(&mut s, &w, Role::Approver)[0].seed.as_deref(), Some(seed.as_str()), "listed under its wallet");
        let shown = a.acknowledge(&mut s, &w, &h, &SIGNER).unwrap();
        assert_eq!(shown.seed.as_deref(), Some(seed.as_str()), "shown beside its wallet");
        let locked = a.consent(&mut s, &w, &h, &shown.bundle_id, None, &SIGNER).unwrap_err();
        assert_eq!(locked.wire_code().as_deref(), Some("locked"));
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "still on screen while it is unlocked");
        unlock(&mut w, &seed, &key);
        a.consent(&mut s, &w, &h, &shown.bundle_id, None, &SIGNER).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!((got["seed"].as_str(), got["network"].as_str()), (Some(seed.as_str()), Some("regtest")));
        assert_eq!((got["origin"].as_str(), got["birthday"].as_str()), (Some("restored"), Some("2021-11-14")));
        assert!(got.get("databaseKey").is_none(), "{got}");
        assert!(got["external"].as_str().unwrap().starts_with("wpkh(["));
        assert!(a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").is_ok());
    }

    #[test]
    fn a_wallet_named_by_its_locked_seed_waits_for_its_unlock() {
        let (_, w, seed, _) = enrolled();
        let mut nobody = Registry::new();
        let mut a = Access::new();
        let ask = format!(r#"{{"group":"mock-segwit","network":"regtest","seed":"{seed}"}}"#);
        let (h, _) = a.request_open(&mut nobody, &w, "bitcoin_wallet_core_module", &ask).unwrap();
        let shown = a.acknowledge(&mut nobody, &w, &h, &SIGNER).unwrap();
        assert!(shown.lines.iter().any(|l| l.contains("unlock Card to open it")), "{:?}", shown.lines);
        assert_eq!(shown.seed.as_deref(), Some(seed.as_str()));
        let e = a.consent(&mut nobody, &w, &h, &shown.bundle_id, None, &SIGNER).unwrap_err();
        assert_eq!(e.wire_code().as_deref(), Some("locked"));
        let unknown = r#"{"group":"mock-segwit","seed":"s_nope"}"#;
        assert!(a.request_open(&mut nobody, &w, "x", unknown).is_err());
    }

    #[test]
    fn the_first_app_to_show_an_open_keeps_it_and_an_approver_decides_only_opens() {
        let (mut s, mut w, seed, key) = enrolled();
        unlock(&mut w, &seed, &key);
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let (h, _) = a.request_open(&mut s, &w, "bitcoin_wallet_core_module", OPEN).unwrap();
        let shown = a.acknowledge(&mut s, &w, &h, &SIGNER).unwrap();
        assert!(matches!(a.acknowledge(&mut s, &w, &h, &KEYS), Err(ManagerError::Refused(_))), "the Signer app's now");
        assert!(a.reject(&h, &KEYS).is_err());
        let custodian_way = a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw", None), &SIGNER);
        assert!(matches!(custodian_way, Err(ManagerError::Refused(_))), "an approver gives consent, no password");
        a.reject(&h, &SIGNER).unwrap();

        // Only the keystore's accounts unlock for signing.
        let (mut ks, _, _) = fixture();
        let (h, _) = a.request_unlock(&mut ks, "game", r#"{"account":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"}"#).unwrap();
        assert!(a.queue(&mut ks, &w, Role::Approver).iter().all(|q| q.handle != h), "unlocks stay with the keys app");
        assert!(a.queue(&mut ks, &w, Role::Custodian).iter().any(|q| q.handle == h));
        assert!(matches!(a.acknowledge(&mut ks, &w, &h, &SIGNER), Err(ManagerError::Refused(_))));
    }

    const OPEN: &str = r#"{"group":"mock-segwit","network":"regtest"}"#;
}
