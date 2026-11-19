//! Opening wallets and asking for allowances: requests a person decides in the Signer app (an
//! approver) or the keys app (the custodian), and the wallets they leave open.
//!
//! An open request connects one Bitcoin wallet to one module for this session. An approver gives
//! consent once the wallet is unlocked: the module collects the wallet's descriptors and its seed
//! with its receipt, and takes its database key from `data_key`. The custodian's older path hands
//! over a database key from the keystore. The module may read the descriptors again until it
//! closes the wallet. An allowance request asks for a standing permission of the module's own,
//! which an approver may grant as asked or narrow. Nothing here is written down.

use std::time::{Duration, Instant};

use rand::RngCore;
use serde::de::IgnoredAny;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use logos_signer_interface::Family;

use crate::allowance::{self, Caller, Grant, Limits, Scope};
use crate::btc::AccountPublic;
use crate::error::{bad, ManagerError, Result};
use crate::evm::check_displayable;
use crate::registry::{Found, Registry};
use crate::unlock::Unlock;

pub const MAX_PENDING_PER_REQUESTER: usize = 2;
pub const SETTLED_RETENTION: Duration = Duration::from_secs(120);
pub const ABANDONED_OFFER_TTL: Duration = Duration::from_secs(300);

// The signer whose Bitcoin wallets keep their database key in their own vault; any other is a device.
use crate::roster::KEYSTORE;

/// What the keystore does for an open or an allowance, beyond the signer interface.
pub trait KeyHolder {
    fn database_key(&mut self, group: &str, password: Option<&str>) -> Result<Zeroizing<String>>;
    /// A device account's database key, made at its first open under the password the person set.
    fn device_database_key(&mut self, signer: &str, account: &str, password: &str) -> Result<Zeroizing<String>>;
    /// The device wallets that have a database key, as `(signer, account)`.
    fn device_wallets(&mut self) -> Result<Vec<(String, String)>>;
    /// Keep the account's key ready to sign. The password is checked and not kept.
    fn hold_key(&mut self, account: &str, password: &str) -> Result<()>;
    fn release_key(&mut self, account: Option<&str>) -> Result<usize>;
    fn held_keys(&mut self) -> Result<Vec<String>>;
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
    /// The wallet's seed, as an earlier open handed it over: names a wallet whose seed is locked,
    /// so its signers list it no more until it is unlocked.
    #[serde(default)]
    pub seed: Option<String>,
    #[serde(default)]
    pub reason: String,
}

/// `{ account, scope, limits?, review?, endsAtRestart?, via?, reason? }`: what a module asks for
/// itself. `via` names the module its requests go through.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AllowanceParams {
    pub account: String,
    pub scope: Scope,
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub review: bool,
    #[serde(default)]
    pub ends_at_restart: bool,
    #[serde(default)]
    pub via: Option<String>,
    #[serde(default)]
    pub reason: String,
}

impl AllowanceParams {
    fn grant(&self, requester: &str) -> Grant {
        let caller = match &self.via {
            Some(via) => Caller { module: via.clone(), on_behalf_of: Some(requester.to_string()) },
            None => Caller { module: requester.to_string(), on_behalf_of: None },
        };
        Grant {
            account: self.account.clone(),
            callers: vec![caller],
            scope: self.scope.clone(),
            review: self.review,
            ends_at_restart: self.ends_at_restart,
            limits: self.limits.clone(),
        }
    }
}

/// What the person changed in an allowance a module asked for.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Narrowed {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub review: bool,
    #[serde(default)]
    pub ends_at_restart: bool,
}

impl Narrowed {
    pub fn applied_to(self, asked: &Grant) -> Grant {
        Grant { limits: self.limits, review: self.review, ends_at_restart: self.ends_at_restart, ..asked.clone() }
    }
}

#[derive(Debug)]
enum Kind {
    Open(OpenParams),
    Allowance(Box<Grant>),
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

/// Who shows and decides a request: an approver gives consent to opens and decides allowances;
/// the custodian decides opens the older way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Approver,
    Custodian,
    Both,
}


pub struct Gate<'a> {
    pub caller: &'a str,
    pub role: Role,
}

/// What the custodian decided: the wallet picked and its password.
#[derive(Debug)]
pub struct Decision {
    pub group: Option<String>,
    pub password: String,
}

/// `approve_access`'s params: an approver's consent or allowance, or the custodian's decision.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveParams {
    pub handle: String,
    pub bundle_id: String,
    #[serde(default)]
    pub group: Option<String>,
    /// The custodian's path and an allowance's; an approver's consent to an open carries none.
    #[serde(default)]
    pub password: Option<String>,
    /// An allowance as the person narrowed it; left out, as it was asked for.
    #[serde(default)]
    pub allowance: Option<Narrowed>,
    /// Older keys apps still send a device wallet's birthday; ignored.
    #[serde(default, rename = "birthday")]
    _birthday: IgnoredAny,
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

    /// May this caller show and decide the record? Only an approver decides an allowance, and
    /// once one caller claims a record, only that caller.
    fn may(&self, r: &Record, gate: &Gate) -> bool {
        let role = gate.role != Role::Custodian || matches!(r.kind, Kind::Open(_));
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
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Open(p), lines))
    }

    /// A module asks for an allowance of its own: the callers are never its to name.
    pub fn request_allowance(&mut self, signers: &mut Registry, requester: &str, params_json: &str) -> Result<(String, String)> {
        self.admit(requester)?;
        let p: AllowanceParams = serde_json::from_str(params_json).map_err(|e| bad(format!("allowance: {e}")))?;
        check_displayable(&p.reason, "reason")?;
        let mut grant = p.grant(requester);
        let name = allowance::bind(&mut grant, signers)?;
        let mut lines = vec![format!("{requester} asks for an allowance on {name}")];
        lines.extend(grant.describe());
        if !p.reason.trim().is_empty() {
            lines.push(format!("Reason (claimed by the requester): {}", p.reason.trim()));
        }
        Ok(self.push(requester, Kind::Allowance(Box::new(grant)), lines))
    }

    pub fn is_allowance(&self, handle: &str) -> bool {
        self.records.iter().any(|r| r.handle == handle && matches!(r.kind, Kind::Allowance(_)))
    }

    /// The allowance on this approver's screen, as it was asked for.
    pub fn allowance_shown(&mut self, handle: &str, bundle_id_echo: &str, gate: &Gate) -> Result<Grant> {
        let idx = self.shown(handle, bundle_id_echo, gate)?;
        match &self.records[idx].kind {
            Kind::Allowance(g) => Ok((**g).clone()),
            Kind::Open(_) => Err(ManagerError::Refused("not authorized".into())),
        }
    }

    /// The person granted it: the module collects what was granted.
    pub fn settle_allowance(&mut self, handle: &str, result: serde_json::Value) {
        if let Some(r) = self.records.iter_mut().find(|r| r.handle == handle) {
            r.result = Some(result);
            r.state = State::Settled("approved");
        }
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
            .filter(|r| role != Role::Custodian || matches!(r.kind, Kind::Open(_)))
            .map(|r| Summary {
                seed: Self::seed_of(r, signers, wallets),
                handle: r.handle.clone(),
                requester: r.requester.clone(),
                kind: match r.kind {
                    Kind::Open(_) => "open",
                    Kind::Allowance(_) => "allowance",
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
                Kind::Allowance(_) => "allowance",
            },
            bundle_id: hex::encode(r.bundle_id),
            lines: r.lines.clone(),
            asked: match &r.kind {
                Kind::Open(p) => serde_json::json!({ "group": p.group, "family": p.family, "network": p.network, "seed": p.seed }),
                Kind::Allowance(g) => serde_json::json!({ "grant": g }),
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
        let result = serde_json::json!({
            "group": group, "family": found.account.family, "chain": acct.chain.as_str(), "network": p.network,
            "external": acct.descriptor(0), "internal": acct.descriptor(1),
            "fingerprint": acct.fingerprint.to_string(), "seed": seed,
        });
        let requester = r.requester.clone();
        self.grants.retain(|(m, g)| !(m == &requester && g == &group));
        self.grants.push((requester, group));
        let r = &mut self.records[idx];
        r.result = Some(result);
        r.state = State::Settled("approved");
        Ok(())
    }

    /// The person decided in the keys app: the wallet and its password.
    pub fn approve(
        &mut self,
        signers: &mut Registry,
        keys: &mut dyn KeyHolder,
        handle: &str,
        bundle_id_echo: &str,
        decision: Decision,
        gate: &Gate,
    ) -> Result<()> {
        if gate.role == Role::Approver {
            return Err(ManagerError::Refused("not authorized".into()));
        }
        let idx = self.shown(handle, bundle_id_echo, gate)?;
        let r = &self.records[idx];
        let requester = r.requester.clone();
        let password = Zeroizing::new(decision.password);
        let Kind::Open(p) = &r.kind else { return Err(ManagerError::Refused("not authorized".into())) };
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
        // A device account's database key has a vault of its own.
        let database_key = if found.name != KEYSTORE {
            let (signer, account) = database_holder(signers, keys, &found)?;
            keys.device_database_key(&signer, &account, &password)?
        } else {
            keys.database_key(&group, Some(&password))?
        };
        let result = serde_json::json!({
            "group": group, "family": found.account.family, "chain": acct.chain.as_str(), "network": p.network,
            "external": acct.descriptor(0), "internal": acct.descriptor(1),
            "fingerprint": acct.fingerprint.to_string(), "databaseKey": database_key.as_str(),
        });
        self.grants.retain(|(m, g)| !(m == &requester && g == &group));
        self.grants.push((requester, group));
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

    /// The open's descriptors and database key, or the allowance granted. Repeatable until acked.
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

    /// Close a wallet for a module.
    pub fn close(&mut self, module: &str, group: &str) -> bool {
        let before = self.grants.len();
        self.grants.retain(|(m, g)| !(m == module && g == group.trim()));
        self.grants.len() != before
    }

    pub fn open_accounts(&self) -> Vec<(String, String)> {
        self.grants.clone()
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

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use logos_signer_interface::mock::{MockOptions, MockSigner};

    /// The keystore's extras, in memory: password "pw", a fixed database key, held keys by account.
    #[derive(Default)]
    pub(crate) struct FakeKeys {
        pub held: Vec<String>,
        /// Device wallets by signer and account: their password and key.
        pub devices: std::collections::HashMap<(String, String), (String, String)>,
    }

    impl KeyHolder for FakeKeys {
        fn database_key(&mut self, _: &str, password: Option<&str>) -> Result<Zeroizing<String>> {
            match password {
                Some("pw") => Ok(Zeroizing::new("ab".repeat(32))),
                _ => Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this account is not correct",
                ))),
            }
        }
        fn device_database_key(&mut self, signer: &str, account: &str, password: &str) -> Result<Zeroizing<String>> {
            let n = self.devices.len() + 1;
            let (pw, key) = self
                .devices
                .entry((signer.into(), account.into()))
                .or_insert_with(|| (password.into(), format!("{n:02x}").repeat(32)));
            if pw != password {
                return Err(ManagerError::Signer(logos_signer_interface::SignerError::new(
                    logos_signer_interface::ErrorCode::WrongSecret,
                    "the password for this wallet's database key is not correct",
                )));
            }
            Ok(Zeroizing::new(key.clone()))
        }
        fn device_wallets(&mut self) -> Result<Vec<(String, String)>> {
            Ok(self.devices.keys().cloned().collect())
        }
        fn hold_key(&mut self, account: &str, password: &str) -> Result<()> {
            self.database_key(account, Some(password))?;
            self.held.push(account.to_ascii_lowercase());
            Ok(())
        }
        fn release_key(&mut self, account: Option<&str>) -> Result<usize> {
            let before = self.held.len();
            match account {
                Some(a) => self.held.retain(|h| *h != a.to_ascii_lowercase()),
                None => self.held.clear(),
            }
            Ok(before - self.held.len())
        }
        fn held_keys(&mut self) -> Result<Vec<String>> {
            Ok(self.held.clone())
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
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw"), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["network"], "regtest");
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw"), &KEYS).unwrap();
        assert!(a.fetch(&h, &r).unwrap()["network"].is_null(), "named nothing, echoes nothing");
    }

    fn decide(group: Option<&str>, password: &str) -> Decision {
        Decision { group: group.map(str::to_string), password: password.into() }
    }

    /// A device's module offering the mock's accounts, and no keystore.
    fn device_fixture() -> (Registry, FakeKeys, Access) {
        let mut r = Registry::new();
        r.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        (r, FakeKeys::default(), Access::new())
    }

    #[test]
    fn a_device_wallet_opens_with_a_password_set_at_its_first_open_and_takes_no_allowance() {
        let (mut s, mut k, mut a) = device_fixture();
        let ask = r#"{"group":"mock-segwit","network":"regtest"}"#;
        let open = |a: &mut Access, s: &mut Registry| {
            let (h, r) = a.request_open(s, &Unlock::in_memory(), "bitcoin_wallet_core_module", ask).unwrap();
            let bundle = a.acknowledge(s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
            (h, r, bundle)
        };
        let (h, r, b) = open(&mut a, &mut s);
        a.approve(&mut s, &mut k, &h, &b, decide(None, "data-pw"), &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert!(k.devices.contains_key(&("keycard_shell_module".to_string(), "mock-segwit".to_string())));
        let first = got["databaseKey"].as_str().unwrap().to_string();

        // Opened again: the same key, behind the password set the first time.
        let (h, r, b) = open(&mut a, &mut s);
        assert!(a.approve(&mut s, &mut k, &h, &b, decide(None, "nope"), &KEYS).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &b, decide(None, "data-pw"), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some(first.as_str()));

        // And an allowance is refused before anything is shown.
        assert!(a.request_allowance(&mut s, "bitcoin_wallet_core_module", SPEND).is_err());
    }

    #[test]
    fn a_device_wallet_keeps_its_database_key_whichever_transport_opens_it() {
        let mut s = Registry::new();
        s.add("keycard_module", Box::new(MockSigner::new(MockOptions::default())));
        s.add("keycard_shell_module", Box::new(MockSigner::new(MockOptions::default())));
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        // First opened through the Shell; now the card is in a reader, which is preferred.
        let shell = ("keycard_shell_module".to_string(), "mock-segwit".to_string());
        k.devices.insert(shell.clone(), ("data-pw".into(), "cd".repeat(32)));
        assert_eq!(s.find("mock-segwit").unwrap().name, "keycard_module");
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"group":"mock-segwit"}"#).unwrap();
        let bundle = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
        a.approve(&mut s, &mut k, &h, &bundle, decide(None, "data-pw"), &KEYS).unwrap();
        assert_eq!(a.fetch(&h, &r).unwrap()["databaseKey"].as_str(), Some("cd".repeat(32).as_str()));
        assert_eq!(k.devices.keys().collect::<Vec<_>>(), vec![&shell], "no second key, no second database");
    }

    #[test]
    fn an_older_keys_apps_birthday_still_approves_and_goes_nowhere() {
        let (mut s, mut k, mut a) = device_fixture();
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", OPEN).unwrap();
        let bundle = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap().bundle_id;
        let sent = format!(r#"{{"handle":"{h}","bundle_id":"{bundle}","password":"data-pw","birthday":"2021-11-14"}}"#);
        let p: ApproveParams = serde_json::from_str(&sent).unwrap();
        let d = Decision { group: p.group, password: p.password.unwrap() };
        a.approve(&mut s, &mut k, &p.handle, &p.bundle_id, d, &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert!(got.get("birthday").is_none() && got.get("origin").is_none(), "{got}");
        assert!(got["databaseKey"].is_string());
        let unknown = r#"{"handle":"h","bundle_id":"b","origin":"restored"}"#;
        assert!(serde_json::from_str::<ApproveParams>(unknown).is_err(), "only the field older apps sent");
    }

    #[test]
    fn an_open_request_gives_the_requester_its_wallet_and_nobody_else_its_descriptors() {
        let (mut s, mut k, mut a) = fixture();
        let (h, r) = a.request_open(&mut s, &Unlock::in_memory(), "bitcoin_wallet_core_module", r#"{"family":"bitcoin","network":"signet"}"#).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &KEYS).unwrap();
        assert!(shown.lines.join("\n").contains("Any native segwit wallet on signet"), "{:?}", shown.lines);
        assert_eq!(shown.asked, serde_json::json!({ "group": null, "family": "bitcoin", "network": "signet", "seed": null }));
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw"), &KEYS).is_err(), "no wallet picked");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-taproot"), "pw"), &KEYS).is_err(), "wrong family");
        assert!(a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "nope"), &KEYS).is_err());
        assert_eq!(a.status(&h, &r).unwrap().0, "rendered", "a wrong password leaves it on screen");
        a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(Some("mock-segwit"), "pw"), &KEYS).unwrap();
        let got = a.fetch(&h, &r).unwrap();
        assert_eq!(got["group"], "mock-segwit");
        assert_eq!((got["chain"].as_str(), got["network"].as_str()), (Some("test"), Some("signet")));
        assert_eq!(got["databaseKey"], "ab".repeat(32));
        assert!(got["external"].as_str().unwrap().starts_with("wpkh(["));
        let (ext, _) = a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").unwrap();
        assert_eq!(ext, got["external"].as_str().unwrap());
        assert!(a.descriptors(&mut s, "someone_else", "mock-segwit").is_err());
        a.ack(&h, &r).unwrap();
        assert!(a.fetch(&h, &r).is_err());
        assert!(a.close("bitcoin_wallet_core_module", "mock-segwit"));
        assert!(a.descriptors(&mut s, "bitcoin_wallet_core_module", "mock-segwit").is_err());
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
        let seed = w.enroll(holder, Some(&key), "Card", crate::unlock::About::default()).unwrap().seed;
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
    fn the_first_app_to_show_an_open_keeps_it_and_an_approver_gives_consent_with_no_password() {
        let (mut s, mut w, seed, key) = enrolled();
        unlock(&mut w, &seed, &key);
        let (mut k, mut a) = (FakeKeys::default(), Access::new());
        let (h, _) = a.request_open(&mut s, &w, "bitcoin_wallet_core_module", OPEN).unwrap();
        let shown = a.acknowledge(&mut s, &w, &h, &SIGNER).unwrap();
        assert!(matches!(a.acknowledge(&mut s, &w, &h, &KEYS), Err(ManagerError::Refused(_))), "the Signer app's now");
        assert!(a.reject(&h, &KEYS).is_err());
        let custodian_way = a.approve(&mut s, &mut k, &h, &shown.bundle_id, decide(None, "pw"), &SIGNER);
        assert!(matches!(custodian_way, Err(ManagerError::Refused(_))), "an approver gives consent, no password");
        a.reject(&h, &SIGNER).unwrap();
    }

    /// A keystore that can keep a key ready, as the real one says it can.
    fn holding() -> (Registry, Access) {
        let mut r = Registry::new();
        r.add("keystore_module", Box::new(MockSigner::new(MockOptions { holds_key: true, ..Default::default() })));
        (r, Access::new())
    }

    #[test]
    fn a_module_asks_for_its_own_allowance_and_only_an_approver_sees_it() {
        let (mut s, mut a) = holding();
        let w = Unlock::in_memory();
        let (h, r) = a.request_allowance(&mut s, "maker", SPEND).unwrap();
        assert!(a.queue(&mut s, &w, Role::Custodian).iter().all(|q| q.handle != h), "not the keys app's to grant");
        assert_eq!(a.queue(&mut s, &w, Role::Approver)[0].kind, "allowance");
        assert!(matches!(a.acknowledge(&mut s, &w, &h, &KEYS), Err(ManagerError::Refused(_))));

        let shown = a.acknowledge(&mut s, &w, &h, &SIGNER).unwrap();
        assert!(shown.lines[0].starts_with("maker asks for an allowance"), "{:?}", shown.lines);
        assert!(shown.lines.iter().any(|l| l == "For maker"), "{:?}", shown.lines);
        assert!(shown.lines.iter().any(|l| l == "At most 1000 sats per signature"), "{:?}", shown.lines);
        assert_eq!(shown.asked["grant"]["scope"], serde_json::json!({ "kind": "spend", "network": "regtest" }));

        let asked = a.allowance_shown(&h, &shown.bundle_id, &SIGNER).unwrap();
        assert!(a.allowance_shown(&h, "00", &SIGNER).is_err(), "not what was shown");
        assert_eq!(asked.callers, vec![Caller { module: "maker".into(), on_behalf_of: None }]);
        a.settle_allowance(&h, serde_json::json!({ "id": "alw_1" }));
        assert_eq!(a.status(&h, &r).unwrap(), ("settled", Some("approved")));
        assert_eq!(a.fetch(&h, &r).unwrap()["id"], "alw_1");
    }

    #[test]
    fn a_module_behind_another_is_named_through_it_and_cannot_name_anyone_else() {
        let (mut s, mut a) = holding();
        let ask = r#"{"account":"mock-segwit","scope":{"kind":"spend","network":"regtest"},"via":"bitcoin_wallet_core_module"}"#;
        let (h, _) = a.request_allowance(&mut s, "maker", ask).unwrap();
        let shown = a.acknowledge(&mut s, &Unlock::in_memory(), &h, &SIGNER).unwrap();
        let asked = a.allowance_shown(&h, &shown.bundle_id, &SIGNER).unwrap();
        let through = Caller { module: "bitcoin_wallet_core_module".into(), on_behalf_of: Some("maker".into()) };
        assert_eq!(asked.callers, vec![through]);
        let naming = r#"{"account":"mock-segwit","scope":{"kind":"spend","network":"regtest"},"callers":[{"module":"x"}]}"#;
        assert!(a.request_allowance(&mut s, "maker", naming).is_err());
    }

    #[test]
    fn only_a_signer_that_holds_keys_takes_an_allowance_and_on_its_own_chain() {
        let (mut s, _, mut a) = fixture();
        assert!(a.request_allowance(&mut s, "maker", SPEND).unwrap_err().to_string().contains("each signature"));
        let (mut s, mut a) = holding();
        let mainnet = r#"{"account":"mock-segwit","scope":{"kind":"spend","network":"bitcoin"}}"#;
        assert!(a.request_allowance(&mut s, "maker", mainnet).is_err(), "a test wallet on mainnet");
        let evm = r#"{"account":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","scope":{"kind":"spend","network":"regtest"}}"#;
        assert!(a.request_allowance(&mut s, "maker", evm).is_err(), "no Bitcoin to spend");
        let reviewed = r#"{"account":"0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266","scope":{"kind":"all"},"review":true}"#;
        assert!(a.request_allowance(&mut s, "maker", reviewed).is_ok(), "review covers an EVM account");
    }

    const OPEN: &str = r#"{"group":"mock-segwit","network":"regtest"}"#;
    const SPEND: &str = r#"{"account":"mock-segwit","scope":{"kind":"spend","network":"regtest"},"limits":{"perRequest":"1000"}}"#;
}
