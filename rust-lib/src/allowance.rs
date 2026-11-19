//! Standing permissions: which callers an account signs for without its password, and on what terms.
//! An allowance only ever removes a prompt. What none covers goes to a person, as any request does.

use std::collections::BTreeSet;
use std::path::PathBuf;

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::btc::{self, AccountPublic};
use crate::error::{bad, ManagerError, Result};
use crate::evm::check_displayable;
use crate::registry::Registry;
use crate::roster::KEYSTORE;
use crate::unlock::{seal, unseal, write_private, Key};

const FILE: &str = "allowances.sealed";
const AAD: &[u8] = b"allowances";
pub const MAX_ALLOWANCES: usize = 64;
/// Spends remembered for a rolling period. Past this the oldest merge forward, which only overcounts.
const MAX_WINDOW: usize = 512;

mod amount {
    use serde::de::Error;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u128, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u128, D::Error> {
        String::deserialize(d)?.trim().parse().map_err(D::Error::custom)
    }

    pub mod opt {
        use super::*;

        pub fn serialize<S: Serializer>(v: &Option<u128>, s: S) -> Result<S::Ok, S::Error> {
            match v {
                Some(n) => s.serialize_str(&n.to_string()),
                None => s.serialize_none(),
            }
        }

        pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u128>, D::Error> {
            match Option::<String>::deserialize(d)? {
                Some(t) => t.trim().parse().map(Some).map_err(D::Error::custom),
                None => Ok(None),
            }
        }
    }
}

/// Who an allowance is for. `for` names the module behind an intermediary, as that module reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Caller {
    pub module: String,
    #[serde(default, rename = "for", skip_serializing_if = "Option::is_none")]
    pub on_behalf_of: Option<String>,
}

impl Caller {
    fn matches(&self, requester: &str, on_behalf: Option<&str>) -> bool {
        self.module == "*"
            || (self.module == requester && self.on_behalf_of.as_deref().is_none_or(|f| Some(f) == on_behalf))
    }

    fn describe(&self) -> String {
        match (self.module.as_str(), &self.on_behalf_of) {
            ("*", _) => "any app".into(),
            (m, Some(f)) => format!("{f} through {m}"),
            (m, None) => m.to_string(),
        }
    }
}

/// What an allowance covers. Each scope has at most one allowance per account and caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Scope {
    /// Bitcoin leaving the account on one network, fee included.
    Spend { network: String },
    /// Every kind of request, each shown to a person.
    All,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Period {
    #[serde(with = "amount")]
    pub amount: u128,
    pub ms: u64,
}

/// Every limit is optional, and one left out doesn't limit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Limits {
    #[serde(default, skip_serializing_if = "Option::is_none", with = "amount::opt")]
    pub per_request: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "amount::opt")]
    pub total: Option<u128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub per_period: Option<Period>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<u64>,
    /// Where it may pay. Absent pays anywhere; empty pays nowhere but back to the wallet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destinations: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "amount::opt")]
    pub max_fee: Option<u128>,
}

fn period(ms: u64) -> String {
    match ms / 1000 {
        s @ 0..=119 => format!("{s} seconds"),
        s @ 120..=7199 => format!("{} minutes", s / 60),
        s @ 7200..=172_799 => format!("{} hours", s / 3600),
        s => format!("{} days", s / 86_400),
    }
}

/// `2026-11-18 14:03 UTC`, from days since 1970 by Howard Hinnant's civil calendar.
fn utc(ms: u64) -> String {
    let (days, secs) = ((ms / 86_400_000) as i64, ms / 1000 % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year}-{month:02}-{day:02} {:02}:{:02} UTC", secs / 3600, secs / 60 % 60)
}

/// What a person grants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub account: String,
    pub callers: Vec<Caller>,
    pub scope: Scope,
    /// Each signature is shown to a person, who confirms it with no password.
    #[serde(default)]
    pub review: bool,
    #[serde(default)]
    pub ends_at_restart: bool,
    #[serde(default)]
    pub limits: Limits,
}

impl Grant {
    pub fn check(&self) -> Result<()> {
        if self.callers.is_empty() {
            return Err(bad("allowance: name the apps it is for"));
        }
        for c in &self.callers {
            check_displayable(&c.module, "app")?;
            if c.module.trim().is_empty() {
                return Err(bad("allowance: name the apps it is for"));
            }
            if let Some(f) = &c.on_behalf_of {
                check_displayable(f, "app")?;
            }
            if c.module == "*" && (!self.review || c.on_behalf_of.is_some()) {
                return Err(bad("allowance: signing without review must name the apps it covers"));
            }
        }
        let l = &self.limits;
        match &self.scope {
            Scope::Spend { network } => check_displayable(network, "network")?,
            Scope::All => {
                if !self.review {
                    return Err(bad("allowance: only a reviewed allowance can cover every request"));
                }
                if l.per_request.is_some() || l.total.is_some() || l.per_period.is_some() || l.destinations.is_some() || l.max_fee.is_some() {
                    return Err(bad("allowance: amounts apply to spending, not to every request"));
                }
            }
        }
        let nothing = l.per_request == Some(0)
            || l.total == Some(0)
            || l.count == Some(0)
            || l.max_fee == Some(0)
            || l.per_period.as_ref().is_some_and(|p| p.amount == 0 || p.ms == 0);
        if nothing {
            return Err(bad("allowance: limits that allow nothing"));
        }
        for d in l.destinations.iter().flatten() {
            check_displayable(d, "destination")?;
        }
        Ok(())
    }

    /// The manager's own words for it, as a person is shown them.
    pub fn describe(&self) -> Vec<String> {
        let callers: Vec<_> = self.callers.iter().map(Caller::describe).collect();
        let mut out = vec![format!("For {}", callers.join(", "))];
        out.push(match &self.scope {
            Scope::Spend { network } => format!("Spend Bitcoin on {network}"),
            Scope::All => "Every kind of request".to_string(),
        });
        out.push(if self.review { "Each signature is shown to you, with no password" } else { "Signed WITHOUT showing you each one" }.into());
        let l = &self.limits;
        if let Some(n) = l.per_request {
            out.push(format!("At most {n} sats per signature"));
        }
        if let Some(n) = l.total {
            out.push(format!("At most {n} sats in all"));
        }
        if let Some(p) = &l.per_period {
            out.push(format!("At most {} sats every {}", p.amount, period(p.ms)));
        }
        if let Some(n) = l.max_fee {
            out.push(format!("Fee of at most {n} sats"));
        }
        if let Some(n) = l.count {
            out.push(format!("At most {n} signature{}", if n == 1 { "" } else { "s" }));
        }
        match &l.destinations {
            Some(list) if list.is_empty() => out.push("Pays only back to this wallet".into()),
            Some(list) => out.push(format!("Pays only {}", list.join(", "))),
            None => {}
        }
        if let Some(t) = l.expires_at_ms {
            out.push(format!("Until {}", utc(t)));
        }
        if self.ends_at_restart {
            out.push("Ends when the app restarts".into());
        }
        out
    }

    /// Is `decided` this request, or tighter? A person may narrow what an app asked for, never widen it.
    pub fn narrowed_by(&self, decided: &Grant) -> bool {
        fn within<T: PartialOrd + Copy>(asked: Option<T>, decided: Option<T>) -> bool {
            match (asked, decided) {
                (Some(a), Some(d)) => d <= a,
                (Some(_), None) => false,
                (None, _) => true,
            }
        }
        let (a, d) = (&self.limits, &decided.limits);
        let period = match (&a.per_period, &d.per_period) {
            (Some(x), Some(y)) => y.amount <= x.amount && y.ms >= x.ms,
            (Some(_), None) => false,
            (None, _) => true,
        };
        let places = match (&a.destinations, &d.destinations) {
            (Some(x), Some(y)) => y.iter().all(|p| x.contains(p)),
            (Some(_), None) => false,
            (None, _) => true,
        };
        self.account == decided.account
            && self.callers == decided.callers
            && self.scope == decided.scope
            && (decided.review || !self.review)
            && (decided.ends_at_restart || !self.ends_at_restart)
            && within(a.per_request, d.per_request)
            && within(a.total, d.total)
            && within(a.max_fee, d.max_fee)
            && within(a.count, d.count)
            && within(a.expires_at_ms, d.expires_at_ms)
            && period
            && places
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Used {
    #[serde(with = "amount")]
    pub spent: u128,
    pub count: u32,
    /// `(at_ms, amount)` of each charge a rolling period still counts.
    #[serde(default)]
    pub window: Vec<(u64, String)>,
}

impl Used {
    fn in_period(&self, ms: u64, now: u64) -> u128 {
        let since = now.saturating_sub(ms);
        self.window.iter().filter(|(at, _)| *at > since).filter_map(|(_, n)| n.parse::<u128>().ok()).sum()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Allowance {
    pub id: String,
    /// Moves with every charge, so a replacement can say which state a person saw.
    pub version: u64,
    pub grant: Grant,
    #[serde(default)]
    pub used: Used,
}

impl Allowance {
    /// Past its date, or with nothing left of its count or total.
    pub fn ended(&self, now: u64) -> bool {
        let l = &self.grant.limits;
        l.expires_at_ms.is_some_and(|t| now >= t) || l.count.is_some_and(|n| self.used.count >= n) || l.total.is_some_and(|n| self.used.spent >= n)
    }

    fn check(&self, asked: &Asked, now: u64) -> std::result::Result<(), String> {
        let l = &self.grant.limits;
        if l.expires_at_ms.is_some_and(|t| now >= t) {
            return Err("This app's allowance has expired".into());
        }
        if let Some(n) = l.count.filter(|n| self.used.count >= *n) {
            return Err(format!("This app has used all {n} signatures of its allowance"));
        }
        let Some(spend) = &asked.spend else { return Ok(()) };
        let sat = u128::from(spend.sat);
        if let Some(n) = l.per_request.filter(|n| sat > *n) {
            return Err(format!("This spends {sat} sats, over this app's limit of {n} per signature"));
        }
        if let Some(n) = l.total {
            let left = n.saturating_sub(self.used.spent);
            if sat > left {
                return Err(format!("This spends {sat} sats, and this app has {left} left of its allowance"));
            }
        }
        if let Some(p) = &l.per_period {
            let left = p.amount.saturating_sub(self.used.in_period(p.ms, now));
            if sat > left {
                return Err(format!("This spends {sat} sats, and this app has {left} left for this period"));
            }
        }
        if let Some(n) = l.max_fee.filter(|n| u128::from(spend.fee_sat) > *n) {
            return Err(format!("This pays a fee of {} sats, over this app's limit of {n}", spend.fee_sat));
        }
        if let Some(list) = &l.destinations {
            if let Some(other) = spend.destinations.iter().find(|d| !list.contains(d)) {
                return Err(format!("This pays {other}, which this app's allowance doesn't name"));
            }
        }
        Ok(())
    }

    /// How an app and a person read it: what it is, what is left, and how it stands.
    pub fn view(&self, held: bool, now: u64) -> Value {
        let l = &self.grant.limits;
        let state = if self.ended(now) {
            "ended"
        } else if held {
            "active"
        } else {
            "waiting"
        };
        let period_spent = l.per_period.as_ref().map(|p| self.used.in_period(p.ms, now).to_string());
        json!({
            "id": self.id, "version": self.version, "account": self.grant.account, "callers": self.grant.callers,
            "scope": self.grant.scope, "review": self.grant.review, "endsAtRestart": self.grant.ends_at_restart,
            "limits": l, "lines": self.grant.describe(), "state": state,
            "used": { "spent": self.used.spent.to_string(), "count": self.used.count, "periodSpent": period_spent },
        })
    }
}

/// Ties a grant to the keystore's copy of its account, the one signer here that can keep a key
/// ready, and says what the account is called.
pub fn bind(grant: &mut Grant, signers: &mut Registry) -> Result<String> {
    grant.check()?;
    let found = signers
        .holders(&grant.account)?
        .into_iter()
        .find(|f| f.name == KEYSTORE && f.info.holds_key)
        .ok_or_else(|| bad("allowance: this account's signer needs a person for each signature"))?;
    if let Scope::Spend { network } = &mut grant.scope {
        let acct = AccountPublic::from_account(&found.account).map_err(|_| bad("allowance: spending is for Bitcoin wallets"))?;
        *network = btc::network_name(acct.chain.network(network)?).to_string();
    }
    grant.account = found.account.id.clone();
    Ok(found.account.label.clone().unwrap_or_else(|| found.account.id.clone()))
}

/// A Bitcoin request as the manager read it from its PSBT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcSpend {
    pub network: String,
    pub sat: u64,
    pub fee_sat: u64,
    pub txid: String,
    pub destinations: Vec<String>,
}

/// What an allowance is decided on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    pub account: String,
    pub requester: String,
    pub on_behalf: Option<String>,
    /// A bare digest: nobody can read what it signs, so only the password covers it.
    pub digest: bool,
    pub spend: Option<BtcSpend>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Unattended(String),
    Review(String),
    /// A person decides, with the password; the words say why when an allowance came close.
    Person(Option<String>),
}

/// What a charge took, to give back if nothing was signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Charge {
    pub id: String,
    pub amount: u128,
    pub at: u64,
}

/// `{ id, version }`: the allowance a grant replaces, as the person saw it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replaces {
    pub id: String,
    pub version: u64,
}

#[derive(Serialize, Deserialize)]
struct Stored {
    allowances: Vec<Allowance>,
}

#[derive(Default)]
pub struct Allowances {
    list: Vec<Allowance>,
    /// Accounts whose key the keystore keeps ready for this run.
    held: BTreeSet<String>,
    dir: Option<PathBuf>,
    opened: bool,
    /// A change still to be written, for when a wallet is open.
    dirty: bool,
    /// The sealed file didn't open: nothing replaces it until it does.
    unreadable: bool,
}

fn lower(id: &str) -> String {
    id.trim().to_ascii_lowercase()
}

impl Allowances {
    pub fn load(dir: PathBuf) -> Self {
        Allowances { dir: Some(dir), ..Default::default() }
    }

    /// Reads what was kept, once a wallet is unlocked and its key is at hand.
    pub fn open(&mut self, key: &Key) {
        if self.opened {
            return;
        }
        let Some(dir) = &self.dir else { return };
        self.opened = true;
        let Ok(text) = std::fs::read_to_string(dir.join(FILE)) else { return };
        let stored = unseal(key, text.trim(), AAD).and_then(|plain| serde_json::from_slice::<Stored>(&plain).ok());
        match stored {
            Some(s) => {
                let known: BTreeSet<String> = self.list.iter().map(|a| a.id.clone()).collect();
                self.list.extend(s.allowances.into_iter().filter(|a| !known.contains(&a.id)));
            }
            None => self.unreadable = true,
        }
    }

    pub fn unreadable(&self) -> bool {
        self.unreadable
    }

    /// On disk when it returns. One that ends at restart is never written.
    pub fn save(&self, key: &Key) -> Result<()> {
        let io = |e: std::io::Error| ManagerError::Signing(format!("keeping the allowances: {e}"));
        if self.unreadable {
            return Err(ManagerError::Signing("the kept allowances can't be read".into()));
        }
        let Some(dir) = &self.dir else { return Err(ManagerError::Signing("the module has not started yet".into())) };
        let kept: Vec<Allowance> = self.list.iter().filter(|a| !a.grant.ends_at_restart).cloned().collect();
        let plain = serde_json::to_vec(&Stored { allowances: kept }).map_err(|e| ManagerError::Signing(e.to_string()))?;
        std::fs::create_dir_all(dir).map_err(io)?;
        write_private(dir, FILE, seal(key, &plain, AAD).as_bytes()).map_err(io)
    }

    pub fn list(&self) -> &[Allowance] {
        &self.list
    }

    /// Back to a list taken before a change that couldn't be kept.
    pub fn restore(&mut self, list: Vec<Allowance>) {
        self.list = list;
    }

    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    pub fn take_dirty(&mut self) -> bool {
        std::mem::take(&mut self.dirty)
    }

    pub fn get(&self, id: &str) -> Option<&Allowance> {
        self.list.iter().find(|a| a.id == id)
    }

    pub fn is_held(&self, account: &str) -> bool {
        self.held.contains(&lower(account))
    }

    pub fn set_held(&mut self, account: &str) {
        self.held.insert(lower(account));
    }

    /// The keystore let go of this account's key.
    pub fn drop_held(&mut self, account: &str) {
        self.held.remove(&lower(account));
    }

    /// Keeps only the accounts the keystore says it still holds.
    pub fn retain_held(&mut self, held: &[String]) {
        let now: BTreeSet<String> = held.iter().map(|a| lower(a)).collect();
        self.held.retain(|a| now.contains(a));
    }

    /// Held keys no allowance needs any more: the caller has the keystore let go of them.
    pub fn unneeded(&mut self, now: u64) -> Vec<String> {
        let live: BTreeSet<String> = self.list.iter().filter(|a| !a.ended(now)).map(|a| lower(&a.grant.account)).collect();
        let gone: Vec<String> = self.held.iter().filter(|a| !live.contains(*a)).cloned().collect();
        self.held.retain(|a| live.contains(a));
        gone
    }

    fn applies(a: &Allowance, asked: &Asked) -> bool {
        let scope = match (&a.grant.scope, &asked.spend) {
            (Scope::All, _) => true,
            (Scope::Spend { network }, Some(s)) => network.trim().eq_ignore_ascii_case(s.network.trim()),
            (Scope::Spend { .. }, None) => false,
        };
        scope
            && lower(&a.grant.account) == lower(&asked.account)
            && a.grant.callers.iter().any(|c| c.matches(&asked.requester, asked.on_behalf.as_deref()))
    }

    /// The closest fit first: a named scope, then a caller named through its intermediary.
    fn rank(a: &Allowance, asked: &Asked) -> u8 {
        let general = u8::from(a.grant.scope == Scope::All);
        let exact = a.grant.callers.iter().any(|c| {
            c.module == asked.requester && c.on_behalf_of.is_some() && c.on_behalf_of == asked.on_behalf
        });
        general * 2 + u8::from(!exact)
    }

    /// Without review first, so a request over that limit can still be reviewed.
    pub fn decide(&self, asked: &Asked, now: u64) -> Verdict {
        if asked.digest {
            return Verdict::Person(None);
        }
        let mut why = None;
        for review in [false, true] {
            let mut fits: Vec<&Allowance> =
                self.list.iter().filter(|a| a.grant.review == review && Self::applies(a, asked)).collect();
            fits.sort_by_key(|a| Self::rank(a, asked));
            for a in fits {
                match a.check(asked, now) {
                    Ok(()) if !self.is_held(&a.grant.account) => {
                        why.get_or_insert_with(|| "This app's allowance is waiting for the wallet's password".to_string());
                    }
                    Ok(()) if review => return Verdict::Review(a.id.clone()),
                    Ok(()) => return Verdict::Unattended(a.id.clone()),
                    Err(e) => {
                        why.get_or_insert(e);
                    }
                }
            }
        }
        Verdict::Person(why)
    }

    /// A new allowance, or the one it replaces with its use cleared, as ERC-20's `approve` does.
    pub fn grant(&mut self, grant: Grant, replaces: Option<&Replaces>, now: u64) -> Result<Allowance> {
        grant.check()?;
        let account = lower(&grant.account);
        let old = match replaces {
            Some(r) => {
                let at = self.list.iter().position(|a| a.id == r.id).ok_or_else(|| ManagerError::NotFound(r.id.clone()))?;
                if self.list[at].version != r.version {
                    return Err(ManagerError::Refused("This allowance was used after you saw it: review it again".into()));
                }
                if lower(&self.list[at].grant.account) != account {
                    return Err(bad("allowance: a replacement is for the same account"));
                }
                Some(at)
            }
            None => None,
        };
        let clash = self.list.iter().enumerate().any(|(i, a)| {
            Some(i) != old
                && !a.ended(now)
                && lower(&a.grant.account) == account
                && a.grant.scope == grant.scope
                && a.grant.callers.iter().any(|c| grant.callers.contains(c))
        });
        if clash {
            return Err(bad("allowance: this app already has one for this account: change that one"));
        }
        if old.is_none() && self.list.len() >= MAX_ALLOWANCES {
            return Err(bad("allowance: too many allowances"));
        }
        let mut id = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut id);
        let made = Allowance { id: format!("alw_{}", hex::encode(id)), version: 1, grant, used: Used::default() };
        match old {
            Some(at) => self.list[at] = made.clone(),
            None => self.list.push(made.clone()),
        }
        Ok(made)
    }

    pub fn revoke(&mut self, id: &str) -> Option<Allowance> {
        let at = self.list.iter().position(|a| a.id == id)?;
        self.dirty = true;
        Some(self.list.remove(at))
    }

    /// Counts a signature against the allowance, before it is signed.
    pub fn charge(&mut self, id: &str, amount: u128, now: u64) -> Result<Charge> {
        let a = self.list.iter_mut().find(|a| a.id == id).ok_or_else(|| ManagerError::NotFound(id.to_string()))?;
        a.used.spent = a.used.spent.checked_add(amount).ok_or_else(|| bad("spending overflows"))?;
        a.used.count = a.used.count.saturating_add(1);
        a.version += 1;
        if let Some(p) = &a.grant.limits.per_period {
            let since = now.saturating_sub(p.ms);
            a.used.window.retain(|(at, _)| *at > since);
            a.used.window.push((now, amount.to_string()));
            while a.used.window.len() > MAX_WINDOW {
                let (_, first) = a.used.window.remove(0);
                let next = a.used.window[0].1.parse::<u128>().unwrap_or(0);
                a.used.window[0].1 = (first.parse::<u128>().unwrap_or(0) + next).to_string();
            }
        }
        Ok(Charge { id: id.to_string(), amount, at: now })
    }

    /// Nothing was signed after all.
    pub fn refund(&mut self, c: &Charge) {
        let Some(a) = self.list.iter_mut().find(|a| a.id == c.id) else { return };
        a.used.spent = a.used.spent.saturating_sub(c.amount);
        a.used.count = a.used.count.saturating_sub(1);
        a.version += 1;
        let text = c.amount.to_string();
        if let Some(at) = a.used.window.iter().rposition(|(at, n)| *at == c.at && *n == text) {
            a.used.window.remove(at);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const ACCOUNT: &str = "group-1";
    const CORE: &str = "bitcoin_wallet_core_module";

    fn caller(module: &str) -> Caller {
        Caller { module: module.into(), on_behalf_of: None }
    }

    fn spend_grant(limits: Limits) -> Grant {
        Grant {
            account: ACCOUNT.into(),
            callers: vec![caller(CORE)],
            scope: Scope::Spend { network: "regtest".into() },
            review: false,
            ends_at_restart: false,
            limits,
        }
    }

    fn review_all() -> Grant {
        Grant { callers: vec![caller("*")], scope: Scope::All, review: true, ..spend_grant(Limits::default()) }
    }

    fn asked(sat: u64) -> Asked {
        Asked {
            account: ACCOUNT.into(),
            requester: CORE.into(),
            on_behalf: None,
            digest: false,
            spend: Some(BtcSpend {
                network: "regtest".into(),
                sat,
                fee_sat: 100,
                txid: "ab".into(),
                destinations: vec!["bcrt1qdest".into()],
            }),
        }
    }

    fn held(grant: Grant) -> (Allowances, String) {
        let mut a = Allowances::default();
        a.set_held(ACCOUNT);
        let id = a.grant(grant, None, 0).unwrap().id;
        (a, id)
    }

    fn dir() -> PathBuf {
        let mut salt = [0u8; 8];
        rand::thread_rng().fill_bytes(&mut salt);
        let d = std::env::temp_dir().join(format!("signer-allowances-{}", hex::encode(salt)));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn key(b: u8) -> Key {
        Zeroizing::new([b; 32])
    }

    #[test]
    fn dates_read_as_a_person_writes_them() {
        assert_eq!(utc(0), "1970-01-01 00:00 UTC");
        assert_eq!(utc(1_795_010_580_000), "2026-11-18 14:03 UTC");
        assert_eq!(utc(1_709_164_800_000), "2024-02-29 00:00 UTC");
    }

    #[test]
    fn limits_left_out_do_not_limit_and_a_request_inside_them_signs_unattended() {
        let (a, id) = held(spend_grant(Limits::default()));
        assert_eq!(a.decide(&asked(u64::MAX), 1), Verdict::Unattended(id));
    }

    #[test]
    fn over_a_limit_goes_to_a_person_who_is_told_why() {
        let (mut a, id) = held(spend_grant(Limits { per_request: Some(1_000), total: Some(1_500), ..Limits::default() }));
        let Verdict::Person(Some(why)) = a.decide(&asked(1_001), 1) else { panic!("over per signature") };
        assert!(why.contains("1001 sats") && why.contains("1000"), "{why}");

        a.charge(&id, 1_000, 1).unwrap();
        let Verdict::Person(Some(why)) = a.decide(&asked(501), 2) else { panic!("over the total") };
        assert!(why.contains("500 left"), "{why}");
        assert_eq!(a.decide(&asked(500), 2), Verdict::Unattended(id));
    }

    #[test]
    fn a_rolling_period_frees_up_as_it_passes() {
        let per_period = Some(Period { amount: 1_000, ms: 60_000 });
        let (mut a, id) = held(spend_grant(Limits { per_period, ..Limits::default() }));
        a.charge(&id, 900, 1_000).unwrap();
        assert!(matches!(a.decide(&asked(200), 2_000), Verdict::Person(Some(_))));
        assert_eq!(a.decide(&asked(200), 61_001), Verdict::Unattended(id));
    }

    #[test]
    fn count_expiry_fee_and_destinations_each_send_it_to_a_person() {
        let (mut a, id) = held(spend_grant(Limits { count: Some(1), ..Limits::default() }));
        a.charge(&id, 1, 1).unwrap();
        a.unneeded(2);
        let Verdict::Person(Some(why)) = a.decide(&asked(1), 2) else { panic!("used up") };
        assert!(why.contains("used all 1"), "the reason, not the released key: {why}");
        assert!(a.get(&id).unwrap().ended(2));

        let (a, _) = held(spend_grant(Limits { expires_at_ms: Some(10), ..Limits::default() }));
        assert!(matches!(a.decide(&asked(1), 10), Verdict::Person(Some(_))));

        let (a, _) = held(spend_grant(Limits { max_fee: Some(99), ..Limits::default() }));
        assert!(matches!(a.decide(&asked(1), 1), Verdict::Person(Some(_))));

        let (a, id) = held(spend_grant(Limits { destinations: Some(vec!["bcrt1qdest".into()]), ..Limits::default() }));
        assert_eq!(a.decide(&asked(1), 1), Verdict::Unattended(id));
        let (a, _) = held(spend_grant(Limits { destinations: Some(vec![]), ..Limits::default() }));
        assert!(matches!(a.decide(&asked(1), 1), Verdict::Person(Some(_))), "empty pays nowhere");
    }

    #[test]
    fn only_the_named_caller_on_the_named_network_is_covered() {
        let (a, _) = held(spend_grant(Limits::default()));
        let other = Asked { requester: "other_module".into(), ..asked(1) };
        assert_eq!(a.decide(&other, 1), Verdict::Person(None));
        let mut wrong = asked(1);
        wrong.spend.as_mut().unwrap().network = "testnet".into();
        assert_eq!(a.decide(&wrong, 1), Verdict::Person(None));
        let elsewhere = Asked { account: "group-2".into(), ..asked(1) };
        assert_eq!(a.decide(&elsewhere, 1), Verdict::Person(None));
    }

    #[test]
    fn a_caller_behind_an_intermediary_counts_only_through_the_one_named() {
        let through = Caller { module: CORE.into(), on_behalf_of: Some("maker_bridge".into()) };
        let (a, id) = held(Grant { callers: vec![through], ..spend_grant(Limits::default()) });
        let vouched = Asked { on_behalf: Some("maker_bridge".into()), ..asked(1) };
        assert_eq!(a.decide(&vouched, 1), Verdict::Unattended(id));
        assert_eq!(a.decide(&asked(1), 1), Verdict::Person(None), "nobody vouched");
        let forged = Asked { requester: "other_module".into(), on_behalf: Some("maker_bridge".into()), ..asked(1) };
        assert_eq!(a.decide(&forged, 1), Verdict::Person(None), "only that intermediary's word counts");
    }

    #[test]
    fn over_the_unattended_limit_a_review_allowance_takes_it() {
        let (mut a, unattended) = held(spend_grant(Limits { per_request: Some(100), ..Limits::default() }));
        let review = a.grant(review_all(), None, 0).unwrap().id;
        assert_eq!(a.decide(&asked(100), 1), Verdict::Unattended(unattended));
        assert_eq!(a.decide(&asked(101), 1), Verdict::Review(review));
    }

    #[test]
    fn a_bare_digest_always_needs_the_password() {
        let (a, _) = held(review_all());
        let digest = Asked { digest: true, spend: None, ..asked(0) };
        assert_eq!(a.decide(&digest, 1), Verdict::Person(None));
    }

    #[test]
    fn a_review_allowance_covers_requests_with_no_spend_to_read() {
        let (a, id) = held(review_all());
        let evm = Asked { requester: "eth_wallet".into(), spend: None, ..asked(0) };
        assert_eq!(a.decide(&evm, 1), Verdict::Review(id));
    }

    #[test]
    fn without_its_key_held_an_allowance_covers_nothing_and_says_so() {
        let mut a = Allowances::default();
        a.grant(spend_grant(Limits::default()), None, 0).unwrap();
        let Verdict::Person(Some(why)) = a.decide(&asked(1), 1) else { panic!("waiting") };
        assert!(why.contains("password"), "{why}");
    }

    #[test]
    fn what_a_grant_may_not_say() {
        let refused = |g: Grant| Allowances::default().grant(g, None, 0).is_err();
        assert!(refused(Grant { callers: vec![], ..spend_grant(Limits::default()) }));
        assert!(refused(Grant { callers: vec![caller("*")], ..spend_grant(Limits::default()) }), "any app, unseen");
        assert!(refused(Grant { review: false, ..review_all() }), "everything, unseen");
        assert!(refused(Grant { limits: Limits { total: Some(5), ..Limits::default() }, ..review_all() }));
        assert!(refused(spend_grant(Limits { per_request: Some(0), ..Limits::default() })));
        assert!(refused(spend_grant(Limits { count: Some(0), ..Limits::default() })));
    }

    #[test]
    fn one_allowance_per_account_caller_and_scope_and_several_scopes_may_stand() {
        let (mut a, _) = held(spend_grant(Limits::default()));
        assert!(a.grant(spend_grant(Limits::default()), None, 0).is_err());
        let other_network = Grant { scope: Scope::Spend { network: "signet".into() }, ..spend_grant(Limits::default()) };
        a.grant(other_network, None, 0).unwrap();
        let other_caller = Grant { callers: vec![caller("other_module")], ..spend_grant(Limits::default()) };
        a.grant(other_caller, None, 0).unwrap();
    }

    #[test]
    fn callers_listed_together_share_one_budget() {
        let shared = Grant { callers: vec![caller(CORE), caller("other_module")], ..spend_grant(Limits { total: Some(100), ..Limits::default() }) };
        let (mut a, id) = held(shared);
        a.charge(&id, 100, 1).unwrap();
        let other = Asked { requester: "other_module".into(), ..asked(1) };
        assert!(matches!(a.decide(&other, 2), Verdict::Person(Some(_))));
    }

    #[test]
    fn replacing_clears_the_use_but_not_if_it_moved_after_the_person_saw_it() {
        let (mut a, id) = held(spend_grant(Limits { total: Some(100), ..Limits::default() }));
        let seen = a.get(&id).unwrap().version;
        a.charge(&id, 60, 1).unwrap();
        let stale = Replaces { id: id.clone(), version: seen };
        assert!(matches!(a.grant(spend_grant(Limits::default()), Some(&stale), 2), Err(ManagerError::Refused(_))));

        let fresh = Replaces { id: id.clone(), version: a.get(&id).unwrap().version };
        let made = a.grant(spend_grant(Limits { total: Some(50), ..Limits::default() }), Some(&fresh), 2).unwrap();
        assert_eq!((made.used.spent, a.list().len()), (0, 1));
        assert!(a.get(&id).is_none(), "a replacement has an id of its own");
    }

    #[test]
    fn a_refund_gives_back_the_amount_the_count_and_the_period() {
        let per_period = Some(Period { amount: 100, ms: 60_000 });
        let (mut a, id) = held(spend_grant(Limits { per_period, count: Some(1), ..Limits::default() }));
        let c = a.charge(&id, 100, 5).unwrap();
        a.refund(&c);
        let used = &a.get(&id).unwrap().used;
        assert_eq!((used.spent, used.count, used.window.len()), (0, 0, 0));
        assert_eq!(a.decide(&asked(100), 6), Verdict::Unattended(id));
    }

    #[test]
    fn a_person_may_narrow_a_request_but_never_widen_it() {
        let asked = spend_grant(Limits { per_request: Some(100), count: Some(5), ..Limits::default() });
        let tighter = spend_grant(Limits { per_request: Some(50), count: Some(5), total: Some(70), ..Limits::default() });
        assert!(asked.narrowed_by(&tighter));
        assert!(asked.narrowed_by(&Grant { review: true, ..asked.clone() }), "adding review narrows");
        assert!(!asked.narrowed_by(&spend_grant(Limits { per_request: Some(101), count: Some(5), ..Limits::default() })));
        assert!(!asked.narrowed_by(&spend_grant(Limits { count: Some(5), ..Limits::default() })), "dropping a limit widens");
        assert!(!asked.narrowed_by(&Grant { callers: vec![caller("other")], ..asked.clone() }));
        let reviewed = Grant { review: true, ..asked.clone() };
        assert!(!reviewed.narrowed_by(&asked), "dropping review widens");
    }

    #[test]
    fn kept_allowances_survive_a_restart_inactive_with_what_they_spent() {
        let d = dir();
        let mut a = Allowances::load(d.clone());
        a.open(&key(1));
        a.set_held(ACCOUNT);
        let id = a.grant(spend_grant(Limits { total: Some(100), ..Limits::default() }), None, 0).unwrap().id;
        a.charge(&id, 60, 1).unwrap();
        a.save(&key(1)).unwrap();

        let mut again = Allowances::load(d.clone());
        again.open(&key(1));
        assert_eq!(again.get(&id).unwrap().used.spent, 60);
        assert!(matches!(again.decide(&asked(1), 2), Verdict::Person(Some(_))), "no key held yet");
        again.set_held(ACCOUNT);
        assert_eq!(again.decide(&asked(40), 2), Verdict::Unattended(id));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn one_set_to_end_at_restart_is_never_written_down() {
        let d = dir();
        let mut a = Allowances::load(d.clone());
        a.open(&key(1));
        let id = a.grant(Grant { ends_at_restart: true, ..spend_grant(Limits::default()) }, None, 0).unwrap().id;
        a.save(&key(1)).unwrap();
        let mut again = Allowances::load(d.clone());
        again.open(&key(1));
        assert!(again.get(&id).is_none());
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_file_that_will_not_open_is_never_overwritten() {
        let d = dir();
        let mut a = Allowances::load(d.clone());
        a.open(&key(1));
        a.grant(spend_grant(Limits::default()), None, 0).unwrap();
        a.save(&key(1)).unwrap();
        let before = std::fs::read(d.join(FILE)).unwrap();

        let mut other = Allowances::load(d.clone());
        other.open(&key(2));
        assert!(other.unreadable());
        assert!(other.save(&key(2)).is_err());
        assert_eq!(std::fs::read(d.join(FILE)).unwrap(), before);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn a_key_no_live_allowance_needs_is_let_go() {
        let (mut a, id) = held(spend_grant(Limits { expires_at_ms: Some(10), ..Limits::default() }));
        assert!(a.unneeded(5).is_empty());
        assert_eq!(a.unneeded(10), vec![ACCOUNT.to_string()]);
        assert!(!a.is_held(ACCOUNT));
        assert!(a.get(&id).is_some(), "it stays listed until someone removes it");
    }
}
