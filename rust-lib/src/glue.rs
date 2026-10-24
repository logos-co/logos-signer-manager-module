//! Logos module glue for `signer_manager_module`. The builder derives the `.lidl` from the
//! `SignerManagerModule` trait and injects the generated scaffold at the `include!` point.
//!
//! Every structured value crosses IPC as a JSON string: `{ "ok": true, ... }` or
//! `{ "ok": false, "error": "...", "code"? }`. The approval API keeps keystore_module's names and
//! shapes, so a requester or an approver changes only the module it calls.

use std::sync::{Arc, Weak};
use std::time::Duration;

use serde_json::json;
use zeroize::Zeroizing;

use logos_signer_interface::{
    json as signer_json, Account, ErrorCode, JobStatus, SignRequest, Signature, Signer, SignerError, SignerInfo, UnlockKey,
    UnlockKeyRequest,
};

use crate::access::{Access, Cover, Decision, Gate, KeyHolder, OpenedWallet, Role, Terms, Unlocked};
use crate::approval::{Approvals, Approved, Move};
use crate::gate;
use crate::registry::Registry;
use crate::unlock::{About, Factor, Holder, Unlock};
use crate::wallets::{Begun, Then, Wallets};
use crate::ManagerError;

/// The signer manager's IPC contract.
pub trait SignerManagerModule: Send + Sync + 'static {
    /// Name the roles and the signer modules consulted: `{ approvers?, custodians?, signers? }` →
    /// `{ ok, approvers, custodians, signers }`. TOTAL — what the document doesn't name is held by
    /// nobody — and effective at once. UNGATED for now, as keystore_module's: see docs/specs.md.
    fn configure(&self, config_json: String) -> String;

    // ── Tier B: any NAMED module may ask ────────────────────────────────
    /// Ask a person to approve signing; returns at once with `{ ok, handle, receipt, state }`.
    /// The handle is announced on the event plane; the receipt, returned once, authorises collecting.
    fn request_approval(&self, intent_json: String) -> String;
    /// `{ ok, state, reason? }`: offered, rendered, signing or settled. Never the intent or results.
    fn approval_status(&self, handle: String, receipt: String) -> String;
    /// `{ ok, signed: [...] }`, idempotent until `ack_result`.
    fn fetch_result(&self, handle: String, receipt: String) -> String;
    /// The requester has the results; erase them.
    fn ack_result(&self, handle: String, receipt: String) -> bool;
    /// The requester gave up; a signer still working is told to stop.
    fn cancel_approval(&self, handle: String, receipt: String) -> bool;
    /// Every account once, with every signer that holds it, ranked: `{ ok, accounts: [{ key,
    /// family, chain?, address?, path?, label?, labels?, wallet?: { fingerprint?, name? }, holders:
    /// [{ signer, accountId, kind, model, transport, presence, available, collects, showsRequest,
    /// requestKinds }] }] }`. No xpub.
    fn roster(&self) -> String;

    // ── Tier A: the configured approver only ────────────────────────────
    /// Queue summaries, never leg detail: `{ ok, pending: [{ handle, requester, state, purpose,
    /// legs, ageMs, error? }] }`.
    fn pending(&self) -> String;
    /// Claim a request for display: `{ ok, handle, bundle_id, requester, claim_lines,
    /// render_lines, signer, collects, account, unlocked, signers, explicit }`. `collects` says what
    /// `approve` must carry, unless `unlocked`, when an unlock covers the request and no password is
    /// needed. `signers` are every holder of the account, ranked, as `{ signer, accountId, kind,
    /// model, transport, presence, available, collects, showsRequest, canTake, why? }`; `signer` is
    /// the one it goes to, chosen by the person when `explicit`.
    fn acknowledge(&self, handle: String) -> String;
    /// The person chose which holder signs the request on screen: the `acknowledge` reply for it.
    /// The request and its commitment don't change.
    fn choose_signer(&self, handle: String, bundle_id: String, signer: String) -> String;
    /// The `acknowledge` reply again, as the holders stand now: after a signer's accounts change.
    fn approval_signers(&self, handle: String) -> String;
    /// The person said yes: `{ ok, signed_count }` once signed, or `{ ok, state: "signing" }` while a
    /// device works. A wrong password answers `{ ok: false, code: "wrong_secret" }` and the request
    /// stays on screen. `password` is the vault password or a card's PIN, or empty.
    fn approve(&self, handle: String, bundle_id: String, password: String) -> String;
    /// The person said no.
    fn reject(&self, handle: String) -> bool;

    // ── Opening and unlocking: asked by any named module, decided by the custodian ──
    /// Ask a person to open a Bitcoin wallet for the caller: `{ group, network?, seed? }` to reopen
    /// one (`seed` names it while its seed is locked), or `{ family, network }` to let the person
    /// pick, create or restore one, with optional `unlock` terms and a `reason` → `{ ok, handle,
    /// receipt, state }`. Given in the Signer app, `fetch_result` returns `{ ok, result: { group,
    /// family, chain, network, external, internal, fingerprint, seed, origin?, birthday? } }`, and
    /// the caller takes its database key from `data_key`. The keys app's older path returns a
    /// `databaseKey` and `unlocked` instead of `seed`. Tier B.
    fn request_open(&self, params_json: String) -> String;
    /// Ask for an account to stay unlocked: `{ account, ttlMs?, count?, apps?, confirm?, reason? }`
    /// → `{ ok, handle, receipt, state }`. The person decides the terms. Tier B.
    fn request_unlock(&self, params_json: String) -> String;
    /// The queue: `{ ok, requests: [{ handle, requester, kind, state, ageMs, seed }] }`, `seed` the
    /// wallet an open names when known; an approver sees opens only. Approvers and the custodian.
    fn access_requests(&self) -> String;
    /// Claim one for display: `{ ok, handle, requester, kind, bundle_id, lines, asked, seed }`.
    /// `asked` is `{ group, family, network, unlock, seed }` for an open and `{ account, terms }` for
    /// an unlock; `seed` is the named wallet's. The first app to claim it keeps it.
    fn acknowledge_access(&self, handle: String) -> String;
    /// The person decided: an approver's consent `{ handle, bundle_id, group? }`, once the wallet is
    /// unlocked (`code: locked` until then), or the custodian's `{ handle, bundle_id, group?,
    /// password, unlock?, birthday? }` → `{ ok }`, or `{ ok: false, code }` with the request left on
    /// screen.
    fn approve_access(&self, params_json: String) -> String;
    /// The person said no: the app that claimed it.
    fn reject_access(&self, handle: String) -> bool;
    /// An open wallet's descriptors again: `{ ok, group, external, internal }`, only for a module
    /// the wallet is open for.
    fn account_descriptors(&self, group: String) -> String;
    /// Close a wallet: `{ group }` for the caller's own, or as the custodian `{ group, module }` →
    /// `{ ok, closed }`. An unlock scoped to that module alone ends with it.
    fn close_account(&self, params_json: String) -> String;
    /// Every open wallet and its module: `{ ok, open: [{ module, group }] }`. Tier D.
    fn open_accounts(&self) -> String;
    /// The person's own unlock, from the keys app: `{ account, password, ttlMs?, count?, apps,
    /// confirm? }` → `{ ok, account, expiresInMs, countLeft }`. Tier D.
    fn unlock(&self, params_json: String) -> String;
    /// `{ account? }`, every account for `{}` → `{ ok, locked }`. Tier D.
    fn lock(&self, params_json: String) -> String;
    /// `{ ok, unlocked: [{ account, expiresInMs, countLeft, apps, confirm }] }`. Approver and custodian.
    fn unlocked(&self) -> String;
    /// Requests signed without being shown: `{ ok, signed: [{ handle, requester, account, ageMs }] }`.
    /// Approver and custodian.
    fn unattended_signatures(&self) -> String;

    // ── Wallets: each seed unlocked once per session, in the Signer app ─────
    /// Every wallet: `{ ok, wallets: [{ seed, name, locked, kinds, privateName? }] }`. Tier B.
    fn wallets(&self) -> String;
    /// The caller's own key for a wallet's data: `{ seed, scope, generation? }`, `seed` a wallet's
    /// or `"profile"` → `{ ok, key, generation }`, or `code: locked`. Tier B: a module gets only
    /// keys of its own.
    fn data_key(&self, params_json: String) -> String;
    /// A signer registers the seed it just added, with the holder's unlock key at index 0 when it
    /// gives one: `{ seed, kind, unlockKey?, name, origin?, birthday? }` → `{ ok, seed, new,
    /// unlocked }`. `seed` in is the signer's own name for it. The configured signers only.
    fn enroll_seed(&self, params_json: String) -> String;
    /// The Signer app's view: `{ ok, wallets: [{ seed, name, privateName?, locked, holders, device,
    /// index, generation, ways: [{ id, factors: [{ kind, id?, name? }] }], alwaysUnlocked, origin?,
    /// birthday? }],
    /// passwords: [{ id, name, wallets }] }`. `device`: its holders give an unlock key, so a way
    /// may take the device. Approvers.
    fn wallet_settings(&self) -> String;
    /// Unlock a wallet by one of its ways in: `{ seed, way, holder?, secret?, passwords? }`, or `{
    /// handle, passwords }` to type a password again → `{ ok, state: "done" }`, or `{ ok, state:
    /// "device", handle }` while the holder works. `passwords` maps a password's id to it. Approvers.
    fn unlock_wallet(&self, params_json: String) -> String;
    /// How a device step stands: `{ ok, state, seed, step?, code?, error? }`, `state` one of
    /// `device`, `needs_password`, `done`, `failed`. Approvers.
    fn unlock_progress(&self, handle: String) -> String;
    /// Stop a device step: the holder stops asking. Approvers.
    fn cancel_unlock(&self, handle: String) -> bool;
    /// `{ seeds? }`, every wallet for `{}` → `{ ok, locked }`. Approvers.
    fn lock_wallets(&self, params_json: String) -> String;
    /// A wallet's ways in: `{ seed, ways: [[factor]], holder?, secret?, passwords? }`, each factor
    /// `device` or `password:<id>` → as `unlock_wallet`; `[[]]` alone leaves it always unlocked.
    /// Approvers.
    fn set_rule(&self, params_json: String) -> String;
    /// New keys for a wallet: `{ seed, newIndex?, holder?, secret?, passwords? }`; `newIndex: true`
    /// moves to the next unlock key → as `unlock_wallet`. Approvers.
    fn change_keys(&self, params_json: String) -> String;
    /// `{ seed, name?, privateName? }` → `{ ok }`; an empty `privateName` clears it. Approvers.
    fn set_names(&self, params_json: String) -> String;
    /// `{ name, password }` → `{ ok, id }`. Approvers.
    fn create_password(&self, params_json: String) -> String;
    /// `{ id, name }` → `{ ok }`. Approvers.
    fn rename_password(&self, params_json: String) -> String;
    /// `{ id, old, new }` → `{ ok }`. Approvers.
    fn change_password(&self, params_json: String) -> String;
    /// `{ id }` → `{ ok }`, refused while a wallet's rule takes it. Approvers.
    fn remove_password(&self, params_json: String) -> String;

    // ── Tier C: ungated reads ───────────────────────────────────────────
    /// Every signer's accounts, each under the first signer that offers it: `{ ok, accounts: [{
    /// id, key, family, chain?, address?, label?, signer, available }] }`. No xpub: it would show a
    /// Bitcoin wallet's whole history to anyone who asked. `key` is the account's `roster` key.
    fn accounts(&self) -> String;
    /// The signer modules consulted, with what each says it is: `{ ok, signers: [{ name, info? }] }`.
    fn signers(&self) -> String;
    /// What this module sees as its caller, with the roles and signers in force:
    /// `{ ok, kind, identity, approvers, custodians, signers }`.
    fn caller_identity(&self) -> String;
    /// Framework hook — defaulted, so not part of the IPC contract.
    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

/// Typed events. Payloads carry handles only: the event plane is unauthenticated.
pub trait SignerManagerModuleEvents {
    /// A new request is waiting.
    fn approval_offered(&self, handle: String);
    /// A request reached a terminal state.
    fn approval_settled(&self, handle: String, state: String);
    /// A request moved without settling, such as to `signing`.
    fn approval_progress(&self, handle: String, state: String);
    /// A signer's accounts changed; re-read `accounts`. `count` is advisory.
    fn accounts_changed(&self, count: i64);
    /// An open or unlock request is waiting for the custodian.
    fn access_requested(&self, handle: String);
    /// An open or unlock request reached a terminal state.
    fn access_settled(&self, handle: String, state: String);
    /// An account was unlocked or locked.
    fn unlock_changed(&self, account: String);
    /// A request was signed without being shown, inside an unlock that allows it.
    fn signed_without_asking(&self, handle: String);
    /// A wallet was added, unlocked or changed: re-read `wallets`, and ask `data_key` again.
    fn wallets_changed(&self, seed: String);
    /// Wallets were locked: drop what was read under their keys.
    fn wallets_locked(&self, count: i64);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

/// How long the manager waits on a signer module before calling it unavailable.
const SIGNER_TIMEOUT: Duration = Duration::from_secs(20);
const INFO_TIMEOUT: Duration = Duration::from_secs(3);

/// A signer module over IPC, through the `signer` interface bound to its name.
type OriginSnapshots = Arc<std::sync::Mutex<std::collections::BTreeMap<String, serde_json::Value>>>;

struct IpcSigner {
    name: String,
    peer: Option<String>,
    routed: std::collections::BTreeMap<String, serde_json::Value>,
    origins: OriginSnapshots,
}

fn unavailable(name: &str, e: impl std::fmt::Display) -> SignerError {
    SignerError::new(ErrorCode::Unavailable, format!("{name}: {e}"))
}

impl Signer for IpcSigner {
    fn info(&self) -> SignerInfo {
        signer::SignerClient::bind(&self.name)
            .signer_info_with_timeout(INFO_TIMEOUT)
            .ok()
            .and_then(|reply| signer_json::read_info(&reply).ok())
            .unwrap_or(SignerInfo {
                interface: String::new(),
                kind: String::new(),
                model: String::new(),
                families: Vec::new(),
                request_kinds: Vec::new(),
                shows_request: false,
                collects: logos_signer_interface::Collects::Nothing,
                unlock_key: false,
            })
    }

    fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
        let reply = signer::SignerClient::bind(&self.name)
            .signer_accounts_with_timeout(SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        let mut snapshot: serde_json::Value = serde_json::from_str(&reply).map_err(|e| unavailable(&self.name, e))?;
        if let Some(peer) = &self.peer {
            let other = signer::SignerClient::bind(peer).signer_accounts_with_timeout(INFO_TIMEOUT)
                .ok().and_then(|s| serde_json::from_str(&s).ok()).unwrap_or(serde_json::Value::Null);
            snapshot = crate::keycard_routes::inventory(snapshot, &other);
        }
        self.routed.clear();
        if crate::keycard_routes::peer(&self.name).is_some() {
            for row in snapshot["accounts"].as_array().into_iter().flatten() {
                if let (Some(id), Some(offer)) = (row["id"].as_str(), row.get("keycardAccount").filter(|v| v.is_object())) {
                    self.routed.insert(id.to_lowercase(), offer.clone());
                }
            }
        }
        let accounts = signer_json::read_accounts(&snapshot.to_string())?;
        self.origins.lock().unwrap_or_else(|e| e.into_inner()).insert(self.name.clone(), snapshot);
        Ok(accounts)
    }

    fn sign(&mut self, request: SignRequest) -> logos_signer_interface::Result<String> {
        let offer = self.routed.get(&request.account.to_lowercase()).cloned();
        let mut value = serde_json::to_value(request).map_err(|e| unavailable(&self.name, e))?;
        if let Some(offer) = offer { value["keycardAccount"] = offer; }
        let body = Zeroizing::new(value.to_string());
        if let Some(serde_json::Value::String(secret)) = value.get_mut("secret") {
            zeroize::Zeroize::zeroize(secret);
        }
        drop(value);
        let reply = signer::SignerClient::bind(&self.name)
            .sign_with_timeout(&body, SIGNER_TIMEOUT).map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply)
    }

    fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        let reply = signer::SignerClient::bind(&self.name)
            .sign_status_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_status(&reply)
    }

    fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
        let reply = signer::SignerClient::bind(&self.name)
            .sign_result_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_signatures(&reply)
    }

    fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        let reply = signer::SignerClient::bind(&self.name)
            .cancel_sign_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply).map(drop)
    }

    fn unlock_key(&mut self, request: UnlockKeyRequest) -> logos_signer_interface::Result<String> {
        let mut value = serde_json::to_value(request).map_err(|e| unavailable(&self.name, e))?;
        let body = Zeroizing::new(value.to_string());
        if let Some(serde_json::Value::String(secret)) = value.get_mut("secret") {
            zeroize::Zeroize::zeroize(secret);
        }
        drop(value);
        let reply = signer::SignerClient::bind(&self.name)
            .unlock_key_with_timeout(&body, SIGNER_TIMEOUT).map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply)
    }

    fn unlock_key_status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
        let reply = signer::SignerClient::bind(&self.name)
            .unlock_key_status_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_status(&reply)
    }

    fn unlock_key_result(&mut self, job: &str) -> logos_signer_interface::Result<UnlockKey> {
        let reply = Zeroizing::new(
            signer::SignerClient::bind(&self.name)
                .unlock_key_result_with_timeout(job, SIGNER_TIMEOUT)
                .map_err(|e| unavailable(&self.name, e))?,
        );
        signer_json::read_unlock_key(&reply)
    }

    fn cancel_unlock_key(&mut self, job: &str) -> logos_signer_interface::Result<()> {
        let reply = signer::SignerClient::bind(&self.name)
            .cancel_unlock_key_with_timeout(job, SIGNER_TIMEOUT)
            .map_err(|e| unavailable(&self.name, e))?;
        signer_json::read_job(&reply).map(drop)
    }
}

/// The keystore's extras beyond the signer interface: database keys and unlocks.
struct KeystoreKeys;

fn keystore_reply(reply: Result<String, logos_rust_sdk::LogosError>) -> crate::Result<serde_json::Value> {
    let reply = reply.map_err(|e| ManagerError::Signer(unavailable("keystore_module", e)))?;
    Ok(logos_signer_interface::wire::parse_reply(&reply)?)
}

/// What the keystore released for an open: the key, and where the wallet's history starts.
fn opened_wallet(v: &serde_json::Value) -> OpenedWallet {
    let key = v.get("databaseKey").and_then(|k| k.as_str()).unwrap_or_default();
    // A keystore from before origins were kept says neither: the wallet core then scans the most.
    let origin = v.get("origin").and_then(|o| o.as_str()).filter(|o| *o == "created").unwrap_or("restored");
    let birthday = v.get("birthday").and_then(|b| b.as_str()).filter(|b| is_day(b)).map(str::to_string);
    OpenedWallet { database_key: Zeroizing::new(key.to_string()), origin: origin.into(), birthday }
}

/// `YYYY-MM-DD`, as the keystore writes a birthday; anything else is dropped, not passed on.
fn is_day(s: &str) -> bool {
    s.len() == 10 && s.bytes().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == b'-' } else { c.is_ascii_digit() })
}

impl KeyHolder for KeystoreKeys {
    fn database_key(&mut self, group: &str, password: Option<&str>) -> crate::Result<OpenedWallet> {
        let body = Zeroizing::new(json!({ "group": group, "password": password }).to_string());
        Ok(opened_wallet(&keystore_reply(modules().keystore_module.database_key(&body))?))
    }

    fn device_database_key(&mut self, signer: &str, account: &str, password: &str, birthday: Option<&str>)
        -> crate::Result<OpenedWallet> {
        let body = Zeroizing::new(
            json!({ "signer": signer, "account": account, "password": password, "birthday": birthday }).to_string(),
        );
        Ok(opened_wallet(&keystore_reply(modules().keystore_module.device_database_key(&body))?))
    }

    fn device_wallets(&mut self) -> crate::Result<Vec<(String, String)>> {
        let v = keystore_reply(modules().keystore_module.device_wallets())?;
        Ok(v.get("wallets").and_then(|w| w.as_array()).into_iter().flatten().filter_map(|w| {
            Some((w.get("signer")?.as_str()?.to_string(), w.get("account")?.as_str()?.to_string()))
        }).collect())
    }

    fn unlock(&mut self, account: &str, password: &str, ttl_ms: Option<u64>, count: Option<u32>) -> crate::Result<Unlocked> {
        let body = Zeroizing::new(
            json!({ "account": account, "password": password, "ttlMs": ttl_ms, "count": count }).to_string(),
        );
        let v = keystore_reply(modules().keystore_module.unlock(&body))?;
        serde_json::from_value(v).map_err(|e| ManagerError::Signing(format!("keystore unlock reply: {e}")))
    }

    fn lock(&mut self, account: Option<&str>) -> crate::Result<usize> {
        let v = keystore_reply(modules().keystore_module.lock(&json!({ "account": account }).to_string()))?;
        Ok(v.get("locked").and_then(|n| n.as_u64()).unwrap_or(0) as usize)
    }

    fn unlocked(&mut self) -> crate::Result<Vec<Unlocked>> {
        let v = keystore_reply(modules().keystore_module.unlocked())?;
        serde_json::from_value(v.get("unlocked").cloned().unwrap_or_default())
            .map_err(|e| ManagerError::Signing(format!("keystore unlocked reply: {e}")))
    }
}

/// A request signed without being shown, for the keys app and the signer to list.
struct Unattended {
    handle: String,
    requester: String,
    account: String,
    at: std::time::Instant,
}

/// The module: one lock around its state. Concurrency is "multi", so each call runs on a worker
/// thread and waits there for the lock, never nested on the main thread an outbound call needs.
struct SignerManagerModuleImpl {
    core: Arc<std::sync::Mutex<Core>>,
}

impl Default for SignerManagerModuleImpl {
    fn default() -> Self {
        let core = Arc::new_cyclic(|me| std::sync::Mutex::new(Core { me: me.clone(), ..Default::default() }));
        SignerManagerModuleImpl { core }
    }
}

impl SignerManagerModuleImpl {
    fn core(&self) -> std::sync::MutexGuard<'_, Core> {
        self.core.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[derive(Default)]
struct Core {
    approvals: Approvals,
    access: Access,
    wallets: Wallets,
    unattended: Vec<Unattended>,
    roles: gate::Roles,
    signers: Registry,
    origins: OriginSnapshots,
    /// The signers whose accounts changed, named by their listeners.
    stale: Arc<std::sync::Mutex<Vec<String>>>,
    started: bool,
    /// This core, for the listeners: a signer's news is announced when it comes, not at the next call.
    me: Weak<std::sync::Mutex<Core>>,
}

/// From a listener thread: re-read and announce what a signer's event changed.
fn nudge(me: &Weak<std::sync::Mutex<Core>>) {
    if let Some(core) = me.upgrade() {
        core.lock().unwrap_or_else(|e| e.into_inner()).refresh();
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

/// A refusal carries the signer's code, so the approver can tell "try the password again".
fn manager_err(e: &ManagerError) -> String {
    match e.wire_code() {
        Some(code) => json!({ "ok": false, "code": code, "error": e.to_string() }).to_string(),
        None => err(e),
    }
}

/// Identical whether the handle is unknown or not yours: no oracle for "does this exist?".
fn not_authorized() -> String {
    json!({ "ok": false, "error": "not authorized" }).to_string()
}

impl Core {
    fn caller() -> gate::Caller {
        match logos_rust_sdk::current_caller() {
            logos_rust_sdk::LogosCaller::Unknown => gate::Caller::Unknown,
            logos_rust_sdk::LogosCaller::HostAnchor => gate::Caller::HostAnchor,
            logos_rust_sdk::LogosCaller::Module { name, .. } => gate::Caller::Module(name),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => gate::Caller::Derived { parent, leaf },
            logos_rust_sdk::LogosCaller::Operator { name } => gate::Caller::Operator(name),
        }
    }

    fn is_approver(&self) -> bool {
        gate::holds_any_role(&self.roles.approvers, &Self::caller())
    }

    fn is_custodian(&self) -> bool {
        gate::holds_any_role(&self.roles.custodians, &Self::caller())
    }

    /// Does an unlock cover this approval's requester for its account?
    fn cover(&mut self, handle: &str) -> Cover {
        let Some((requester, account)) = self.approvals.requester_and_account(handle) else { return Cover::No };
        if self.access.covers(&account, &requester) == Cover::No {
            return Cover::No;
        }
        // The keystore keeps the time and the count: one it has dropped covers nothing here either.
        let _ = self.access.unlocked(&mut KeystoreKeys);
        self.access.covers(&account, &requester)
    }

    fn named_caller(&self) -> Option<String> {
        Self::caller().named().map(str::to_string)
    }

    /// The configured signer modules, bound by name, each listened to for account changes and
    /// for its jobs' progress.
    fn bind_signers(&mut self) {
        let mut r = Registry::new();
        for name in &self.roles.signers {
            r.add(name.clone(), Box::new(IpcSigner { name: name.clone(), origins: self.origins.clone(),
                peer: crate::keycard_routes::peer(name).filter(|p| self.roles.signers.iter().any(|n| n == p)).map(str::to_owned),
                routed: Default::default() }));
            let mut client = signer::SignerClient::bind(name);
            if let Ok(sub) = client.on_signer_accounts_changed() {
                let (stale, me, name) = (self.stale.clone(), self.me.clone(), name.clone());
                std::thread::spawn(move || {
                    for _ in sub {
                        stale.lock().unwrap_or_else(|e| e.into_inner()).push(name.clone());
                        nudge(&me);
                    }
                });
            }
            if let Ok(sub) = client.on_sign_progress() {
                let me = self.me.clone();
                std::thread::spawn(move || {
                    for _ in sub {
                        nudge(&me);
                    }
                });
            }
        }
        self.signers = r;
        self.started = true;
    }

    /// Before each call: bind the signers once, and re-read their accounts after a change.
    fn refresh(&mut self) {
        if !self.started {
            self.bind_signers();
        }
        let mut changed = std::mem::take(&mut *self.stale.lock().unwrap_or_else(|e| e.into_inner()));
        if changed.iter().any(|name| crate::keycard_routes::peer(name).is_some()) {
            for name in ["keycard_module", "keycard_shell_module"] {
                if !changed.iter().any(|n| n == name) { changed.push(name.into()); }
            }
        }
        if !changed.is_empty() {
            // Only the signers that announced: a module that isn't installed keeps resting.
            self.signers.forget(&changed);
            emit_accounts_changed(self.signers.accounts().len() as i64);
        }
        // A device ends its job in its own time: look, and announce what that moved.
        self.approvals.progress(&mut self.signers);
        for m in self.approvals.drain_moves() {
            match m {
                Move::Settled(h, o) => emit_approval_settled(&h, o.as_str()),
                Move::Rendered(h) => emit_approval_progress(&h, "rendered"),
            }
        }
        // So does a holder working out an unlock key; its jobs are announced nowhere, so this looks.
        self.wallets.progress_all(&mut self.signers);
        self.announce_wallets();
    }

    fn announce_wallets(&mut self) {
        for seed in self.wallets.drain_changed() {
            emit_wallets_changed(&seed);
        }
    }

    /// The access gate for the caller: the custodian, else an approver.
    fn access_gate(&self) -> Option<(String, Role)> {
        let name = self.named_caller()?;
        let role = if self.is_custodian() {
            Role::Custodian
        } else if self.is_approver() {
            Role::Approver
        } else {
            return None;
        };
        Some((name, role))
    }
}

/// A device step's reply: done, or the handle `unlock_progress` follows.
fn begun(r: crate::Result<Begun>) -> String {
    match r {
        Ok(Begun::Done) => json!({ "ok": true, "state": "done" }).to_string(),
        Ok(Begun::Waiting(handle)) => json!({ "ok": true, "state": "device", "handle": handle }).to_string(),
        Err(e) => manager_err(&e),
    }
}

/// What a step that may need the device carries: the holder, its PIN or password, typed passwords.
#[derive(serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct StepWire {
    #[serde(default)]
    holder: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    passwords: std::collections::BTreeMap<String, String>,
}

impl StepWire {
    fn take(&mut self) -> (Option<String>, Option<logos_signer_interface::Secret>, std::collections::BTreeMap<String, Zeroizing<String>>) {
        let passwords = std::mem::take(&mut self.passwords).into_iter().map(|(id, pw)| (id, Zeroizing::new(pw))).collect();
        (self.holder.take(), self.secret.take().map(logos_signer_interface::Secret::new), passwords)
    }
}

/// Parse params that carry a secret; the buffer is wiped whatever the outcome.
fn secret_params<T: serde::de::DeserializeOwned>(params_json: String) -> Result<T, String> {
    let owned = Zeroizing::new(params_json);
    serde_json::from_str(&owned).map_err(|e| e.to_string())
}

impl Core {
    fn on_context_ready(&mut self, ctx: &RustModuleContext) {
        let dir = std::path::Path::new(&ctx.instance_persistence_path).join("unlock");
        self.wallets = Wallets::new(Unlock::load(dir));
        self.bind_signers();
        // The terms of any unlock were kept here and are gone: nothing stays unlocked past a restart.
        let _ = KeystoreKeys.lock(None);
        // An always-unlocked wallet is open from the start, but a module loaded before this one
        // hears of it only once its subscription arms: say so again then.
        let me = self.me.clone();
        std::thread::spawn(move || {
            for wait in [3, 15] {
                std::thread::sleep(Duration::from_secs(wait));
                let Some(core) = me.upgrade() else { return };
                let mut core = core.lock().unwrap_or_else(|e| e.into_inner());
                for w in core.wallets.store.wallets().into_iter().filter(|w| !w.locked) {
                    core.wallets.note(&w.seed);
                }
                core.refresh();
            }
        });
    }

    fn configure(&mut self, config_json: String) -> String {
        match self.roles.configure(&config_json) {
            Ok(()) => {
                self.bind_signers();
                json!({ "ok": true, "approvers": self.roles.approvers, "custodians": self.roles.custodians,
                        "signers": self.roles.signers })
                .to_string()
            }
            Err(e) => err(e),
        }
    }

    fn request_approval(&mut self, intent_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        let (handle, receipt) = match self.approvals.request(&mut self.signers, &requester, &intent_json) {
            Ok(hr) => hr,
            Err(e) => return manager_err(&e),
        };
        // Inside an unlock the person granted without confirmation, it is signed as it arrives.
        if self.cover(&handle) == Cover::WithoutAsking {
            match self.approvals.sign_unattended(&mut self.signers, &handle) {
                Ok(Approved::Settled(_)) => {
                    let account = self.approvals.requester_and_account(&handle).map(|(_, a)| a).unwrap_or_default();
                    self.unattended.push(Unattended { handle: handle.clone(), requester, account, at: std::time::Instant::now() });
                    emit_signed_without_asking(&handle);
                    emit_approval_settled(&handle, "approved");
                    return json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "settled" }).to_string();
                }
                Ok(Approved::Signing) => {}
                Err(e) if e.code() == Some(ErrorCode::Locked) => {
                    if let Some((_, account)) = self.approvals.requester_and_account(&handle) {
                        self.access.expired(&account);
                    }
                }
                Err(_) => {}
            }
        }
        emit_approval_offered(&handle);
        json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
    }

    fn approval_status(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        if self.access.owns(&handle) {
            return match self.access.status(&handle, &receipt) {
                Ok((state, reason)) => json!({ "ok": true, "state": state, "reason": reason }).to_string(),
                Err(_) => not_authorized(),
            };
        }
        match self.approvals.status(&mut self.signers, &handle, &receipt) {
            Ok((state, reason)) => json!({ "ok": true, "state": state, "reason": reason }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn fetch_result(&mut self, handle: String, receipt: String) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        if self.access.owns(&handle) {
            return match self.access.fetch(&handle, &receipt) {
                Ok(v) => json!({ "ok": true, "result": v }).to_string(),
                Err(ManagerError::NotFound(_)) => not_authorized(),
                Err(e) => err(e),
            };
        }
        match self.approvals.fetch_result(&mut self.signers, &handle, &receipt) {
            Ok(signed) => json!({ "ok": true, "signed": signed }).to_string(),
            Err(ManagerError::NotFound(_)) => not_authorized(),
            Err(e) => err(e),
        }
    }

    fn ack_result(&mut self, handle: String, receipt: String) -> bool {
        if self.named_caller().is_none() {
            return false;
        }
        if self.access.owns(&handle) {
            return self.access.ack(&handle, &receipt).is_ok();
        }
        self.approvals.ack_result(&handle, &receipt).is_ok()
    }

    fn cancel_approval(&mut self, handle: String, receipt: String) -> bool {
        if self.named_caller().is_none() {
            return false;
        }
        self.refresh();
        if self.access.owns(&handle) {
            let ok = self.access.cancel(&handle, &receipt).is_ok();
            if ok {
                emit_access_settled(&handle, "cancelled");
            }
            return ok;
        }
        let ok = self.approvals.cancel(&mut self.signers, &handle, &receipt).is_ok();
        if ok {
            emit_approval_settled(&handle, "cancelled");
        }
        ok
    }

    fn pending(&mut self) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let list: Vec<_> = self
            .approvals
            .pending(&mut self.signers)
            .into_iter()
            .map(|p| {
                json!({ "handle": p.handle, "requester": p.requester, "state": p.state, "purpose": p.purpose,
                        "legs": p.leg_count, "ageMs": p.age_ms as u64, "error": p.error })
            })
            .collect();
        json!({ "ok": true, "pending": list }).to_string()
    }

    fn acknowledge(&mut self, handle: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let shown = self.approvals.acknowledge(&mut self.signers, &handle);
        self.shown(&handle, shown)
    }

    fn choose_signer(&mut self, handle: String, bundle_id: String, signer: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let shown = self.approvals.choose(&mut self.signers, &handle, &bundle_id, &signer);
        self.shown(&handle, shown)
    }

    fn approval_signers(&mut self, handle: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let shown = self.approvals.signers_for(&mut self.signers, &handle);
        self.shown(&handle, shown)
    }

    /// The approver's view of a request. `unlocked`: an unlock covers it, so `approve` needs no
    /// password; only the keystore's copy of an account is ever unlocked.
    fn shown(&mut self, handle: &str, shown: crate::Result<crate::approval::Rendered>) -> String {
        match shown {
            Ok(v) => {
                let unlocked = v.signer == crate::roster::KEYSTORE && self.cover(handle) != Cover::No;
                json!({ "ok": true, "handle": v.handle, "bundle_id": v.bundle_id, "requester": v.requester,
                        "claim_lines": v.claim_lines, "render_lines": v.render_lines,
                        "signer": v.signer, "collects": v.collects, "account": v.account,
                        "unlocked": unlocked, "signers": v.signers, "explicit": v.explicit })
                .to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn approve(&mut self, handle: String, bundle_id: String, password: String) -> String {
        let password = Zeroizing::new(password);
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        let keystore = self.approvals.signer_of(&handle).as_deref() == Some(crate::roster::KEYSTORE);
        let unlocked = keystore && self.cover(&handle) != Cover::No;
        match self.approvals.approve(&mut self.signers, &handle, &bundle_id, &password, unlocked) {
            Ok(Approved::Settled(n)) => {
                emit_approval_settled(&handle, "approved");
                json!({ "ok": true, "signed_count": n }).to_string()
            }
            Ok(Approved::Signing) => {
                emit_approval_progress(&handle, "signing");
                json!({ "ok": true, "state": "signing" }).to_string()
            }
            Err(e) => {
                // Unlocked here but locked at the keystore: its time or count ran out.
                if unlocked && password.is_empty() && e.code() == Some(ErrorCode::Locked) {
                    if let Some((_, account)) = self.approvals.requester_and_account(&handle) {
                        self.access.expired(&account);
                    }
                }
                manager_err(&e)
            }
        }
    }

    fn reject(&mut self, handle: String) -> bool {
        if !self.is_approver() {
            return false;
        }
        self.refresh();
        let ok = self.approvals.reject(&mut self.signers, &handle).is_ok();
        if ok {
            emit_approval_settled(&handle, "rejected");
        }
        ok
    }

    fn request_open(&mut self, params_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.request_open(&mut self.signers, &self.wallets.store, &requester, &params_json) {
            Ok((handle, receipt)) => {
                emit_access_requested(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn request_unlock(&mut self, params_json: String) -> String {
        let Some(requester) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.request_unlock(&mut self.signers, &requester, &params_json) {
            Ok((handle, receipt)) => {
                emit_access_requested(&handle);
                json!({ "ok": true, "handle": handle, "receipt": receipt, "state": "offered" }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn access_requests(&mut self) -> String {
        let Some((_, role)) = self.access_gate() else {
            return not_authorized();
        };
        self.refresh();
        let list: Vec<_> = self
            .access
            .queue(&mut self.signers, &self.wallets.store, role)
            .into_iter()
            .map(|q| json!({ "handle": q.handle, "requester": q.requester, "kind": q.kind, "state": q.state,
                             "ageMs": q.age_ms as u64, "seed": q.seed }))
            .collect();
        json!({ "ok": true, "requests": list }).to_string()
    }

    fn acknowledge_access(&mut self, handle: String) -> String {
        let Some((name, role)) = self.access_gate() else {
            return not_authorized();
        };
        self.refresh();
        let gate = Gate { caller: &name, role };
        match self.access.acknowledge(&mut self.signers, &self.wallets.store, &handle, &gate) {
            Ok(v) => json!({ "ok": true, "handle": v.handle, "requester": v.requester, "kind": v.kind,
                             "bundle_id": v.bundle_id, "lines": v.lines, "asked": v.asked, "seed": v.seed })
            .to_string(),
            Err(ManagerError::Refused(_)) | Err(ManagerError::NotFound(_)) => not_authorized(),
            Err(e) => err(e),
        }
    }

    fn approve_access(&mut self, params_json: String) -> String {
        let params_json = Zeroizing::new(params_json);
        let Some((name, role)) = self.access_gate() else {
            return not_authorized();
        };
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            handle: String,
            bundle_id: String,
            #[serde(default)]
            group: Option<String>,
            /// The custodian's path; an approver's consent carries none.
            #[serde(default)]
            password: Option<String>,
            #[serde(default)]
            unlock: Option<Terms>,
            /// A device wallet's first day of use, at its first open.
            #[serde(default)]
            birthday: Option<String>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("approve_access: {e}")),
        };
        self.refresh();
        // A module holding both roles gives consent unless it brings the keystore's password.
        let consent = w.password.is_none() && (role == Role::Approver || self.is_approver());
        let decided = if consent {
            let gate = Gate { caller: &name, role: Role::Approver };
            self.access.consent(&mut self.signers, &self.wallets.store, &w.handle, &w.bundle_id, w.group, &gate)
        } else {
            let birthday = w.birthday.map(|b| b.trim().to_string()).filter(|b| !b.is_empty());
            let password = w.password.unwrap_or_default();
            let decision = Decision { group: w.group, password, unlock: w.unlock, birthday };
            let gate = Gate { caller: &name, role };
            self.access.approve(&mut self.signers, &mut KeystoreKeys, &w.handle, &w.bundle_id, decision, &gate)
        };
        match decided {
            Err(ManagerError::Refused(why)) if why == "not authorized" => not_authorized(),
            Ok(()) => {
                emit_access_settled(&w.handle, "approved");
                json!({ "ok": true }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn reject_access(&mut self, handle: String) -> bool {
        let Some((name, role)) = self.access_gate() else {
            return false;
        };
        let ok = self.access.reject(&handle, &Gate { caller: &name, role }).is_ok();
        if ok {
            emit_access_settled(&handle, "rejected");
        }
        ok
    }

    fn account_descriptors(&mut self, group: String) -> String {
        let Some(module) = self.named_caller() else {
            return not_authorized();
        };
        self.refresh();
        match self.access.descriptors(&mut self.signers, &module, &group) {
            Ok((external, internal)) => json!({ "ok": true, "group": group, "external": external, "internal": internal }).to_string(),
            Err(_) => not_authorized(),
        }
    }

    fn close_account(&mut self, params_json: String) -> String {
        #[derive(serde::Deserialize)]
        struct Wire {
            group: String,
            #[serde(default)]
            module: Option<String>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("close_account: {e}")),
        };
        let module = match (&w.module, self.named_caller()) {
            (Some(m), _) if self.is_custodian() => m.clone(),
            (None, Some(me)) => me,
            _ => return not_authorized(),
        };
        match self.access.close(&mut KeystoreKeys, &module, &w.group) {
            Ok(closed) => json!({ "ok": true, "closed": closed }).to_string(),
            Err(e) => manager_err(&e),
        }
    }

    fn open_accounts(&mut self) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        let list: Vec<_> =
            self.access.open_accounts().into_iter().map(|(m, g)| json!({ "module": m, "group": g })).collect();
        json!({ "ok": true, "open": list }).to_string()
    }

    fn unlock(&mut self, params_json: String) -> String {
        let params_json = Zeroizing::new(params_json);
        if !self.is_custodian() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            account: String,
            password: String,
            #[serde(default)]
            ttl_ms: Option<u64>,
            #[serde(default)]
            count: Option<u32>,
            #[serde(default)]
            apps: Vec<String>,
            #[serde(default = "confirm_by_default")]
            confirm: bool,
        }
        fn confirm_by_default() -> bool {
            true
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("unlock: {e}")),
        };
        let password = Zeroizing::new(w.password);
        let terms = Terms { ttl_ms: w.ttl_ms, count: w.count, apps: w.apps, confirm: w.confirm };
        self.refresh();
        match self.access.unlock(&mut self.signers, &mut KeystoreKeys, &w.account, &password, &terms) {
            Ok(u) => {
                emit_unlock_changed(&u.account);
                json!({ "ok": true, "account": u.account, "expiresInMs": u.expires_in_ms, "countLeft": u.count_left })
                    .to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn lock(&mut self, params_json: String) -> String {
        if !self.is_custodian() {
            return not_authorized();
        }
        let account: Option<String> = serde_json::from_str::<serde_json::Value>(&params_json)
            .ok()
            .and_then(|v| v.get("account").and_then(|a| a.as_str()).map(str::to_string));
        match self.access.lock(&mut KeystoreKeys, account.as_deref()) {
            Ok(n) => {
                emit_unlock_changed(account.as_deref().unwrap_or("*"));
                json!({ "ok": true, "locked": n }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn unlocked(&mut self) -> String {
        if !self.is_custodian() && !self.is_approver() {
            return not_authorized();
        }
        match self.access.unlocked(&mut KeystoreKeys) {
            Ok(list) => {
                let list: Vec<_> = list
                    .into_iter()
                    .map(|(u, apps, confirm)| {
                        json!({ "account": u.account, "expiresInMs": u.expires_in_ms, "countLeft": u.count_left,
                                "apps": apps, "confirm": confirm })
                    })
                    .collect();
                json!({ "ok": true, "unlocked": list }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn unattended_signatures(&mut self) -> String {
        if !self.is_custodian() && !self.is_approver() {
            return not_authorized();
        }
        let now = std::time::Instant::now();
        let list: Vec<_> = self
            .unattended
            .iter()
            .map(|u| json!({ "handle": u.handle, "requester": u.requester, "account": u.account,
                             "ageMs": now.duration_since(u.at).as_millis() as u64 }))
            .collect();
        json!({ "ok": true, "signed": list }).to_string()
    }

    fn accounts(&mut self) -> String {
        self.refresh();
        let list: Vec<_> = self
            .signers
            .accounts()
            .into_iter()
            .map(|(signer, a)| {
                json!({ "id": a.id, "key": crate::roster::key_of(&a), "family": a.family, "chain": a.chain,
                        "address": a.address, "label": a.label, "signer": signer, "available": a.available })
            })
            .collect();
        let mut inventory = json!({ "ok": true, "accounts": list });
        for (provider, snapshot) in self.origins.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            crate::origins::attach(&mut inventory, provider, snapshot);
        }
        inventory.to_string()
    }

    fn roster(&mut self) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        self.refresh();
        let roster = self.signers.roster();
        let snapshots = self.origins.lock().unwrap_or_else(|e| e.into_inner()).clone();
        let store = &self.wallets.store;
        let list: Vec<_> = roster
            .iter()
            .map(|(key, holders)| {
                let mut e = crate::roster::entry_json(key, holders, |f| crate::origins::of(&snapshots, &f.name, &f.account));
                e["seed"] = holders.iter().find_map(|f| store.seed_of(&f.name, f.account.seed.as_deref()?)).into();
                e
            })
            .collect();
        json!({ "ok": true, "accounts": list }).to_string()
    }

    fn signers(&mut self) -> String {
        self.refresh();
        let list: Vec<_> =
            self.signers.infos().into_iter().map(|(name, info)| json!({ "name": name, "info": info })).collect();
        json!({ "ok": true, "signers": list }).to_string()
    }

    fn is_signer(&self) -> Option<String> {
        self.named_caller().filter(|n| self.roles.signers.iter().any(|s| s == n))
    }

    // These two answer signers and data owners mid-call, while the caller may be waiting on its
    // own reply: they must not call out to any module, so neither refreshes.
    fn data_key(&mut self, params_json: String) -> String {
        let Some(module) = self.named_caller() else {
            return not_authorized();
        };
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            seed: String,
            #[serde(default)]
            account: Option<String>,
            scope: String,
            #[serde(default)]
            generation: Option<u32>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("data_key: {e}")),
        };
        let seed = match (&w.account, w.seed.trim().is_empty()) {
            (Some(account), true) => match self.signers.seed_of_account(account) {
                Some((holder, named)) => match self.wallets.store.seed_of(&holder, &named) {
                    Some(seed) => seed,
                    None => return json!({ "ok": false, "code": "unavailable", "error": "data_key: this account's wallet isn't known yet" }).to_string(),
                },
                None => return json!({ "ok": false, "code": "unavailable", "error": "data_key: no signer lists this account" }).to_string(),
            },
            (None, false) => self.wallets.store.resolve(&module, &w.seed),
            _ => return err("data_key: name a seed or an account"),
        };
        match self.wallets.store.data_key(&module, &seed, &w.scope, w.generation) {
            Ok((key, generation)) => {
                let key = Zeroizing::new(hex::encode(&key[..]));
                json!({ "ok": true, "key": key.as_str(), "generation": generation, "seed": seed }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn enroll_seed(&mut self, params_json: String) -> String {
        let Some(signer) = self.is_signer() else {
            return not_authorized();
        };
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            seed: String,
            #[serde(default)]
            kind: String,
            #[serde(default)]
            unlock_key: Option<String>,
            name: String,
            #[serde(default)]
            origin: Option<String>,
            #[serde(default)]
            birthday: Option<String>,
        }
        let w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("enroll_seed: {e}")),
        };
        let key = match w.unlock_key.map(Zeroizing::new).as_deref().map(|k| hex::decode(k.trim())) {
            Some(Ok(bytes)) => Some(Zeroizing::new(bytes)),
            Some(Err(_)) => return err("enroll_seed: unlockKey is not hex"),
            None => None,
        };
        let holder = Holder { signer, seed: w.seed, kind: w.kind };
        let about = About { private_name: None, origin: w.origin, birthday: w.birthday };
        match self.wallets.store.enroll(holder, key.as_ref().map(|k| k.as_slice()), &w.name, about) {
            Ok(e) => {
                self.wallets.note(&e.seed);
                self.announce_wallets();
                json!({ "ok": true, "seed": e.seed, "new": e.new, "unlocked": e.unlocked }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn wallets(&mut self) -> String {
        if self.named_caller().is_none() {
            return not_authorized();
        }
        let list: Vec<_> = self
            .wallets
            .store
            .wallets()
            .into_iter()
            .map(|w| {
                let mut kinds: Vec<String> = w.holders.iter().map(|h| h.kind.clone()).collect();
                kinds.dedup();
                json!({ "seed": w.seed, "name": w.name, "locked": w.locked, "kinds": kinds,
                        "privateName": w.about.private_name })
            })
            .collect();
        json!({ "ok": true, "wallets": list }).to_string()
    }

    fn wallet_settings(&mut self) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        let store = &self.wallets.store;
        let factor = |f: &Factor| match f {
            Factor::Device => json!({ "kind": "device" }),
            Factor::Password(id) => json!({ "kind": "password", "id": id, "name": store.password_name(id) }),
        };
        let wallets: Vec<_> = store
            .wallets()
            .into_iter()
            .map(|w| {
                let ways: Vec<_> = w
                    .ways
                    .iter()
                    .map(|(id, factors)| json!({ "id": id, "factors": factors.iter().map(factor).collect::<Vec<_>>() }))
                    .collect();
                let always = w.ways.iter().any(|(_, f)| f.is_empty());
                json!({ "seed": w.seed, "name": w.name, "privateName": w.about.private_name, "locked": w.locked,
                        "holders": w.holders, "device": w.device, "index": w.index, "generation": w.generation,
                        "ways": ways, "alwaysUnlocked": always, "origin": w.about.origin, "birthday": w.about.birthday })
            })
            .collect();
        let passwords: Vec<_> = store
            .passwords()
            .into_iter()
            .map(|(id, name, used)| json!({ "id": id, "name": name, "wallets": used }))
            .collect();
        json!({ "ok": true, "wallets": wallets, "passwords": passwords }).to_string()
    }

    fn unlock_wallet(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            #[serde(default)]
            seed: String,
            #[serde(default)]
            way: String,
            #[serde(default)]
            handle: Option<String>,
            #[serde(flatten)]
            step: StepWire,
        }
        let mut w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("unlock_wallet: {e}")),
        };
        self.refresh();
        let (holder, secret, passwords) = w.step.take();
        let r = match w.handle {
            Some(h) => self.wallets.retry(&h, passwords),
            None => {
                let then = Then::Unlock { way: w.way };
                self.wallets.begin(&mut self.signers, &w.seed, then, holder.as_deref(), secret, passwords)
            }
        };
        let reply = begun(r);
        self.announce_wallets();
        reply
    }

    fn unlock_progress(&mut self, handle: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        self.refresh();
        match self.wallets.progress(&mut self.signers, &handle) {
            Ok(mut v) => {
                v["ok"] = true.into();
                v.to_string()
            }
            Err(_) => not_authorized(),
        }
    }

    fn cancel_unlock(&mut self, handle: String) -> bool {
        self.is_approver() && self.wallets.cancel(&mut self.signers, &handle).is_ok()
    }

    fn lock_wallets(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            #[serde(default)]
            seeds: Option<Vec<String>>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("lock_wallets: {e}")),
        };
        let locked = self.wallets.lock(&mut self.signers, w.seeds.as_deref());
        // Their signers drop the accounts they read under those keys: read them again.
        self.signers.forget(&self.roles.signers.clone());
        emit_wallets_locked(locked as i64);
        json!({ "ok": true, "locked": locked }).to_string()
    }

    fn set_rule(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        struct Wire {
            seed: String,
            ways: Vec<Vec<String>>,
            #[serde(flatten)]
            step: StepWire,
        }
        let mut w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("set_rule: {e}")),
        };
        let ways: crate::Result<Vec<Vec<Factor>>> =
            w.ways.iter().map(|way| way.iter().map(|f| Factor::parse(f)).collect()).collect();
        let ways = match ways {
            Ok(ways) => ways,
            Err(e) => return manager_err(&e),
        };
        self.refresh();
        let (holder, secret, passwords) = w.step.take();
        let then = Then::SetRule { ways };
        let reply = begun(self.wallets.begin(&mut self.signers, &w.seed, then, holder.as_deref(), secret, passwords));
        self.announce_wallets();
        reply
    }

    fn change_keys(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Wire {
            seed: String,
            #[serde(default)]
            new_index: bool,
            #[serde(flatten)]
            step: StepWire,
        }
        let mut w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("change_keys: {e}")),
        };
        let new_index = match (w.new_index, self.wallets.store.index(&w.seed)) {
            (false, _) => None,
            (true, Ok(i)) => Some(i + 1),
            (true, Err(e)) => return manager_err(&e),
        };
        self.refresh();
        let (holder, secret, passwords) = w.step.take();
        let then = Then::ChangeKeys { new_index };
        let reply = begun(self.wallets.begin(&mut self.signers, &w.seed, then, holder.as_deref(), secret, passwords));
        self.announce_wallets();
        reply
    }

    fn set_names(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            seed: String,
            #[serde(default)]
            name: Option<String>,
            #[serde(default)]
            private_name: Option<String>,
        }
        let w: Wire = match serde_json::from_str(&params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("set_names: {e}")),
        };
        let private = w.private_name.as_deref().map(|p| Some(p).filter(|p| !p.trim().is_empty()));
        match self.wallets.store.set_names(&w.seed, w.name.as_deref(), private) {
            Ok(()) => {
                self.wallets.note(&w.seed);
                self.announce_wallets();
                json!({ "ok": true }).to_string()
            }
            Err(e) => manager_err(&e),
        }
    }

    fn create_password(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: String,
            password: String,
        }
        let w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("create_password: {e}")),
        };
        let password = Zeroizing::new(w.password);
        match self.wallets.store.create_password(&w.name, &password) {
            Ok(id) => json!({ "ok": true, "id": id }).to_string(),
            Err(e) => manager_err(&e),
        }
    }

    fn rename_password(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: String,
            name: String,
        }
        match serde_json::from_str::<Wire>(&params_json) {
            Ok(w) => match self.wallets.store.rename_password(&w.id, &w.name) {
                Ok(()) => json!({ "ok": true }).to_string(),
                Err(e) => manager_err(&e),
            },
            Err(e) => err(format!("rename_password: {e}")),
        }
    }

    fn change_password(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: String,
            old: String,
            new: String,
        }
        let w: Wire = match secret_params(params_json) {
            Ok(w) => w,
            Err(e) => return err(format!("change_password: {e}")),
        };
        let (old, new) = (Zeroizing::new(w.old), Zeroizing::new(w.new));
        match self.wallets.store.change_password(&w.id, &old, &new) {
            Ok(()) => json!({ "ok": true }).to_string(),
            Err(e) => manager_err(&e),
        }
    }

    fn remove_password(&mut self, params_json: String) -> String {
        if !self.is_approver() {
            return not_authorized();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            id: String,
        }
        match serde_json::from_str::<Wire>(&params_json) {
            Ok(w) => match self.wallets.store.remove_password(&w.id) {
                Ok(()) => json!({ "ok": true }).to_string(),
                Err(e) => manager_err(&e),
            },
            Err(e) => err(format!("remove_password: {e}")),
        }
    }

    fn caller_identity(&mut self) -> String {
        let c = logos_rust_sdk::current_caller();
        let (kind, name) = match &c {
            logos_rust_sdk::LogosCaller::Unknown => ("unknown", String::new()),
            logos_rust_sdk::LogosCaller::HostAnchor => ("host", String::new()),
            logos_rust_sdk::LogosCaller::Module { name, .. } => ("module", name.clone()),
            logos_rust_sdk::LogosCaller::Derived { parent, leaf } => ("derived", format!("{parent}.{leaf}")),
            logos_rust_sdk::LogosCaller::Operator { name } => ("operator", name.clone()),
        };
        // The whole configuration, so an approver can build a `configure` that keeps it: it is total.
        json!({ "ok": true, "kind": kind, "identity": name, "approvers": self.roles.approvers,
                "custodians": self.roles.custodians, "signers": self.roles.signers })
        .to_string()
    }
}

impl SignerManagerModule for SignerManagerModuleImpl {
    fn on_context_ready(&self, ctx: &RustModuleContext) {
        self.core().on_context_ready(ctx)
    }

    fn ack_result(&self, handle: String, receipt: String) -> bool {
        self.core().ack_result(handle, receipt)
    }

    fn cancel_approval(&self, handle: String, receipt: String) -> bool {
        self.core().cancel_approval(handle, receipt)
    }

    fn reject(&self, handle: String) -> bool {
        self.core().reject(handle)
    }

    fn reject_access(&self, handle: String) -> bool {
        self.core().reject_access(handle)
    }

    fn configure(&self, config_json: String) -> String {
        self.core().configure(config_json)
    }

    fn request_approval(&self, intent_json: String) -> String {
        self.core().request_approval(intent_json)
    }

    fn approval_status(&self, handle: String, receipt: String) -> String {
        self.core().approval_status(handle, receipt)
    }

    fn fetch_result(&self, handle: String, receipt: String) -> String {
        self.core().fetch_result(handle, receipt)
    }

    fn pending(&self) -> String {
        self.core().pending()
    }

    fn acknowledge(&self, handle: String) -> String {
        self.core().acknowledge(handle)
    }

    fn choose_signer(&self, handle: String, bundle_id: String, signer: String) -> String {
        self.core().choose_signer(handle, bundle_id, signer)
    }

    fn approval_signers(&self, handle: String) -> String {
        self.core().approval_signers(handle)
    }

    fn roster(&self) -> String {
        self.core().roster()
    }

    fn approve(&self, handle: String, bundle_id: String, password: String) -> String {
        self.core().approve(handle, bundle_id, password)
    }

    fn request_open(&self, params_json: String) -> String {
        self.core().request_open(params_json)
    }

    fn request_unlock(&self, params_json: String) -> String {
        self.core().request_unlock(params_json)
    }

    fn access_requests(&self) -> String {
        self.core().access_requests()
    }

    fn acknowledge_access(&self, handle: String) -> String {
        self.core().acknowledge_access(handle)
    }

    fn approve_access(&self, params_json: String) -> String {
        self.core().approve_access(params_json)
    }

    fn account_descriptors(&self, group: String) -> String {
        self.core().account_descriptors(group)
    }

    fn close_account(&self, params_json: String) -> String {
        self.core().close_account(params_json)
    }

    fn open_accounts(&self) -> String {
        self.core().open_accounts()
    }

    fn unlock(&self, params_json: String) -> String {
        self.core().unlock(params_json)
    }

    fn lock(&self, params_json: String) -> String {
        self.core().lock(params_json)
    }

    fn unlocked(&self) -> String {
        self.core().unlocked()
    }

    fn unattended_signatures(&self) -> String {
        self.core().unattended_signatures()
    }

    fn accounts(&self) -> String {
        self.core().accounts()
    }

    fn signers(&self) -> String {
        self.core().signers()
    }

    fn caller_identity(&self) -> String {
        self.core().caller_identity()
    }

    fn wallets(&self) -> String {
        self.core().wallets()
    }

    fn data_key(&self, params_json: String) -> String {
        self.core().data_key(params_json)
    }

    fn enroll_seed(&self, params_json: String) -> String {
        self.core().enroll_seed(params_json)
    }

    fn wallet_settings(&self) -> String {
        self.core().wallet_settings()
    }

    fn unlock_wallet(&self, params_json: String) -> String {
        self.core().unlock_wallet(params_json)
    }

    fn unlock_progress(&self, handle: String) -> String {
        self.core().unlock_progress(handle)
    }

    fn cancel_unlock(&self, handle: String) -> bool {
        self.core().cancel_unlock(handle)
    }

    fn lock_wallets(&self, params_json: String) -> String {
        self.core().lock_wallets(params_json)
    }

    fn set_rule(&self, params_json: String) -> String {
        self.core().set_rule(params_json)
    }

    fn change_keys(&self, params_json: String) -> String {
        self.core().change_keys(params_json)
    }

    fn set_names(&self, params_json: String) -> String {
        self.core().set_names(params_json)
    }

    fn create_password(&self, params_json: String) -> String {
        self.core().create_password(params_json)
    }

    fn rename_password(&self, params_json: String) -> String {
        self.core().rename_password(params_json)
    }

    fn change_password(&self, params_json: String) -> String {
        self.core().change_password(params_json)
    }

    fn remove_password(&self, params_json: String) -> String {
        self.core().remove_password(params_json)
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<SignerManagerModuleImpl>();
}
