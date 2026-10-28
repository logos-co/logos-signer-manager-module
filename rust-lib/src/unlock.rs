//! Each wallet's seed and the keys its data is kept under. A seed unlocks once per session by one of
//! its ways in, each a set of factors that must all be there: the unlock key any holder of the seed
//! gives, and named passwords. The seed key that unwraps derives each module's own keys.
//!
//! `<persistence>/unlock/` keeps `seeds.json` and `passwords.json`, the directory 0700 and the files
//! 0600. Nothing in them opens without the factors; the keys live in memory until locked.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use logos_signer_interface::{ErrorCode, SignerError};

use crate::error::{bad, ManagerError, Result};
use crate::evm::check_displayable;

const UNLOCK_SALT: &[u8] = b"logos/unlock/v1";
const DATA_SALT: &[u8] = b"logos/data/v1";
/// The manager's own name in its module keys, for what it seals under a seed.
const MANAGER: &str = "signer_manager_module";
/// `data_key`'s target for the key any unlocked seed opens.
pub const PROFILE: &str = "profile";
const MAX_WAYS: usize = 8;
const MAX_NAME: usize = 64;
const VERSION: u32 = 1;

pub type Key = Zeroizing<[u8; 32]>;

fn random_key() -> Key {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::thread_rng().fill_bytes(k.as_mut());
    k
}

fn random_id(prefix: &str) -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    format!("{prefix}{}", hex::encode(b))
}

fn signer_error(code: ErrorCode, msg: impl Into<String>) -> ManagerError {
    ManagerError::Signer(SignerError::new(code, msg))
}

fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8]) -> Key {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(salt), ikm).expand(info, out.as_mut()).expect("32 bytes is a valid HKDF length");
    out
}

fn aad(parts: &[&str]) -> Vec<u8> {
    parts.join("\0").into_bytes()
}

fn cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new(&(*key).into())
}

/// `nonce ‖ ciphertext`, as hex.
fn seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> String {
    let nonce = XChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
    let ct = cipher(key).encrypt(&nonce, Payload { msg: plain, aad }).expect("encrypting in memory");
    let mut out = nonce.to_vec();
    out.extend(ct);
    hex::encode(out)
}

fn unseal(key: &[u8; 32], sealed: &str, aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let bytes = hex::decode(sealed).ok()?;
    if bytes.len() < 24 + 16 {
        return None;
    }
    let (nonce, ct) = bytes.split_at(24);
    let nonce: [u8; 24] = nonce.try_into().ok()?;
    cipher(key).decrypt(&XNonce::from(nonce), Payload { msg: ct, aad }).ok().map(Zeroizing::new)
}

fn unseal_key(key: &[u8; 32], sealed: &str, aad: &[u8]) -> Option<Key> {
    let plain = unseal(key, sealed, aad)?;
    let k: [u8; 32] = plain.as_slice().try_into().ok()?;
    Some(Zeroizing::new(k))
}

/// The key `module` keeps `scope` under, from a seed key of generation `generation` or the profile key.
fn module_key(root: &[u8; 32], module: &str, scope: &str, generation: u32) -> Key {
    hkdf(DATA_SALT, root, format!("{module}\0{scope}\0{generation}").as_bytes())
}

/// What an unlock key hashes to: names its seed without revealing it.
fn check_of(unlock_key: &[u8]) -> String {
    hex::encode(&hkdf(UNLOCK_SALT, unlock_key, b"check")[..16])
}

fn check_name(name: &str, what: &str) -> Result<String> {
    let name = name.trim();
    check_displayable(name, what)?;
    if name.is_empty() || name.chars().count() > MAX_NAME {
        return Err(bad(format!("{what}: 1 to {MAX_NAME} characters")));
    }
    Ok(name.to_string())
}

/// One part of a way in.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Factor {
    /// The seed's unlock key, from any of its holders.
    Device,
    /// A named password, by its id.
    Password(String),
}

impl Factor {
    pub fn label(&self) -> String {
        match self {
            Factor::Device => "device".into(),
            Factor::Password(id) => format!("password:{id}"),
        }
    }

    pub fn parse(s: &str) -> Result<Factor> {
        match s.trim() {
            "device" => Ok(Factor::Device),
            other => other
                .strip_prefix("password:")
                .filter(|id| id.starts_with("p_") && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_'))
                .map(|id| Factor::Password(id.to_string()))
                .ok_or_else(|| bad(format!("factor: {other:?} is neither \"device\" nor \"password:<id>\""))),
        }
    }
}

impl Serialize for Factor {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.label())
    }
}

impl<'de> Deserialize<'de> for Factor {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Factor::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A holder of a seed: a signer module, and the seed as it names it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Holder {
    pub signer: String,
    pub seed: String,
    /// The signer's kind: `keystore`, `keycard`, `keycard_shell`, `qr`.
    pub kind: String,
}

/// What only an unlock shows, sealed under the seed key.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct About {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_name: Option<String>,
    /// `created` when the signer made the seed, so it has no history; else `restored`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<String>,
    /// The seed's first possible day, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub birthday: Option<String>,
}

impl About {
    fn is_empty(&self) -> bool {
        self.private_name.is_none() && self.origin.is_none() && self.birthday.is_none()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Way {
    id: String,
    factors: Vec<Factor>,
    /// The seed key under this way's key.
    wrapped: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SeedRecord {
    id: String,
    name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    about: Option<String>,
    holders: Vec<Holder>,
    /// The device ways take the unlock key at `m/1280263247'/index'`.
    index: u32,
    /// The check of the unlock key at index 0: another holder of the same seed joins it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    identity: Option<String>,
    /// The check of the unlock key at `index`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    check: Option<String>,
    ways: Vec<Way>,
    generation: u32,
    /// Every earlier seed key, each under the next: `chain[g]` is generation `g`'s.
    #[serde(default)]
    chain: Vec<String>,
    /// The profile key under this seed's key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    profile: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PasswordRecord {
    id: String,
    name: String,
    salt: String,
    log_n: u8,
    r: u32,
    p: u32,
    /// The password's own key under its scrypt output: changing the password rewraps only this.
    wrapped: String,
}

#[derive(Default, Serialize, Deserialize)]
struct SeedsFile {
    version: u32,
    seeds: Vec<SeedRecord>,
}

#[derive(Default, Serialize, Deserialize)]
struct PasswordsFile {
    version: u32,
    passwords: Vec<PasswordRecord>,
}

/// scrypt's cost for new passwords.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cost {
    pub log_n: u8,
    pub r: u32,
    pub p: u32,
}

impl Default for Cost {
    fn default() -> Self {
        Cost { log_n: 17, r: 8, p: 1 }
    }
}

/// What a person gave for one operation: the unlock key a holder answered, and typed passwords.
#[derive(Default)]
pub struct Secrets {
    pub device: Option<Zeroizing<Vec<u8>>>,
    pub passwords: BTreeMap<String, Zeroizing<String>>,
}

/// A wallet as the Signer app shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WalletView {
    pub seed: String,
    pub name: String,
    pub locked: bool,
    pub holders: Vec<Holder>,
    /// Its holders give an unlock key: a way in may take the device.
    pub device: bool,
    pub index: u32,
    pub generation: u32,
    pub ways: Vec<(String, Vec<Factor>)>,
    /// Empty while locked.
    pub about: About,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Enrolled {
    pub seed: String,
    pub new: bool,
    pub unlocked: bool,
}

#[derive(Default)]
pub struct Unlock {
    dir: Option<PathBuf>,
    seeds: Vec<SeedRecord>,
    passwords: Vec<PasswordRecord>,
    /// Unlocked seeds' current keys.
    open: BTreeMap<String, Key>,
    profile: Option<Key>,
    cost: Cost,
    /// Why the files couldn't be read; nothing is written while set.
    broken: Option<String>,
}

fn read_json<T: Default + serde::de::DeserializeOwned>(path: &Path) -> std::result::Result<T, String> {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

/// Staged beside it at 0600 from creation, synced, renamed over it.
fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut salt = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut salt);
    let staged = dir.join(format!(".{name}.{}.tmp", hex::encode(salt)));
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let written = (|| {
        let mut f = opts.open(&staged)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        std::fs::rename(&staged, dir.join(name))
    })();
    if written.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    written
}

impl Unlock {
    /// Nothing on disk: for tests.
    pub fn in_memory() -> Self {
        Self::default()
    }

    /// Before the module knows where its files are: everything is refused.
    pub fn not_ready() -> Self {
        Unlock { broken: Some("the module has not started yet".into()), ..Default::default() }
    }

    /// The store in `dir`. Files that can't be read leave it refusing everything, so nothing
    /// overwrites them.
    pub fn load(dir: PathBuf) -> Self {
        let seeds = read_json::<SeedsFile>(&dir.join("seeds.json"));
        let passwords = read_json::<PasswordsFile>(&dir.join("passwords.json"));
        let mut u = Unlock { dir: Some(dir), ..Default::default() };
        match (seeds, passwords) {
            (Ok(s), Ok(p)) if s.version <= VERSION && p.version <= VERSION => {
                u.seeds = s.seeds;
                u.passwords = p.passwords;
                u.open_always();
            }
            (Ok(_), Ok(_)) => u.broken = Some("the unlock files are from a newer version".into()),
            (Err(e), _) | (_, Err(e)) => u.broken = Some(e),
        }
        u
    }

    pub fn with_cost(mut self, cost: Cost) -> Self {
        self.cost = cost;
        self
    }

    fn usable(&self) -> Result<()> {
        match &self.broken {
            Some(why) => Err(ManagerError::Signing(format!("the unlock store can't be read: {why}"))),
            None => Ok(()),
        }
    }

    fn save(&self) -> Result<()> {
        self.usable()?;
        let Some(dir) = &self.dir else { return Ok(()) };
        let io = |e: std::io::Error| ManagerError::Signing(format!("writing the unlock store: {e}"));
        std::fs::create_dir_all(dir).map_err(io)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(io)?;
        }
        let encode = |e: serde_json::Error| ManagerError::Signing(e.to_string());
        let seeds = serde_json::to_vec_pretty(&SeedsFile { version: VERSION, seeds: self.seeds.clone() }).map_err(encode)?;
        let passwords =
            serde_json::to_vec_pretty(&PasswordsFile { version: VERSION, passwords: self.passwords.clone() }).map_err(encode)?;
        write_private(dir, "seeds.json", &seeds).map_err(io)?;
        write_private(dir, "passwords.json", &passwords).map_err(io)
    }

    fn record(&self, seed: &str) -> Result<&SeedRecord> {
        self.usable()?;
        self.seeds
            .iter()
            .find(|s| s.id == seed.trim())
            .ok_or_else(|| ManagerError::NotFound(format!("no wallet {}", seed.trim())))
    }

    fn record_mut(&mut self, seed: &str) -> Result<&mut SeedRecord> {
        self.usable()?;
        self.seeds
            .iter_mut()
            .find(|s| s.id == seed.trim())
            .ok_or_else(|| ManagerError::NotFound(format!("no wallet {}", seed.trim())))
    }

    fn key_of(&self, seed: &str) -> Result<&Key> {
        let name = &self.record(seed)?.name;
        self.open.get(seed.trim()).ok_or_else(|| signer_error(ErrorCode::Locked, format!("{name} is locked")))
    }

    fn password(&self, id: &str) -> Result<&PasswordRecord> {
        self.passwords
            .iter()
            .find(|p| p.id == id)
            .ok_or_else(|| ManagerError::NotFound(format!("no password {id}")))
    }

    /// The manager's seed for an account a signer lists under its own name for the seed.
    pub fn seed_of(&self, signer: &str, recogniser: &str) -> Option<String> {
        self.seeds
            .iter()
            .find(|s| s.holders.iter().any(|h| h.signer == signer && h.seed == recogniser))
            .map(|s| s.id.clone())
    }

    /// The seed a caller names: one of the manager's, or, from one of its holders, the seed as
    /// that holder names it.
    pub fn resolve(&self, caller: &str, named: &str) -> String {
        let named = named.trim();
        if named == PROFILE || self.seeds.iter().any(|s| s.id == named) {
            return named.to_string();
        }
        self.seed_of(caller, named).unwrap_or_else(|| named.to_string())
    }

    pub fn is_unlocked(&self, seed: &str) -> bool {
        self.open.contains_key(seed.trim())
    }

    pub fn holders(&self, seed: &str) -> Result<Vec<Holder>> {
        Ok(self.record(seed)?.holders.clone())
    }

    pub fn index(&self, seed: &str) -> Result<u32> {
        Ok(self.record(seed)?.index)
    }

    /// The factors of one of a seed's ways in.
    pub fn way(&self, seed: &str, way: &str) -> Result<Vec<Factor>> {
        self.record(seed)?
            .ways
            .iter()
            .find(|w| w.id == way.trim())
            .map(|w| w.factors.clone())
            .ok_or_else(|| ManagerError::NotFound(format!("no way in {}", way.trim())))
    }

    /// Does any way in of this seed take its device?
    pub fn takes_device(&self, seed: &str) -> Result<bool> {
        Ok(self.record(seed)?.ways.iter().any(|w| w.factors.contains(&Factor::Device)))
    }

    /// Of these ways, the ones the seed doesn't have yet take its device.
    pub fn new_ways_take_device(&self, seed: &str, ways: &[Vec<Factor>]) -> Result<bool> {
        let rec = self.record(seed)?;
        Ok(normalise(ways)?
            .iter()
            .any(|w| w.contains(&Factor::Device) && !rec.ways.iter().any(|old| &old.factors == w)))
    }

    fn password_key(&self, id: &str, typed: &str) -> Result<Key> {
        let rec = self.password(id)?;
        let kek = scrypt_key(typed, rec)?;
        unseal_key(&kek, &rec.wrapped, &aad(&["password", &rec.id]))
            .ok_or_else(|| signer_error(ErrorCode::WrongSecret, format!("the password \"{}\" is not correct", rec.name)))
    }

    /// Each factor's key: the device's unlock key, checked when the seed knows what it hashes to,
    /// and each password's own key.
    fn factor_keys(&self, rec: &SeedRecord, factors: &[Factor], secrets: &Secrets, check: Option<&str>) -> Result<Vec<(Factor, Zeroizing<Vec<u8>>)>> {
        let mut out = Vec::new();
        for f in factors {
            let secret = match f {
                Factor::Device => {
                    let u = secrets.device.as_ref().ok_or_else(|| bad(format!("unlocking {} needs its device", rec.name)))?;
                    logos_signer_interface::unlock::check_unlock_key(&hex::encode(u.as_slice()))?;
                    if check.is_some_and(|c| c != check_of(u)) {
                        return Err(signer_error(ErrorCode::WrongSeed, "this device holds another seed"));
                    }
                    u.clone()
                }
                Factor::Password(id) => {
                    let name = &self.password(id)?.name;
                    let typed = secrets.passwords.get(id).ok_or_else(|| bad(format!("type the password \"{name}\"")))?;
                    Zeroizing::new(self.password_key(id, typed)?.to_vec())
                }
            };
            out.push((f.clone(), secret));
        }
        Ok(out)
    }

    /// A seed registers when a signer adds it, while the holder's unlock key is at hand: a new seed
    /// starts with "device only", or none for a holder that gives no unlock key, and is unlocked.
    /// A seed already known by its holder or its unlock key gains the holder.
    pub fn enroll(&mut self, holder: Holder, unlock_key: Option<&[u8]>, name: &str, about: About) -> Result<Enrolled> {
        self.usable()?;
        if holder.signer.trim().is_empty() || holder.seed.trim().is_empty() {
            return Err(bad("enroll: a holder names its signer and its seed"));
        }
        check_displayable(&holder.seed, "seed")?;
        if let Some(u) = unlock_key {
            logos_signer_interface::unlock::check_unlock_key(&hex::encode(u))?;
        }
        let name = check_name(name, "name")?;
        let about = check_about(about)?;
        let identity = unlock_key.map(check_of);
        let known = self.seeds.iter().position(|s| {
            s.holders.iter().any(|h| h.signer == holder.signer && h.seed == holder.seed)
                || (identity.is_some() && s.identity == identity)
        });
        if let Some(i) = known {
            let rec = &mut self.seeds[i];
            if !rec.holders.contains(&holder) {
                rec.holders.retain(|h| h.signer != holder.signer || h.seed != holder.seed);
                rec.holders.push(holder);
            }
            if rec.identity.is_none() && rec.index == 0 {
                rec.identity = identity.clone();
                rec.check = identity.clone();
            }
            let id = rec.id.clone();
            let device_only = (rec.index == 0).then(|| rec.ways.iter().find(|w| w.factors == [Factor::Device])).flatten();
            let device_only = device_only.map(|w| w.id.clone());
            // The unlock key at index 0 opens a known seed whose rule is still "device only".
            if let (Some(u), Some(way), false) = (unlock_key, device_only, self.open.contains_key(&id)) {
                let secrets = Secrets { device: Some(Zeroizing::new(u.to_vec())), ..Default::default() };
                let _ = self.unlock(&id, &way, &secrets);
            }
            self.save()?;
            return Ok(Enrolled { unlocked: self.open.contains_key(&id), seed: id, new: false });
        }
        let id = random_id("s_");
        let key = random_key();
        let mut rec = SeedRecord {
            id: id.clone(),
            name,
            about: None,
            holders: vec![holder],
            index: 0,
            identity: identity.clone(),
            check: identity,
            ways: Vec::new(),
            generation: 0,
            chain: Vec::new(),
            profile: None,
        };
        if let Some(u) = unlock_key {
            let secrets = Secrets { device: Some(Zeroizing::new(u.to_vec())), ..Default::default() };
            let keys = self.factor_keys(&rec, &[Factor::Device], &secrets, None)?;
            rec.ways.push(wrap_way(&rec, random_id("w_"), keys, &key));
        }
        if !about.is_empty() {
            rec.about = Some(seal_about(&rec, &key, &about));
        }
        if self.profile.is_none() && !self.seeds.iter().any(|s| s.profile.is_some()) {
            self.profile = Some(random_key());
        }
        if let Some(p) = &self.profile {
            rec.profile = Some(seal(&key, p.as_ref(), &aad(&["profile", &id, "0"])));
        }
        self.seeds.push(rec);
        self.open.insert(id.clone(), key);
        self.save()?;
        Ok(Enrolled { seed: id, new: true, unlocked: true })
    }

    /// Unlock a seed by one of its ways in.
    pub fn unlock(&mut self, seed: &str, way: &str, secrets: &Secrets) -> Result<()> {
        let rec = self.record(seed)?.clone();
        let w = rec.ways.iter().find(|w| w.id == way.trim()).ok_or_else(|| ManagerError::NotFound(format!("no way in {}", way.trim())))?;
        let keys = self.factor_keys(&rec, &w.factors, secrets, rec.check.as_deref())?;
        let kek = way_kek(&keys);
        let key = unseal_key(&kek, &w.wrapped, &way_aad(&rec, &w.id))
            .ok_or_else(|| signer_error(ErrorCode::WrongSeed, format!("this doesn't unlock {}", rec.name)))?;
        self.open.insert(rec.id.clone(), key);
        self.share_profile()
    }

    /// Open every always-unlocked seed that isn't open: its way in takes nothing.
    fn open_always(&mut self) {
        let free: Vec<(String, String)> = self
            .seeds
            .iter()
            .filter(|s| !self.open.contains_key(&s.id))
            .filter_map(|s| s.ways.iter().find(|w| w.factors.is_empty()).map(|w| (s.id.clone(), w.id.clone())))
            .collect();
        for (seed, way) in free {
            let _ = self.unlock(&seed, &way, &Secrets::default());
        }
    }

    /// The profile key from the first unlocked seed that has it, wrapped into every unlocked seed
    /// that doesn't yet.
    fn share_profile(&mut self) -> Result<()> {
        if self.profile.is_none() {
            self.profile = self.seeds.iter().find_map(|s| {
                let k = self.open.get(&s.id)?;
                unseal_key(k, s.profile.as_deref()?, &aad(&["profile", &s.id, &s.generation.to_string()]))
            });
        }
        let Some(p) = self.profile.clone() else { return Ok(()) };
        let mut changed = false;
        for s in &mut self.seeds {
            if let (None, Some(k)) = (&s.profile, self.open.get(&s.id)) {
                s.profile = Some(seal(k, p.as_ref(), &aad(&["profile", &s.id, &s.generation.to_string()])));
                changed = true;
            }
        }
        if changed {
            self.save()?;
        }
        Ok(())
    }

    /// Forget these seeds' keys, or every one's; the profile key goes with the last. An
    /// always-unlocked seed stays open.
    pub fn lock(&mut self, seeds: Option<&[String]>) -> usize {
        let before = self.open.len();
        let always: Vec<String> = self.seeds.iter().filter(|s| always_unlocked(s)).map(|s| s.id.clone()).collect();
        match seeds {
            Some(list) => self.open.retain(|id, _| always.contains(id) || !list.iter().any(|s| s.trim() == id)),
            None => self.open.retain(|id, _| always.contains(id)),
        }
        if self.open.is_empty() {
            self.profile = None;
        }
        before - self.open.len()
    }

    /// The key `module` keeps `scope` under, for a seed or the profile, at a generation (the
    /// current one by default): `(key, generation)`.
    pub fn data_key(&self, module: &str, target: &str, scope: &str, generation: Option<u32>) -> Result<(Key, u32)> {
        self.usable()?;
        check_label(module, "module")?;
        check_label(scope, "scope")?;
        if target.trim() == PROFILE {
            let p = self.profile.as_ref().ok_or_else(|| signer_error(ErrorCode::Locked, "every wallet is locked"))?;
            if generation.is_some_and(|g| g != 0) {
                return Err(bad("data_key: the profile has generation 0 only"));
            }
            return Ok((module_key(p, module, scope, 0), 0));
        }
        let rec = self.record(target)?;
        let g = generation.unwrap_or(rec.generation);
        if g > rec.generation {
            return Err(bad(format!("data_key: {} has no generation {g}", rec.name)));
        }
        let root = generation_key(rec, self.key_of(target)?, g)?;
        Ok((module_key(&root, module, scope, g), g))
    }

    /// The private name, origin and birthday of an unlocked seed.
    pub fn about(&self, seed: &str) -> Result<About> {
        let rec = self.record(seed)?;
        let key = self.key_of(seed)?;
        Ok(match &rec.about {
            Some(sealed) => {
                let k = module_key(key, MANAGER, "about", rec.generation);
                let plain = unseal(&k, sealed, &aad(&["about", &rec.id])).ok_or_else(|| ManagerError::Signing("the wallet's sealed details don't open".into()))?;
                serde_json::from_slice(&plain).map_err(|e| ManagerError::Signing(e.to_string()))?
            }
            None => About::default(),
        })
    }

    pub fn wallets(&self) -> Vec<WalletView> {
        if self.broken.is_some() {
            return Vec::new();
        }
        self.seeds
            .iter()
            .map(|s| WalletView {
                seed: s.id.clone(),
                name: s.name.clone(),
                locked: !self.open.contains_key(&s.id),
                holders: s.holders.clone(),
                device: s.identity.is_some(),
                index: s.index,
                generation: s.generation,
                ways: s.ways.iter().map(|w| (w.id.clone(), w.factors.clone())).collect(),
                about: self.about(&s.id).unwrap_or_default(),
            })
            .collect()
    }

    /// Every password: `(id, name, the seeds whose ways take it)`.
    pub fn passwords(&self) -> Vec<(String, String, Vec<String>)> {
        self.passwords
            .iter()
            .map(|p| {
                let used = self
                    .seeds
                    .iter()
                    .filter(|s| s.ways.iter().any(|w| w.factors.contains(&Factor::Password(p.id.clone()))))
                    .map(|s| s.id.clone())
                    .collect();
                (p.id.clone(), p.name.clone(), used)
            })
            .collect()
    }

    pub fn password_name(&self, id: &str) -> Option<String> {
        self.password(id).ok().map(|p| p.name.clone())
    }

    /// Replace an unlocked seed's ways in. A way it already has keeps its wrapping; a new one needs
    /// its factors: the device's unlock key, each password typed.
    pub fn set_rule(&mut self, seed: &str, ways: &[Vec<Factor>], secrets: &Secrets) -> Result<()> {
        let rec = self.record(seed)?.clone();
        let key = self.key_of(seed)?.clone();
        let ways = normalise(ways)?;
        for w in &ways {
            for f in w {
                match f {
                    Factor::Device if rec.identity.is_none() => {
                        return Err(bad(format!("{}'s holders give no unlock key: it unlocks by password", rec.name)));
                    }
                    Factor::Password(id) => {
                        self.password(id)?;
                    }
                    Factor::Device => {}
                }
            }
        }
        let mut next = Vec::new();
        for w in ways {
            match rec.ways.iter().find(|old| old.factors == w) {
                Some(old) => next.push(old.clone()),
                None => {
                    let keys = self.factor_keys(&rec, &w, secrets, rec.check.as_deref())?;
                    next.push(wrap_way(&rec, random_id("w_"), keys, &key));
                }
            }
        }
        self.record_mut(seed)?.ways = next;
        // Its key sat where anyone could read it: a protected rule starts from a new one.
        if always_unlocked(&rec) && !always_unlocked(self.record(seed)?) {
            if let Err(e) = self.change_keys(seed, None, secrets) {
                *self.record_mut(seed)? = rec;
                self.open.insert(seed.trim().to_string(), key);
                return Err(e);
            }
            return Ok(());
        }
        self.save()
    }

    /// A new seed key for an unlocked seed, optionally at a new unlock index: every way in is
    /// wrapped again, so each needs its factors. Earlier keys stay reachable through the chain.
    pub fn change_keys(&mut self, seed: &str, new_index: Option<u32>, secrets: &Secrets) -> Result<()> {
        let rec = self.record(seed)?.clone();
        let old = self.key_of(seed)?.clone();
        let index = match new_index {
            Some(i) if i <= rec.index || i >= 0x8000_0000 => {
                return Err(bad(format!("change_keys: the next unlock index is above {}", rec.index)));
            }
            Some(i) => i,
            None => rec.index,
        };
        // At a new index the device's key has no check yet: the signer refused another seed.
        let check = if new_index.is_some() { None } else { rec.check.clone() };
        let mut keys = Vec::new();
        for w in &rec.ways {
            keys.push(self.factor_keys(&rec, &w.factors, secrets, check.as_deref())?);
        }
        let about = self.about(seed)?;
        let profile = match &rec.profile {
            Some(sealed) => unseal_key(&old, sealed, &aad(&["profile", &rec.id, &rec.generation.to_string()])),
            None => None,
        };
        let key = random_key();
        let mut next = rec.clone();
        next.chain.push(seal(&key, old.as_ref(), &aad(&["chain", &rec.id, &rec.generation.to_string()])));
        next.generation += 1;
        next.index = index;
        next.check = match &secrets.device {
            Some(u) if rec.ways.iter().any(|w| w.factors.contains(&Factor::Device)) => Some(check_of(u)),
            _ if new_index.is_some() => None,
            _ => rec.check.clone(),
        };
        next.ways = rec.ways.iter().zip(keys).map(|(w, k)| wrap_way(&next, w.id.clone(), k, &key)).collect();
        next.about = (!about.is_empty()).then(|| seal_about(&next, &key, &about));
        next.profile = profile.map(|p| seal(&key, p.as_ref(), &aad(&["profile", &next.id, &next.generation.to_string()])));
        *self.record_mut(seed)? = next;
        self.open.insert(rec.id.clone(), key);
        self.save()
    }

    /// A seed's public name, shown while locked, and its private name, shown once unlocked.
    pub fn set_names(&mut self, seed: &str, name: Option<&str>, private_name: Option<Option<&str>>) -> Result<()> {
        let mut rec = self.record(seed)?.clone();
        if let Some(n) = name {
            rec.name = check_name(n, "name")?;
        }
        if let Some(private) = private_name {
            let key = self.key_of(seed)?.clone();
            let mut about = self.about(seed)?;
            about.private_name = match private.map(str::trim).filter(|p| !p.is_empty()) {
                Some(p) => Some(check_name(p, "private name")?),
                None => None,
            };
            rec.about = (!about.is_empty()).then(|| seal_about(&rec, &key, &about));
        }
        *self.record_mut(seed)? = rec;
        self.save()
    }

    pub fn create_password(&mut self, name: &str, typed: &str) -> Result<String> {
        self.usable()?;
        let name = check_name(name, "password name")?;
        if self.passwords.iter().any(|p| p.name.eq_ignore_ascii_case(&name)) {
            return Err(bad(format!("a password is already named \"{name}\"")));
        }
        check_typed(typed)?;
        let id = random_id("p_");
        let own = random_key();
        let rec = new_password_record(id.clone(), name, typed, &own, self.cost)?;
        self.passwords.push(rec);
        self.save()?;
        Ok(id)
    }

    pub fn rename_password(&mut self, id: &str, name: &str) -> Result<()> {
        self.usable()?;
        let name = check_name(name, "password name")?;
        if self.passwords.iter().any(|p| p.id != id && p.name.eq_ignore_ascii_case(&name)) {
            return Err(bad(format!("a password is already named \"{name}\"")));
        }
        self.password(id)?;
        if let Some(p) = self.passwords.iter_mut().find(|p| p.id == id) {
            p.name = name;
        }
        self.save()
    }

    /// The old password opens the password's own key, which the new one wraps: no wallet changes.
    pub fn change_password(&mut self, id: &str, old: &str, new: &str) -> Result<()> {
        self.usable()?;
        check_typed(new)?;
        let own = self.password_key(id, old)?;
        let name = self.password(id)?.name.clone();
        let rec = new_password_record(id.to_string(), name, new, &own, self.cost)?;
        if let Some(p) = self.passwords.iter_mut().find(|p| p.id == id) {
            *p = rec;
        }
        self.save()
    }

    /// Only a password no way in takes.
    pub fn remove_password(&mut self, id: &str) -> Result<()> {
        self.usable()?;
        self.password(id)?;
        let users: Vec<String> = self
            .seeds
            .iter()
            .filter(|s| s.ways.iter().any(|w| w.factors.contains(&Factor::Password(id.to_string()))))
            .map(|s| s.name.clone())
            .collect();
        if !users.is_empty() {
            return Err(bad(format!("the password unlocks {}: change their rules first", users.join(", "))));
        }
        self.passwords.retain(|p| p.id != id);
        self.save()
    }
}

/// Sorted factors per way, no repeats, no empty way, no way twice, at most [`MAX_WAYS`].
fn normalise(ways: &[Vec<Factor>]) -> Result<Vec<Vec<Factor>>> {
    if ways.is_empty() || ways.len() > MAX_WAYS {
        return Err(bad(format!("a wallet has 1 to {MAX_WAYS} ways in")));
    }
    // A way that takes nothing leaves the wallet always unlocked: any other way would mean nothing.
    if ways.iter().any(|w| w.is_empty()) {
        if ways.len() > 1 {
            return Err(bad("an always-unlocked wallet has no other way in"));
        }
        return Ok(vec![Vec::new()]);
    }
    let mut out: Vec<Vec<Factor>> = Vec::new();
    for w in ways {
        let mut w = w.clone();
        w.sort();
        w.dedup();
        if out.contains(&w) {
            return Err(bad("the same way in twice"));
        }
        out.push(w);
    }
    Ok(out)
}

/// A way in that takes nothing: the seed key is kept where anyone with the files can open it.
fn always_unlocked(rec: &SeedRecord) -> bool {
    rec.ways.iter().any(|w| w.factors.is_empty())
}

fn check_label(s: &str, what: &str) -> Result<()> {
    if s.is_empty() || s.len() > 128 || s.contains('\0') {
        return Err(bad(format!("data_key: {what} is 1 to 128 bytes, no NUL")));
    }
    check_displayable(s, what)
}

fn check_typed(typed: &str) -> Result<()> {
    if typed.is_empty() || typed.len() > 1024 {
        return Err(bad("a password is 1 to 1024 bytes"));
    }
    Ok(())
}

fn check_about(about: About) -> Result<About> {
    let day = |d: &str| d.len() == 10 && d.bytes().enumerate().all(|(i, c)| if i == 4 || i == 7 { c == b'-' } else { c.is_ascii_digit() });
    Ok(About {
        private_name: about.private_name.map(|n| check_name(&n, "private name")).transpose()?,
        origin: about.origin.filter(|o| o == "created" || o == "restored"),
        birthday: about.birthday.filter(|b| day(b)),
    })
}

fn scrypt_key(typed: &str, rec: &PasswordRecord) -> Result<Key> {
    if rec.log_n > 22 || rec.r == 0 || rec.p == 0 || rec.r.saturating_mul(rec.p) > 64 {
        return Err(ManagerError::Signing(format!("the password \"{}\" has unusable parameters", rec.name)));
    }
    let params = scrypt::Params::new(rec.log_n, rec.r, rec.p, 32).map_err(|e| ManagerError::Signing(e.to_string()))?;
    let salt = hex::decode(&rec.salt).map_err(|e| ManagerError::Signing(e.to_string()))?;
    let mut out = Zeroizing::new([0u8; 32]);
    scrypt::scrypt(typed.as_bytes(), &salt, &params, out.as_mut()).map_err(|e| ManagerError::Signing(e.to_string()))?;
    Ok(out)
}

fn new_password_record(id: String, name: String, typed: &str, own: &Key, cost: Cost) -> Result<PasswordRecord> {
    let mut salt = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut rec = PasswordRecord { id, name, salt: hex::encode(salt), log_n: cost.log_n, r: cost.r, p: cost.p, wrapped: String::new() };
    let kek = scrypt_key(typed, &rec)?;
    rec.wrapped = seal(&kek, own.as_ref(), &aad(&["password", &rec.id]));
    Ok(rec)
}

/// A way's key from its factors' keys, in a fixed order, each labelled and length-prefixed.
fn way_kek(keys: &[(Factor, Zeroizing<Vec<u8>>)]) -> Key {
    let mut sorted: Vec<&(Factor, Zeroizing<Vec<u8>>)> = keys.iter().collect();
    sorted.sort_by(|a, b| a.0.cmp(&b.0));
    let mut ikm = Zeroizing::new(Vec::new());
    for (f, secret) in sorted {
        ikm.extend_from_slice(f.label().as_bytes());
        ikm.push(0);
        ikm.extend_from_slice(&(secret.len() as u32).to_be_bytes());
        ikm.extend_from_slice(secret);
    }
    hkdf(UNLOCK_SALT, &ikm, b"way")
}

fn way_aad(rec: &SeedRecord, way: &str) -> Vec<u8> {
    aad(&["way", &rec.id, way, &rec.generation.to_string()])
}

fn wrap_way(rec: &SeedRecord, id: String, keys: Vec<(Factor, Zeroizing<Vec<u8>>)>, seed_key: &Key) -> Way {
    let kek = way_kek(&keys);
    let wrapped = seal(&kek, seed_key.as_ref(), &way_aad(rec, &id));
    let mut factors: Vec<Factor> = keys.into_iter().map(|(f, _)| f).collect();
    factors.sort();
    Way { id, factors, wrapped }
}

fn seal_about(rec: &SeedRecord, key: &Key, about: &About) -> String {
    let k = module_key(key, MANAGER, "about", rec.generation);
    let plain = Zeroizing::new(serde_json::to_vec(about).expect("About serialises"));
    seal(&k, &plain, &aad(&["about", &rec.id]))
}

/// Generation `g`'s seed key, from the current one down the chain.
fn generation_key(rec: &SeedRecord, current: &Key, g: u32) -> Result<Key> {
    let mut key = current.clone();
    for h in (g..rec.generation).rev() {
        let sealed = rec.chain.get(h as usize).ok_or_else(|| ManagerError::Signing(format!("{} misses generation {h}", rec.name)))?;
        key = unseal_key(&key, sealed, &aad(&["chain", &rec.id, &h.to_string()]))
            .ok_or_else(|| ManagerError::Signing(format!("{}'s generation {h} doesn't open", rec.name)))?;
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    /// A holder's unlock key: a compressed public key, distinct per `n`.
    fn u(n: u8) -> Vec<u8> {
        let sk = SecretKey::from_slice(&[n; 32]).unwrap();
        PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize().to_vec()
    }

    fn device(n: u8) -> Secrets {
        Secrets { device: Some(Zeroizing::new(u(n))), ..Default::default() }
    }

    fn typed(pairs: &[(&str, &str)]) -> Secrets {
        let passwords = pairs.iter().map(|(id, pw)| (id.to_string(), Zeroizing::new(pw.to_string()))).collect();
        Secrets { passwords, ..Default::default() }
    }

    fn both(n: u8, pairs: &[(&str, &str)]) -> Secrets {
        Secrets { device: Some(Zeroizing::new(u(n))), ..typed(pairs) }
    }

    fn holder(signer: &str, seed: &str) -> Holder {
        Holder { signer: signer.into(), seed: seed.into(), kind: signer.trim_end_matches("_module").into() }
    }

    const CHEAP: Cost = Cost { log_n: 4, r: 8, p: 1 };

    /// A directory of its own, gone with the test.
    struct Dir(PathBuf);

    impl Dir {
        fn new() -> Self {
            let d = std::env::temp_dir().join(random_id("unlock-test-"));
            std::fs::create_dir_all(&d).unwrap();
            Dir(d.join("unlock"))
        }
        fn store(&self) -> Unlock {
            Unlock::load(self.0.clone()).with_cost(CHEAP)
        }
    }

    impl Drop for Dir {
        fn drop(&mut self) {
            if let Some(parent) = self.0.parent() {
                let _ = std::fs::remove_dir_all(parent);
            }
        }
    }

    fn code<T: std::fmt::Debug>(r: Result<T>) -> Option<String> {
        r.unwrap_err().wire_code()
    }

    fn only_way(s: &Unlock, seed: &str) -> String {
        s.wallets().into_iter().find(|w| w.seed == seed).unwrap().ways[0].0.clone()
    }

    #[test]
    fn a_card_added_is_unlocked_and_after_a_restart_only_its_seed_unlocks_it() {
        let dir = Dir::new();
        let mut s = dir.store();
        let e = s.enroll(holder("keycard_module", "uid1"), Some(&u(1)), "Card", About::default()).unwrap();
        assert!(e.new && e.unlocked && s.wallets()[0].device);
        let (k, g) = s.data_key("bitcoin_wallet_core_module", &e.seed, "wallet/btc_1", None).unwrap();
        assert_eq!(g, 0);
        assert_eq!(s.lock(None), 1);
        let locked = s.data_key("bitcoin_wallet_core_module", &e.seed, "wallet/btc_1", None);
        assert_eq!(code(locked).as_deref(), Some("locked"));

        let mut again = dir.store();
        assert!(!again.is_unlocked(&e.seed));
        let way = only_way(&again, &e.seed);
        assert_eq!(code(again.unlock(&e.seed, &way, &device(2))).as_deref(), Some("wrong_seed"));
        assert!(again.unlock(&e.seed, &way, &Secrets::default()).is_err(), "needs its device");
        again.unlock(&e.seed, &way, &device(1)).unwrap();
        assert_eq!(again.data_key("bitcoin_wallet_core_module", &e.seed, "wallet/btc_1", None).unwrap().0, k);
    }

    #[test]
    fn each_module_scope_and_seed_gets_its_own_key() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let a = s.enroll(holder("keycard_module", "a"), Some(&u(1)), "A", About::default()).unwrap().seed;
        let b = s.enroll(holder("keycard_module", "b"), Some(&u(2)), "B", About::default()).unwrap().seed;
        let key = |m: &str, t: &str, sc: &str| s.data_key(m, t, sc, None).unwrap().0;
        let one = key("core", &a, "wallet");
        assert_eq!(key("core", &a, "wallet"), one);
        assert_ne!(key("tx_sender", &a, "wallet"), one);
        assert_ne!(key("core", &a, "history"), one);
        assert_ne!(key("core", &b, "wallet"), one);
        assert_ne!(key("core", PROFILE, "wallet"), one);
        assert!(s.data_key("core", &a, "", None).is_err());
        assert!(s.data_key("core", &a, "wallet", Some(1)).is_err(), "no generation 1 yet");
    }

    #[test]
    fn another_holder_of_the_seed_joins_it_and_its_key_unlocks_it() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let card = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap();
        s.lock(None);
        let shell = s.enroll(holder("keycard_shell_module", "mkid"), Some(&u(1)), "Shell", About::default()).unwrap();
        assert_eq!((shell.seed.as_str(), shell.new, shell.unlocked), (card.seed.as_str(), false, true));
        assert_eq!(s.holders(&card.seed).unwrap().len(), 2);
        assert_eq!(s.seed_of("keycard_shell_module", "mkid").as_deref(), Some(card.seed.as_str()));
        assert_eq!(s.wallets()[0].name, "Card", "the first name stays");
        // Each holder may name the seed its own way, and nobody else's.
        assert_eq!(s.resolve("keycard_shell_module", "mkid"), card.seed);
        assert_eq!(s.resolve("keycard_module", "uid"), card.seed);
        assert_eq!(s.resolve("keycard_module", "mkid"), "mkid");
        assert_eq!(s.resolve("anyone", &card.seed), card.seed);
        let other = s.enroll(holder("keycard_shell_module", "mkid2"), Some(&u(3)), "Other", About::default()).unwrap();
        assert!(other.new);
    }

    #[test]
    fn device_and_password_needs_both_and_device_or_password_takes_either() {
        let dir = Dir::new();
        let mut s = dir.store();
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        let pw = s.create_password("Home", "hunter22").unwrap();
        let and = vec![Factor::Device, Factor::Password(pw.clone())];
        assert!(s.set_rule(&seed, std::slice::from_ref(&and), &device(1)).is_err(), "the password is not typed");
        s.set_rule(&seed, &[and], &both(1, &[(&pw, "hunter22")])).unwrap();
        s.lock(None);
        let way = only_way(&s, &seed);
        assert!(s.unlock(&seed, &way, &device(1)).is_err());
        assert!(s.unlock(&seed, &way, &typed(&[(&pw, "hunter22")])).is_err());
        assert_eq!(code(s.unlock(&seed, &way, &both(1, &[(&pw, "hunter2")]))).as_deref(), Some("wrong_secret"));
        s.unlock(&seed, &way, &both(1, &[(&pw, "hunter22")])).unwrap();

        // The device, or the password alone: two new ways, each needing its own factor.
        let either = [vec![Factor::Device], vec![Factor::Password(pw.clone())]];
        assert!(s.set_rule(&seed, &either, &typed(&[(&pw, "hunter22")])).is_err(), "device only is new again");
        s.set_rule(&seed, &either, &both(1, &[(&pw, "hunter22")])).unwrap();
        s.lock(None);
        let mut s = dir.store();
        let ways = s.wallets()[0].ways.clone();
        let alone = ways.iter().find(|(_, f)| f == &vec![Factor::Password(pw.clone())]).unwrap().0.clone();
        s.unlock(&seed, &alone, &typed(&[(&pw, "hunter22")])).unwrap();
        assert!(s.is_unlocked(&seed));
    }

    #[test]
    fn a_password_changes_without_the_wallets_and_one_in_use_stays() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        let pw = s.create_password("Home", "first").unwrap();
        assert!(s.create_password("home", "x").is_err(), "names are unique");
        s.set_rule(&seed, &[vec![Factor::Password(pw.clone())]], &typed(&[(&pw, "first")])).unwrap();
        assert!(s.change_password(&pw, "nope", "second").is_err());
        s.change_password(&pw, "first", "second").unwrap();
        s.rename_password(&pw, "Family").unwrap();
        assert_eq!(s.passwords(), vec![(pw.clone(), "Family".to_string(), vec![seed.clone()])]);
        s.lock(None);
        let way = only_way(&s, &seed);
        assert!(s.unlock(&seed, &way, &typed(&[(&pw, "first")])).is_err());
        s.unlock(&seed, &way, &typed(&[(&pw, "second")])).unwrap();
        assert!(s.remove_password(&pw).unwrap_err().to_string().contains("Card"));
        s.set_rule(&seed, &[vec![Factor::Device]], &device(1)).unwrap();
        s.remove_password(&pw).unwrap();
        assert!(s.passwords().is_empty());
    }

    #[test]
    fn new_keys_move_the_generation_and_old_data_keys_still_answer() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        let (old, _) = s.data_key("core", &seed, "wallet", None).unwrap();
        assert!(s.change_keys(&seed, None, &Secrets::default()).is_err(), "the device way needs the device");
        assert_eq!(code(s.change_keys(&seed, None, &device(2))).as_deref(), Some("wrong_seed"));
        s.change_keys(&seed, None, &device(1)).unwrap();
        let (new, g) = s.data_key("core", &seed, "wallet", None).unwrap();
        assert_eq!(g, 1);
        assert_ne!(new, old);
        assert_eq!(s.data_key("core", &seed, "wallet", Some(0)).unwrap().0, old, "generation 0 through the chain");
        s.lock(None);
        let way = only_way(&s, &seed);
        s.unlock(&seed, &way, &device(1)).unwrap();
        assert_eq!(s.data_key("core", &seed, "wallet", None).unwrap(), (new, 1));
    }

    #[test]
    fn a_new_unlock_index_makes_the_old_key_useless() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let seed = s.enroll(holder("qr_signer_module", "fp"), Some(&u(1)), "QR", About::default()).unwrap().seed;
        assert!(s.change_keys(&seed, Some(0), &device(2)).is_err(), "only forward");
        // u(2) stands for the same seed's key at index 1.
        s.change_keys(&seed, Some(1), &device(2)).unwrap();
        assert_eq!(s.index(&seed).unwrap(), 1);
        s.lock(None);
        let way = only_way(&s, &seed);
        assert_eq!(code(s.unlock(&seed, &way, &device(1))).as_deref(), Some("wrong_seed"));
        s.unlock(&seed, &way, &device(2)).unwrap();
        // Added again with its index-0 key, it gains the holder but stays locked.
        s.lock(None);
        let again = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap();
        assert_eq!((again.seed.as_str(), again.unlocked), (seed.as_str(), false));
    }

    #[test]
    fn the_private_name_and_birthday_show_only_while_unlocked() {
        let dir = Dir::new();
        let mut s = dir.store();
        let about = About { origin: Some("created".into()), birthday: Some("2026-10-01".into()), private_name: None };
        let seed = s.enroll(holder("keystore_module", "g_1"), Some(&u(1)), "Main", about).unwrap().seed;
        s.set_names(&seed, Some("Spending"), Some(Some("Grandma's savings"))).unwrap();
        let w = &s.wallets()[0];
        assert_eq!((w.name.as_str(), w.about.private_name.as_deref()), ("Spending", Some("Grandma's savings")));
        assert_eq!(w.about.birthday.as_deref(), Some("2026-10-01"));
        s.lock(None);
        assert_eq!(s.wallets()[0].about, About::default());
        assert!(s.set_names(&seed, None, Some(Some("x"))).is_err(), "a private name needs the wallet unlocked");
        s.set_names(&seed, Some("Daily"), None).unwrap();
        let text = std::fs::read_to_string(dir.0.join("seeds.json")).unwrap();
        assert!(text.contains("Daily") && !text.contains("Grandma") && !text.contains("2026-10-01"), "{text}");
    }

    #[test]
    fn the_profile_key_opens_with_any_seed_and_locks_with_the_last() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let a = s.enroll(holder("keycard_module", "a"), Some(&u(1)), "A", About::default()).unwrap().seed;
        let p = s.data_key("eth_wallet_backend", PROFILE, "contacts", None).unwrap().0;
        let b = s.enroll(holder("keycard_module", "b"), Some(&u(2)), "B", About::default()).unwrap().seed;
        s.lock(Some(std::slice::from_ref(&a)));
        assert_eq!(s.data_key("eth_wallet_backend", PROFILE, "contacts", None).unwrap().0, p, "B is still open");
        s.lock(None);
        let locked = s.data_key("eth_wallet_backend", PROFILE, "contacts", None);
        assert_eq!(code(locked).as_deref(), Some("locked"));
        let way = only_way(&s, &b);
        s.unlock(&b, &way, &device(2)).unwrap();
        assert_eq!(s.data_key("eth_wallet_backend", PROFILE, "contacts", None).unwrap().0, p);
    }

    #[test]
    fn a_wallet_without_an_unlock_key_takes_a_password_alone() {
        let dir = Dir::new();
        let mut s = dir.store();
        let e = s.enroll(holder("qr_signer_module", "keystone-fp"), None, "Keystone", About::default()).unwrap();
        assert!(e.unlocked && !s.wallets()[0].device, "no way can take its device");
        let pw = s.create_password("QR", "pw-qr").unwrap();
        assert!(s.set_rule(&e.seed, &[vec![Factor::Device]], &device(1)).is_err(), "it gives no unlock key");
        s.set_rule(&e.seed, &[vec![Factor::Password(pw.clone())]], &typed(&[(&pw, "pw-qr")])).unwrap();
        let mut s = dir.store();
        let way = only_way(&s, &e.seed);
        s.unlock(&e.seed, &way, &typed(&[(&pw, "pw-qr")])).unwrap();
    }

    #[test]
    fn the_files_are_private_and_hold_no_key() {
        let dir = Dir::new();
        let mut s = dir.store();
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        let pw = s.create_password("Home", "hunter22").unwrap();
        let rule = [vec![Factor::Device], vec![Factor::Password(pw.clone())]];
        s.set_rule(&seed, &rule, &both(1, &[(&pw, "hunter22")])).unwrap();
        let (k, _) = s.data_key("core", &seed, "wallet", None).unwrap();
        let secrets = [hex::encode(u(1)), hex::encode(*k), "hunter22".into(), hex::encode(*s.open[&seed])];
        for name in ["seeds.json", "passwords.json"] {
            let text = std::fs::read_to_string(dir.0.join(name)).unwrap();
            assert!(secrets.iter().all(|x| !text.contains(x.as_str())), "{name} holds a secret");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(std::fs::metadata(dir.0.join(name)).unwrap().permissions().mode() & 0o777, 0o600);
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777, 0o700);
        }
    }

    #[test]
    fn files_it_cant_read_are_left_alone_and_refuse_everything() {
        let dir = Dir::new();
        std::fs::create_dir_all(&dir.0).unwrap();
        std::fs::write(dir.0.join("seeds.json"), b"{ not json").unwrap();
        let mut s = dir.store();
        assert!(s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).is_err());
        assert!(s.create_password("Home", "x").is_err());
        assert!(s.wallets().is_empty());
        assert_eq!(std::fs::read(dir.0.join("seeds.json")).unwrap(), b"{ not json");
    }

    #[test]
    fn an_always_unlocked_wallet_opens_at_start_and_lock_leaves_it_open() {
        let dir = Dir::new();
        let mut s = dir.store();
        let free = s.enroll(holder("keycard_module", "a"), Some(&u(1)), "Free", About::default()).unwrap().seed;
        let kept = s.enroll(holder("keycard_module", "b"), Some(&u(2)), "Kept", About::default()).unwrap().seed;
        s.set_rule(&free, &[vec![]], &Secrets::default()).unwrap();
        let (k, g) = s.data_key("core", &free, "wallet", None).unwrap();
        assert_eq!(g, 0, "taking the protection off keeps the key");
        assert_eq!(s.lock(None), 1, "only the protected one locks");
        assert!(s.is_unlocked(&free) && !s.is_unlocked(&kept));
        assert_eq!(s.lock(Some(&[free.clone()])), 0);
        assert!(s.data_key("core", PROFILE, "contacts", None).is_ok(), "the profile stays open with it");

        let again = dir.store();
        assert!(again.is_unlocked(&free) && !again.is_unlocked(&kept), "open from the start");
        assert_eq!(again.data_key("core", &free, "wallet", None).unwrap(), (k, 0));
    }

    #[test]
    fn protecting_an_always_unlocked_wallet_moves_it_to_new_keys() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        s.set_rule(&seed, &[vec![]], &Secrets::default()).unwrap();
        let (old, _) = s.data_key("core", &seed, "wallet", None).unwrap();
        let before = s.record(&seed).unwrap().clone();
        assert!(s.set_rule(&seed, &[vec![Factor::Device]], &Secrets::default()).is_err(), "needs the device");
        assert_eq!(s.record(&seed).unwrap().ways.len(), before.ways.len(), "a refusal changes nothing");
        assert!(s.record(&seed).unwrap().ways[0].factors.is_empty());
        s.set_rule(&seed, &[vec![Factor::Device]], &device(1)).unwrap();
        let (new, g) = s.data_key("core", &seed, "wallet", None).unwrap();
        assert_eq!(g, 1, "a new key: the old one sat in the clear");
        assert_ne!(new, old);
        assert_eq!(s.data_key("core", &seed, "wallet", Some(0)).unwrap().0, old, "old data still opens");
        assert_eq!(s.lock(None), 1, "and it locks again");
    }

    #[test]
    fn a_rule_is_one_to_eight_ways_and_one_taking_nothing_stands_alone() {
        let mut s = Unlock::in_memory().with_cost(CHEAP);
        let seed = s.enroll(holder("keycard_module", "uid"), Some(&u(1)), "Card", About::default()).unwrap().seed;
        assert!(s.set_rule(&seed, &[], &device(1)).is_err());
        assert!(s.set_rule(&seed, &[vec![], vec![Factor::Device]], &device(1)).is_err());
        assert!(s.set_rule(&seed, &[vec![Factor::Device], vec![Factor::Device]], &device(1)).is_err());
        assert!(s.set_rule(&seed, &[vec![Factor::Password("p_unknown".into())]], &device(1)).is_err());
        assert_eq!(Factor::parse("password:p_ab").unwrap(), Factor::Password("p_ab".into()));
        assert!(Factor::parse("password:../x").is_err() && Factor::parse("pin").is_err());
        assert_eq!(serde_json::to_string(&Factor::Device).unwrap(), "\"device\"");
    }
}
