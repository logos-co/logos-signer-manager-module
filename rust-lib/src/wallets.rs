//! The unlock API over the signers. A person unlocks a wallet in the Signer app by one of its ways
//! in; when the way takes the device, the holder works out the seed's unlock key in its own time, a
//! PIN session, a press on the Shell or a QR round trip, and the step finishes when it answers. A
//! rule or a key change that needs the device takes the same step.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use logos_signer_interface::{JobState, Secret, UnlockKeyRequest};

use crate::error::{bad, ManagerError, Result};
use crate::registry::Registry;
use crate::unlock::{Factor, Secrets, Unlock};

/// A settled step is kept this long for `progress` to report.
const SETTLED_RETENTION: Duration = Duration::from_secs(120);
/// A device answer waiting for a password typed again is wiped after this.
const RETRY_WINDOW: Duration = Duration::from_secs(120);

/// What a step does once the holder has answered.
#[derive(Clone, Debug)]
pub enum Then {
    Unlock { way: String },
    SetRule { ways: Vec<Vec<Factor>> },
    ChangeKeys { new_index: Option<u32> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    /// The holder is working: `working` or `confirm_on_device`.
    Device(&'static str),
    /// The device answered, a password didn't: type it again.
    NeedsPassword,
    Done,
    Failed,
}

struct Step {
    handle: String,
    seed: String,
    signer: usize,
    job: Option<String>,
    state: State,
    then: Then,
    passwords: BTreeMap<String, Zeroizing<String>>,
    /// The holder's answer, kept only while a password is typed again.
    device: Option<Zeroizing<Vec<u8>>>,
    error: Option<(Option<String>, String)>,
    at: Instant,
}

/// What a call did.
#[derive(Debug, PartialEq, Eq)]
pub enum Begun {
    Done,
    /// The holder is working; `progress(handle)` reports it.
    Waiting(String),
}

pub struct Wallets {
    pub store: Unlock,
    steps: Vec<Step>,
    seq: u64,
    /// Seeds whose state changed since the last drain, for the glue to announce.
    changed: Vec<String>,
}

impl Default for Wallets {
    /// Refusing everything until the module knows where its files are.
    fn default() -> Self {
        Wallets::new(Unlock::not_ready())
    }
}

impl Wallets {
    pub fn new(store: Unlock) -> Self {
        Wallets { store, steps: Vec::new(), seq: 0, changed: Vec::new() }
    }

    fn sweep(&mut self) {
        let now = Instant::now();
        for s in &mut self.steps {
            if s.state == State::NeedsPassword && now.duration_since(s.at) > RETRY_WINDOW {
                s.device = None;
                s.state = State::Failed;
                s.error = Some((None, "the device's answer expired: unlock again".into()));
                s.at = now;
            }
        }
        self.steps.retain(|s| !matches!(s.state, State::Done | State::Failed) || now.duration_since(s.at) < SETTLED_RETENTION);
    }

    pub fn note(&mut self, seed: &str) {
        if !self.changed.iter().any(|s| s == seed) {
            self.changed.push(seed.to_string());
        }
    }

    pub fn drain_changed(&mut self) -> Vec<String> {
        std::mem::take(&mut self.changed)
    }

    /// Does `then` need the seed's device?
    fn needs_device(&self, seed: &str, then: &Then) -> Result<bool> {
        match then {
            Then::Unlock { way } => Ok(self.store.way(seed, way)?.contains(&Factor::Device)),
            Then::SetRule { ways } => self.store.new_ways_take_device(seed, ways),
            Then::ChangeKeys { .. } => self.store.takes_device(seed),
        }
    }

    fn apply(&mut self, seed: &str, then: &Then, secrets: &Secrets) -> Result<()> {
        match then {
            Then::Unlock { way } => self.store.unlock(seed, way, secrets)?,
            Then::SetRule { ways } => self.store.set_rule(seed, ways, secrets)?,
            Then::ChangeKeys { new_index } => self.store.change_keys(seed, *new_index, secrets)?,
        }
        self.note(seed);
        Ok(())
    }

    /// Do `then` for `seed`: at once when it needs no device, else through `holder` (a signer
    /// module holding the seed; the first one listed by default), with its PIN or password.
    pub fn begin(
        &mut self,
        signers: &mut Registry,
        seed: &str,
        then: Then,
        holder: Option<&str>,
        secret: Option<Secret>,
        passwords: BTreeMap<String, Zeroizing<String>>,
    ) -> Result<Begun> {
        self.sweep();
        if !self.needs_device(seed, &then)? {
            let secrets = Secrets { device: None, passwords };
            self.apply(seed, &then, &secrets)?;
            return Ok(Begun::Done);
        }
        let holders = self.store.holders(seed)?;
        let h = match holder.map(str::trim).filter(|h| !h.is_empty()) {
            Some(name) => holders.iter().find(|h| h.signer == name).ok_or_else(|| bad(format!("{name} doesn't hold this wallet")))?,
            None => holders.first().ok_or_else(|| bad("this wallet has no holder"))?,
        };
        let index = match &then {
            Then::ChangeKeys { new_index: Some(i) } => *i,
            _ => self.store.index(seed)?,
        };
        let signer = signers
            .names()
            .iter()
            .position(|n| *n == h.signer)
            .ok_or_else(|| ManagerError::NotFound(format!("{} isn't consulted", h.signer)))?;
        let job = signers.signer(signer).unlock_key(UnlockKeyRequest { seed: h.seed.clone(), index, secret })?;
        self.seq += 1;
        let handle = format!("smu_{}{:x}", hex::encode(rand_bytes()), self.seq);
        self.steps.push(Step {
            handle: handle.clone(),
            seed: seed.trim().to_string(),
            signer,
            job: Some(job),
            state: State::Device("working"),
            then,
            passwords,
            device: None,
            error: None,
            at: Instant::now(),
        });
        // A holder that answers at once, or a wrong PIN, settles here and not as an event.
        self.advance(signers, &handle);
        let step = self.steps.iter().find(|s| s.handle == handle).expect("advanced, not removed");
        match step.state {
            State::Done => Ok(Begun::Done),
            State::Failed => Err(step_error(step)),
            _ => Ok(Begun::Waiting(handle)),
        }
    }

    /// Ask every working holder how it stands, once.
    pub fn progress_all(&mut self, signers: &mut Registry) {
        self.sweep();
        let live: Vec<String> = self.steps.iter().filter(|s| matches!(s.state, State::Device(_))).map(|s| s.handle.clone()).collect();
        for h in live {
            self.advance(signers, &h);
        }
    }

    fn advance(&mut self, signers: &mut Registry, handle: &str) {
        let Some(i) = self.steps.iter().position(|s| s.handle == handle) else { return };
        let (signer, Some(job)) = (self.steps[i].signer, self.steps[i].job.clone()) else { return };
        let outcome = (|| -> Result<Option<Zeroizing<Vec<u8>>>> {
            let s = signers.signer(signer);
            let st = s.unlock_key_status(&job)?;
            match st.state {
                JobState::Working | JobState::ConfirmOnDevice => {
                    self.steps[i].state = State::Device(st.state.as_str());
                    Ok(None)
                }
                JobState::Done => {
                    let key = s.unlock_key_result(&job)?;
                    let bytes = hex::decode(key.key.expose().trim()).map_err(|_| bad("the holder's unlock key isn't hex"))?;
                    logos_signer_interface::unlock::check_unlock_key(key.key.expose())?;
                    Ok(Some(Zeroizing::new(bytes)))
                }
                JobState::Refused => Err(ManagerError::Refused("declined on the device".into())),
                JobState::Failed | JobState::Cancelled => Err(st
                    .error
                    .map(ManagerError::from)
                    .unwrap_or_else(|| ManagerError::Signing(format!("the holder's job ended {}", st.state.as_str())))),
            }
        })();
        match outcome {
            Ok(None) => {}
            Ok(Some(device)) => {
                self.steps[i].job = None;
                self.finish(i, device);
            }
            Err(e) => {
                let step = &mut self.steps[i];
                step.job = None;
                step.state = State::Failed;
                step.error = Some((e.wire_code(), e.to_string()));
                step.at = Instant::now();
            }
        }
    }

    /// The holder answered: do what the step is for. A wrong password keeps the answer a moment
    /// for the person to type it again; anything else ends the step.
    fn finish(&mut self, i: usize, device: Zeroizing<Vec<u8>>) {
        let (seed, then) = (self.steps[i].seed.clone(), self.steps[i].then.clone());
        let passwords = std::mem::take(&mut self.steps[i].passwords);
        let secrets = Secrets { device: Some(device), passwords };
        let outcome = self.apply(&seed, &then, &secrets);
        let step = &mut self.steps[i];
        step.at = Instant::now();
        match outcome {
            Ok(()) => step.state = State::Done,
            Err(e) if e.wire_code().as_deref() == Some("wrong_secret") => {
                step.state = State::NeedsPassword;
                step.error = Some((e.wire_code(), e.to_string()));
                step.device = secrets.device;
            }
            Err(e) => {
                step.state = State::Failed;
                step.error = Some((e.wire_code(), e.to_string()));
            }
        }
    }

    /// The passwords typed again for a step whose device already answered.
    pub fn retry(&mut self, handle: &str, passwords: BTreeMap<String, Zeroizing<String>>) -> Result<Begun> {
        self.sweep();
        let i = self.position(handle)?;
        if self.steps[i].state != State::NeedsPassword {
            return Err(bad("this unlock isn't waiting for a password"));
        }
        let device = self.steps[i].device.take().ok_or_else(|| bad("the device's answer expired: unlock again"))?;
        self.steps[i].passwords = passwords;
        self.steps[i].error = None;
        self.finish(i, device);
        let step = &self.steps[i];
        match step.state {
            State::Done => Ok(Begun::Done),
            _ => Err(step_error(step)),
        }
    }

    fn position(&self, handle: &str) -> Result<usize> {
        self.steps
            .iter()
            .position(|s| s.handle == handle.trim())
            .ok_or_else(|| ManagerError::NotFound(handle.trim().to_string()))
    }

    /// `{ state, seed, step?, code?, error? }`: `device` with its `step` while the holder works,
    /// `needs_password`, `done` or `failed`.
    pub fn progress(&mut self, signers: &mut Registry, handle: &str) -> Result<serde_json::Value> {
        self.progress_all(signers);
        let s = &self.steps[self.position(handle)?];
        let (code, error) = s.error.clone().map_or((None, None), |(c, e)| (c, Some(e)));
        Ok(match s.state {
            State::Device(step) => serde_json::json!({ "state": "device", "seed": s.seed, "step": step }),
            State::NeedsPassword => serde_json::json!({ "state": "needs_password", "seed": s.seed, "code": code, "error": error }),
            State::Done => serde_json::json!({ "state": "done", "seed": s.seed }),
            State::Failed => serde_json::json!({ "state": "failed", "seed": s.seed, "code": code, "error": error }),
        })
    }

    /// The person gave up: the holder stops asking.
    pub fn cancel(&mut self, signers: &mut Registry, handle: &str) -> Result<()> {
        let i = self.position(handle)?;
        let step = &mut self.steps[i];
        if let Some(job) = step.job.take() {
            let _ = signers.signer(step.signer).cancel_unlock_key(&job);
        }
        step.device = None;
        if !matches!(step.state, State::Done | State::Failed) {
            step.state = State::Failed;
            step.error = Some((None, "cancelled".into()));
            step.at = Instant::now();
        }
        Ok(())
    }

    /// Lock these wallets, or all: their steps end too.
    pub fn lock(&mut self, signers: &mut Registry, seeds: Option<&[String]>) -> usize {
        let ending: Vec<String> = self
            .steps
            .iter()
            .filter(|s| seeds.is_none_or(|list| list.iter().any(|x| x.trim() == s.seed)))
            .map(|s| s.handle.clone())
            .collect();
        for h in ending {
            let _ = self.cancel(signers, &h);
        }
        self.store.lock(seeds)
    }
}

fn step_error(step: &Step) -> ManagerError {
    let (code, message) = step.error.clone().unwrap_or((None, "the unlock did not finish".into()));
    match code.as_deref().and_then(|c| serde_json::from_value(serde_json::Value::String(c.into())).ok()) {
        Some(code) => ManagerError::Signer(logos_signer_interface::SignerError::new(code, message)),
        None => ManagerError::Refused(message),
    }
}

fn rand_bytes() -> [u8; 16] {
    use rand::RngCore;
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use logos_signer_interface::mock::{MockOptions, MockSigner};
    use logos_signer_interface::{Account, Collects, JobStatus, SignRequest, Signature, Signer, SignerInfo, UnlockKey};

    use crate::unlock::{About, Cost, Holder};

    /// A device the test presses, shared with the registry.
    #[derive(Clone)]
    struct Device(Arc<Mutex<MockSigner>>);

    impl Device {
        fn new(opts: MockOptions) -> Self {
            Device(Arc::new(Mutex::new(MockSigner::new(opts))))
        }
        fn press(&self, yes: bool) {
            let mut d = self.0.lock().unwrap();
            let jobs = d.waiting_keys();
            assert_eq!(jobs.len(), 1, "one unlock waiting on the device");
            if yes { d.confirm(&jobs[0]).unwrap() } else { d.refuse(&jobs[0]).unwrap() }
        }
        fn waiting(&self) -> usize {
            self.0.lock().unwrap().waiting_keys().len()
        }
        fn seed(&self) -> String {
            self.0.lock().unwrap().accounts().unwrap()[0].seed.clone().unwrap()
        }
        /// The unlock key at `index`, as the add flow gets it.
        fn key(&self, index: u32, secret: Option<&str>) -> Vec<u8> {
            let mut d = self.0.lock().unwrap();
            let request = UnlockKeyRequest { seed: d.accounts().unwrap()[0].seed.clone().unwrap(), index, secret: secret.map(Secret::new) };
            let job = d.unlock_key(request).unwrap();
            if !d.waiting_keys().is_empty() {
                d.confirm(&job).unwrap();
            }
            hex::decode(d.unlock_key_result(&job).unwrap().key.expose()).unwrap()
        }
    }

    impl Signer for Device {
        fn info(&self) -> SignerInfo {
            self.0.lock().unwrap().info()
        }
        fn accounts(&mut self) -> logos_signer_interface::Result<Vec<Account>> {
            self.0.lock().unwrap().accounts()
        }
        fn sign(&mut self, r: SignRequest) -> logos_signer_interface::Result<String> {
            self.0.lock().unwrap().sign(r)
        }
        fn status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.lock().unwrap().status(job)
        }
        fn result(&mut self, job: &str) -> logos_signer_interface::Result<Vec<Signature>> {
            self.0.lock().unwrap().result(job)
        }
        fn cancel(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.lock().unwrap().cancel(job)
        }
        fn unlock_key(&mut self, r: UnlockKeyRequest) -> logos_signer_interface::Result<String> {
            self.0.lock().unwrap().unlock_key(r)
        }
        fn unlock_key_status(&mut self, job: &str) -> logos_signer_interface::Result<JobStatus> {
            self.0.lock().unwrap().unlock_key_status(job)
        }
        fn unlock_key_result(&mut self, job: &str) -> logos_signer_interface::Result<UnlockKey> {
            self.0.lock().unwrap().unlock_key_result(job)
        }
        fn cancel_unlock_key(&mut self, job: &str) -> logos_signer_interface::Result<()> {
            self.0.lock().unwrap().cancel_unlock_key(job)
        }
    }

    const CHEAP: Cost = Cost { log_n: 4, r: 8, p: 1 };

    fn pw(pairs: &[(&str, &str)]) -> BTreeMap<String, Zeroizing<String>> {
        pairs.iter().map(|(id, p)| (id.to_string(), Zeroizing::new(p.to_string()))).collect()
    }

    /// A card in a reader (PIN 123456) and a Shell (a press), both holding the mock's seed,
    /// enrolled through the card and locked.
    fn fixture() -> (Registry, Device, Device, Wallets, String) {
        let card = Device::new(MockOptions { collects: Collects::Pin, secret: "123456".into(), ..Default::default() });
        let shell = Device::new(MockOptions { needs_confirmation: true, kind: "keycard_shell".into(), ..Default::default() });
        let mut r = Registry::new();
        r.add("keycard_module", Box::new(card.clone()));
        r.add("keycard_shell_module", Box::new(shell.clone()));
        let mut w = Wallets::new(Unlock::in_memory().with_cost(CHEAP));
        let h = |signer: &str, d: &Device| Holder { signer: signer.into(), seed: d.seed(), kind: "keycard".into() };
        let seed = w.store.enroll(h("keycard_module", &card), Some(&card.key(0, Some("123456"))), "Card", About::default()).unwrap().seed;
        w.store.enroll(h("keycard_shell_module", &shell), Some(&shell.key(0, None)), "Card", About::default()).unwrap();
        w.lock(&mut r, None);
        (r, card, shell, w, seed)
    }

    fn device_way(w: &Wallets, seed: &str) -> String {
        w.store.wallets().into_iter().find(|v| v.seed == seed).unwrap().ways[0].0.clone()
    }

    #[test]
    fn a_card_unlocks_its_wallet_in_a_pin_session_and_a_wrong_pin_says_so() {
        let (mut r, _, _, mut w, seed) = fixture();
        let way = Then::Unlock { way: device_way(&w, &seed) };
        let wrong = w.begin(&mut r, &seed, way.clone(), Some("keycard_module"), Some(Secret::new("000000")), BTreeMap::new());
        assert_eq!(wrong.unwrap_err().wire_code().as_deref(), Some("wrong_secret"));
        assert!(!w.store.is_unlocked(&seed));
        let done = w.begin(&mut r, &seed, way, Some("keycard_module"), Some(Secret::new("123456")), BTreeMap::new());
        assert_eq!(done.unwrap(), Begun::Done);
        assert!(w.store.is_unlocked(&seed));
        assert_eq!(w.drain_changed(), vec![seed]);
    }

    #[test]
    fn a_shell_unlocks_once_pressed_and_progress_says_where_it_is() {
        let (mut r, _, shell, mut w, seed) = fixture();
        let way = Then::Unlock { way: device_way(&w, &seed) };
        let Begun::Waiting(h) = w.begin(&mut r, &seed, way, Some("keycard_shell_module"), None, BTreeMap::new()).unwrap() else {
            panic!("the Shell waits for its press");
        };
        let p = w.progress(&mut r, &h).unwrap();
        assert_eq!((p["state"].as_str(), p["step"].as_str()), (Some("device"), Some("confirm_on_device")));
        assert!(!w.store.is_unlocked(&seed));
        shell.press(true);
        assert_eq!(w.progress(&mut r, &h).unwrap()["state"], "done");
        assert!(w.store.is_unlocked(&seed));
    }

    #[test]
    fn a_declined_or_cancelled_unlock_ends_and_the_device_stops_asking() {
        let (mut r, _, shell, mut w, seed) = fixture();
        let way = Then::Unlock { way: device_way(&w, &seed) };
        let Begun::Waiting(h) = w.begin(&mut r, &seed, way.clone(), Some("keycard_shell_module"), None, BTreeMap::new()).unwrap() else {
            panic!("waits");
        };
        shell.press(false);
        let p = w.progress(&mut r, &h).unwrap();
        assert_eq!(p["state"], "failed");
        let Begun::Waiting(h) = w.begin(&mut r, &seed, way, Some("keycard_shell_module"), None, BTreeMap::new()).unwrap() else {
            panic!("waits");
        };
        assert_eq!(shell.waiting(), 1);
        w.cancel(&mut r, &h).unwrap();
        assert_eq!(shell.waiting(), 0);
        assert_eq!(w.progress(&mut r, &h).unwrap()["state"], "failed");
        assert!(!w.store.is_unlocked(&seed));
    }

    #[test]
    fn a_mistyped_password_keeps_the_devices_answer_for_another_try() {
        let (mut r, _, _, mut w, seed) = fixture();
        let way = Then::Unlock { way: device_way(&w, &seed) };
        w.begin(&mut r, &seed, way, Some("keycard_module"), Some(Secret::new("123456")), BTreeMap::new()).unwrap();
        let id = w.store.create_password("Home", "hunter22").unwrap();
        let rule = Then::SetRule { ways: vec![vec![Factor::Device, Factor::Password(id.clone())]] };
        let set = w.begin(&mut r, &seed, rule, Some("keycard_module"), Some(Secret::new("123456")), pw(&[(&id, "hunter22")]));
        assert_eq!(set.unwrap(), Begun::Done, "a new device way takes the device again");
        w.lock(&mut r, None);

        let way = Then::Unlock { way: device_way(&w, &seed) };
        let Begun::Waiting(h) = w.begin(&mut r, &seed, way, Some("keycard_module"), Some(Secret::new("123456")), pw(&[(&id, "hunter2")])).unwrap() else {
            panic!("the device answered, the password didn't");
        };
        assert_eq!(w.progress(&mut r, &h).unwrap()["state"], "needs_password");
        assert!(w.retry(&h, pw(&[(&id, "hunter")])).is_err());
        assert_eq!(w.retry(&h, pw(&[(&id, "hunter22")])).unwrap(), Begun::Done);
        assert!(w.store.is_unlocked(&seed));
    }

    #[test]
    fn a_new_unlock_index_is_asked_of_the_holder_and_the_old_answer_no_longer_unlocks() {
        let (mut r, card, shell, mut w, seed) = fixture();
        let pin = || Some(Secret::new("123456"));
        let way = Then::Unlock { way: device_way(&w, &seed) };
        w.begin(&mut r, &seed, way, Some("keycard_module"), pin(), BTreeMap::new()).unwrap();
        let change = Then::ChangeKeys { new_index: Some(1) };
        assert_eq!(w.begin(&mut r, &seed, change, Some("keycard_module"), pin(), BTreeMap::new()).unwrap(), Begun::Done);
        assert_eq!(w.store.index(&seed).unwrap(), 1);
        w.lock(&mut r, None);
        let way = device_way(&w, &seed);
        let old = Secrets { device: Some(Zeroizing::new(card.key(0, Some("123456")))), ..Default::default() };
        assert!(w.store.unlock(&seed, &way, &old).is_err());
        // The Shell, asked for the new index, gives the same seed's key there.
        let Begun::Waiting(h) = w.begin(&mut r, &seed, Then::Unlock { way }, Some("keycard_shell_module"), None, BTreeMap::new()).unwrap() else {
            panic!("waits");
        };
        shell.press(true);
        assert_eq!(w.progress(&mut r, &h).unwrap()["state"], "done");
        assert!(w.store.is_unlocked(&seed));
    }

    #[test]
    fn locking_ends_the_steps_under_way() {
        let (mut r, _, shell, mut w, seed) = fixture();
        let way = Then::Unlock { way: device_way(&w, &seed) };
        let Begun::Waiting(h) = w.begin(&mut r, &seed, way, Some("keycard_shell_module"), None, BTreeMap::new()).unwrap() else {
            panic!("waits");
        };
        w.lock(&mut r, None);
        assert_eq!(shell.waiting(), 0);
        assert_eq!(w.progress(&mut r, &h).unwrap()["state"], "failed");
        assert!(w.begin(&mut r, &seed, Then::Unlock { way: "w_none".into() }, None, None, BTreeMap::new()).is_err());
    }
}
