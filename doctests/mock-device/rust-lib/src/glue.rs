//! A signer behind logos.signer/1 that behaves like a device: each job waits until its button is
//! pressed, and it can answer wrong on purpose. Its keys come from the "abandon … about" phrase, so
//! it stands beside a keystore holding the "test … junk" keys.

use std::sync::MutexGuard;

use logos_signer_interface::json as signer_json;
use logos_signer_interface::mock::{Doctor, MockOptions, MockSigner};
use logos_signer_interface::{Payload, RequestKind, Signer};
use serde_json::{json, Value};

const PHRASE: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

pub trait MockDeviceSignerModule: Send + Sync + 'static {
    // ── logos.signer/1 ──────────────────────────────────────────────────
    fn signer_info(&self) -> String;
    fn signer_accounts(&self) -> String;
    fn sign(&self, request_json: String) -> String;
    fn sign_status(&self, job: String) -> String;
    fn sign_result(&self, job: String) -> String;
    fn cancel_sign(&self, job: String) -> String;
    // A real signer admits only the manager here; this fixture admits anyone.
    fn unlock_key(&self, request_json: String) -> String;
    fn unlock_key_status(&self, job: String) -> String;
    fn unlock_key_result(&self, job: String) -> String;
    fn cancel_unlock_key(&self, job: String) -> String;

    // ── the device itself, for tests ────────────────────────────────────
    /// What the device shows: `{ ok, waiting: [{ job, account, kind, items }], unlocking: [job] }`.
    fn screen(&self) -> String;
    /// The person presses `confirm` or `refuse` on the device for `job`.
    fn press(&self, job: String, button: String) -> String;
    /// Answer wrong from now on, or rightly again: `none`, `other_key`, `other_digest` or `drop_last`.
    fn doctor(&self, mode: String) -> String;
    /// Plug the device in or out. Its accounts stay listed, available or not.
    fn plug(&self, connected: bool) -> String;
    /// Take whole requests from now on, as a device with a screen does, or hashes again.
    fn whole(&self, enabled: bool) -> String;

    fn on_context_ready(&self, _ctx: &RustModuleContext) {}
}

pub trait MockDeviceSignerModuleEvents {
    fn signer_accounts_changed(&self, count: i64);
    fn sign_progress(&self, job: String, state: String);
}

include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/provider_gen.rs"));

struct MockDeviceSignerModuleImpl {
    device: std::sync::Mutex<MockSigner>,
}

impl Default for MockDeviceSignerModuleImpl {
    fn default() -> Self {
        let opts = MockOptions { needs_confirmation: true, phrase: PHRASE.into(), ..Default::default() };
        MockDeviceSignerModuleImpl { device: std::sync::Mutex::new(MockSigner::new(opts)) }
    }
}

impl MockDeviceSignerModuleImpl {
    fn device(&self) -> MutexGuard<'_, MockSigner> {
        self.device.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn err(e: impl std::fmt::Display) -> String {
    json!({ "ok": false, "error": e.to_string() }).to_string()
}

impl MockDeviceSignerModule for MockDeviceSignerModuleImpl {
    fn signer_info(&self) -> String {
        signer_json::signer_info(&*self.device())
    }

    fn signer_accounts(&self) -> String {
        signer_json::signer_accounts(&mut *self.device())
    }

    fn sign(&self, request_json: String) -> String {
        signer_json::sign(&mut *self.device(), &request_json)
    }

    fn sign_status(&self, job: String) -> String {
        signer_json::sign_status(&mut *self.device(), &job)
    }

    fn sign_result(&self, job: String) -> String {
        signer_json::sign_result(&mut *self.device(), &job)
    }

    fn cancel_sign(&self, job: String) -> String {
        signer_json::cancel_sign(&mut *self.device(), &job)
    }

    fn unlock_key(&self, request_json: String) -> String {
        signer_json::unlock_key(&mut *self.device(), &request_json)
    }

    fn unlock_key_status(&self, job: String) -> String {
        signer_json::unlock_key_status(&mut *self.device(), &job)
    }

    fn unlock_key_result(&self, job: String) -> String {
        signer_json::unlock_key_result(&mut *self.device(), &job)
    }

    fn cancel_unlock_key(&self, job: String) -> String {
        signer_json::cancel_unlock_key(&mut *self.device(), &job)
    }

    fn screen(&self) -> String {
        let waiting: Vec<Value> = self
            .device()
            .waiting()
            .into_iter()
            .map(|(job, req)| {
                let items = match &req.payload {
                    Payload::Hash { items } => items.len(),
                    _ => 1,
                };
                json!({ "job": job, "account": req.account, "kind": req.payload.kind(), "items": items })
            })
            .collect();
        json!({ "ok": true, "waiting": waiting, "unlocking": self.device().waiting_keys() }).to_string()
    }

    fn press(&self, job: String, button: String) -> String {
        // An open key's job id is never announced; the manager looks for it.
        let unlocking = self.device().waiting_keys().contains(&job);
        let pressed = match button.as_str() {
            "confirm" => self.device().confirm(&job),
            "refuse" => self.device().refuse(&job),
            _ => return err("press confirm or refuse"),
        };
        match pressed {
            Ok(()) if unlocking => json!({ "ok": true, "job": job }).to_string(),
            Ok(()) => {
                emit_sign_progress(&job, if button == "confirm" { "done" } else { "failed" });
                json!({ "ok": true, "job": job }).to_string()
            }
            Err(e) => err(e),
        }
    }

    fn doctor(&self, mode: String) -> String {
        match Doctor::parse(&mode) {
            Some(d) => {
                self.device().set_doctor(d);
                json!({ "ok": true, "doctor": mode }).to_string()
            }
            None => err("none, other_key, other_digest or drop_last"),
        }
    }

    fn plug(&self, connected: bool) -> String {
        let count = {
            let mut device = self.device();
            device.set_available(connected);
            device.accounts().map(|a| a.len()).unwrap_or(0)
        };
        emit_signer_accounts_changed(count as i64);
        json!({ "ok": true, "connected": connected }).to_string()
    }

    fn whole(&self, enabled: bool) -> String {
        let kinds = if enabled {
            vec![RequestKind::EvmTransaction, RequestKind::EvmMessage, RequestKind::BtcPsbt]
        } else {
            vec![RequestKind::Hash]
        };
        let count = {
            let mut device = self.device();
            device.set_request_kinds(kinds);
            device.accounts().map(|a| a.len()).unwrap_or(0)
        };
        // The manager reads a signer's info again when it says its accounts changed.
        emit_signer_accounts_changed(count as i64);
        json!({ "ok": true, "whole": enabled }).to_string()
    }
}

#[no_mangle]
pub extern "Rust" fn logos_module_install() {
    install::<MockDeviceSignerModuleImpl>();
}
