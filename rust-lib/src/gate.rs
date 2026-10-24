//! Who may do what, as a pure decision; `glue.rs` resolves the caller and asks. Ported from
//! keystore_module's gate, whose approval roles the manager now holds.

/// The surface that shows a request to a person and takes what its signer needs.
pub const DEFAULT_APPROVER: &str = "evm_signer_ui";
/// The surface that decides which accounts are opened and unlocked for which wallets.
pub const DEFAULT_CUSTODIAN: &str = "evm_keystore_ui";
/// The signer modules consulted, in order, when nothing configures them. A device module that
/// isn't installed offers nothing (`registry.rs`).
pub const DEFAULT_SIGNERS: &[&str] = &["keystore_module", "keycard_shell_module", "keycard_module", "qr_signer_module"];

/// Who holds each role, and which signer modules are consulted. A role is a set: a terminal
/// approver works beside the app rather than displacing it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Roles {
    pub approvers: Vec<String>,
    pub custodians: Vec<String>,
    pub signers: Vec<String>,
}

impl Default for Roles {
    fn default() -> Self {
        Self {
            approvers: vec![DEFAULT_APPROVER.into()],
            custodians: vec![DEFAULT_CUSTODIAN.into()],
            signers: DEFAULT_SIGNERS.iter().map(|s| s.to_string()).collect(),
        }
    }
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum Names {
    One(String),
    Many(Vec<String>),
}

impl Default for Names {
    fn default() -> Self {
        Names::Many(Vec::new())
    }
}

impl Names {
    /// Trimmed, blanks dropped, the first of any repeat kept: an empty list admits nobody.
    fn into_names(self) -> Vec<String> {
        let raw = match self {
            Names::One(s) => vec![s],
            Names::Many(v) => v,
        };
        let mut out: Vec<String> = Vec::new();
        for n in raw {
            let n = n.trim();
            if !n.is_empty() && !out.iter().any(|k| k == n) {
                out.push(n.to_string());
            }
        }
        out
    }
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RolesWire {
    #[serde(default)]
    approvers: Names,
    #[serde(default)]
    custodians: Names,
    #[serde(default)]
    signers: Names,
}

impl Roles {
    /// Replace everything from `{ approvers?, custodians?, signers? }`. Total, as the
    /// keystore's: what the document doesn't name is held by nobody. A malformed document changes
    /// nothing.
    pub fn configure(&mut self, config_json: &str) -> Result<(), String> {
        let doc: serde_json::Value = serde_json::from_str(config_json).map_err(|e| e.to_string())?;
        if !doc.is_object() {
            return Err("configuration must be a JSON object".into());
        }
        let wire: RolesWire = serde_json::from_value(doc).map_err(|e| e.to_string())?;
        self.approvers = wire.approvers.into_names();
        self.custodians = wire.custodians.into_names();
        self.signers = wire.signers.into_names();
        Ok(())
    }
}

/// The caller, reduced to what a gate may care about. The host anchor is one bag covering the
/// shells and every relayed CLI token, so no role admits it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    Unknown,
    HostAnchor,
    Module(String),
    Derived { parent: String, leaf: String },
    Operator(String),
}

impl Caller {
    /// The name a request is recorded against; only a plainly named module has one.
    pub fn named(&self) -> Option<&str> {
        match self {
            Caller::Module(n) => Some(n.as_str()),
            _ => None,
        }
    }
}

/// Does `caller` hold a role any of `holders` may hold? An empty set admits nobody.
pub fn holds_any_role(holders: &[String], caller: &Caller) -> bool {
    holders.iter().any(|h| !h.is_empty() && matches!(caller, Caller::Module(n) if n == h))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(n: &str) -> Caller {
        Caller::Module(n.into())
    }

    #[test]
    fn only_a_named_holder_is_admitted() {
        let r = Roles::default();
        assert!(holds_any_role(&r.approvers, &m("evm_signer_ui")));
        for other in [m("evm_keystore_ui"), m(""), Caller::HostAnchor, Caller::Unknown, Caller::Operator("evm_signer_ui".into())] {
            assert!(!holds_any_role(&r.approvers, &other), "{other:?}");
        }
        assert!(!holds_any_role(&[], &m("evm_signer_ui")));
    }

    #[test]
    fn the_keystore_comes_first_then_the_device_modules() {
        assert_eq!(
            Roles::default().signers,
            vec!["keystore_module", "keycard_shell_module", "keycard_module", "qr_signer_module"]
        );
    }

    #[test]
    fn every_default_signer_loads_with_the_manager_when_installed() {
        // A default signer outside metadata.json loads only once something else loads it.
        let meta: serde_json::Value = serde_json::from_str(include_str!("../../metadata.json")).unwrap();
        let declared = |key: &str| -> Vec<String> {
            let entries = meta[key].as_array().cloned().unwrap_or_default();
            entries.iter().filter_map(|d| d.as_str().or(d["name"].as_str()).map(String::from)).collect()
        };
        let (required, optional) = (declared("dependencies"), declared("optional_dependencies"));
        for signer in DEFAULT_SIGNERS {
            assert!(required.iter().chain(&optional).any(|d| d == signer), "{signer} is not a dependency");
        }
        assert!(optional.iter().all(|d| !required.contains(d)), "a dependency is one kind or the other");
    }

    #[test]
    fn configuring_is_total_and_a_malformed_document_changes_nothing() {
        let mut r = Roles::default();
        r.configure(r#"{"approvers":["evm_signer_ui","evm_signer_cli"],"signers":["keystore_module","ledger_module"]}"#).unwrap();
        assert!(holds_any_role(&r.approvers, &m("evm_signer_cli")));
        assert!(r.custodians.is_empty(), "not named, so nobody");
        assert_eq!(r.signers, vec!["keystore_module", "ledger_module"]);
        let good = r.clone();
        for doc in ["", "[]", r#"{"approver":"x"}"#, r#"{"signers":5}"#] {
            assert!(r.configure(doc).is_err(), "{doc:?}");
            assert_eq!(r, good, "{doc:?}");
        }
    }

    #[test]
    fn only_a_plainly_named_module_can_be_a_requester() {
        assert_eq!(m("wallet").named(), Some("wallet"));
        assert_eq!(Caller::HostAnchor.named(), None);
        assert_eq!(Caller::Derived { parent: "a".into(), leaf: "b".into() }.named(), None);
    }
}
