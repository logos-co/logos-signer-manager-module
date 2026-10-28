//! What the manager refuses, and why.

use logos_signer_interface::{ErrorCode, SignerError};

#[derive(Debug, thiserror::Error)]
pub enum ManagerError {
    #[error("not found: {0}")]
    NotFound(String),
    #[error("invalid parameters: {0}")]
    InvalidParams(String),
    /// A refusal the caller is meant to read and act on.
    #[error("{0}")]
    Refused(String),
    /// The account's signer said no; its code tells the approver whether to ask again.
    #[error("{0}")]
    Signer(SignerError),
    #[error("signing error: {0}")]
    Signing(String),
    /// The signer a request would use changed after the person saw it: they review it again.
    #[error("{0}")]
    SignerChanged(String),
    /// A holder brought the key of another wallet than its own: this names that wallet.
    #[error("this seed is already the wallet {0}")]
    Taken(String),
}

impl ManagerError {
    /// The signer's code, when the signer refused: `wrong_secret` lets the person try again.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ManagerError::Signer(e) => Some(e.code),
            _ => None,
        }
    }

    /// The code a reply carries: the signer's, or the manager's own `signer_changed`.
    pub fn wire_code(&self) -> Option<String> {
        match self {
            ManagerError::SignerChanged(_) => Some("signer_changed".into()),
            ManagerError::Taken(_) => Some("invalid".into()),
            _ => self.code().and_then(|c| serde_json::to_value(c).ok()?.as_str().map(str::to_string)),
        }
    }
}

impl From<SignerError> for ManagerError {
    fn from(e: SignerError) -> Self {
        ManagerError::Signer(e)
    }
}

pub type Result<T> = std::result::Result<T, ManagerError>;

pub fn bad(msg: impl Into<String>) -> ManagerError {
    ManagerError::InvalidParams(msg.into())
}
