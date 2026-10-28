//! signer_manager_module: takes signature requests from any named module, shows them to a person
//! through the signer app, and has the account's signer sign: keystore_module for keys in files,
//! a device module for a hardware wallet. It holds no keys and checks every signature it gets.
//!
//! The core is plain Rust, tested with `cargo test --no-default-features`; the Logos glue is
//! behind the `logos_module` feature, which the builder turns on.

pub mod access;
pub mod unlock;
pub mod wallets;
pub mod approval;
pub mod btc;
pub mod error;
pub mod evm;
pub mod gate;
pub mod psbt;
pub mod registry;
pub mod roster;
pub mod origins;

#[cfg(feature = "logos_module")]
mod glue;

pub use error::{ManagerError, Result};

pub mod keycard_routes;
