//! Parsing layer: bytes -> [`crate::model`].
//!
//! Dependency direction is strictly downward — `parse` may use `input`,
//! `encode`, `model` and `util`, and nothing above it. `verify` and `format`
//! consume the model, never the parser, which is what stops the CLI, the WASM
//! build and the server build from drifting apart.
//!
//! `key` is always compiled because a certificate contains a
//! SubjectPublicKeyInfo; the `key` *feature* controls only whether standalone
//! key files are recognised as bundle items.

pub mod der;
pub mod key;
pub mod oid;

#[cfg(feature = "x509")]
pub mod cert;
#[cfg(feature = "x509")]
mod ext;
#[cfg(feature = "x509")]
mod name;

mod bundle;

pub use bundle::bundle;
