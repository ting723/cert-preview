//! Verification: everything that depends on the clock or on caller context.
//!
//! This layer consumes a [`Bundle`](crate::model::Bundle) and produces a
//! [`Report`](crate::model::Report). It is the *only* place time and hostnames
//! enter the system, which is what keeps the parse output deterministic and
//! therefore snapshot-testable across Rust, Node and the browser.
//!
//! Verification is deliberately **structural**: chains are linked by matching
//! issuer/subject names, and hostnames are matched against subject alternative
//! names. No signature is checked, because doing so would require a full crypto
//! stack (and the false promise of being a trust engine).

pub mod chain;
pub mod hostname;
pub mod validity;

pub use validity::report;
