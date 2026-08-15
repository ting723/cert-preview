//! Platform-agnostic certificate inspection core.
//!
//! # Layers
//!
//! ```text
//! input   bytes        -> labelled DER objects   (PEM scanning, format sniffing)
//! parse   DER          -> model                  (x509, keys, extensions)
//! verify  model + time -> report                 (validity, chain, hostname)
//! format  model        -> text / table / json    (rendering)
//! encode  bytes        -> digests, PEM           (fingerprints)
//! ```
//!
//! Dependencies point strictly downward. The browser (WASM), server and CLI
//! front ends all sit on top of the same `parse` + `verify` + `format` stack,
//! so their output cannot diverge.
//!
//! # What this crate deliberately does not do
//!
//! It does not verify signatures. Doing so needs a full crypto stack, which
//! would multiply the WASM payload, and it would invite the far more dangerous
//! mistake of appearing to be a trust decision engine. Chain analysis here is
//! *structural*: names and key identifiers line up, or they do not.

pub mod encode;
pub mod error;
pub mod format;
pub mod input;
pub mod model;
pub mod parse;
pub mod util;
pub mod verify;

pub use error::{CertError, ErrorCode, ErrorPayload, Result};
pub use format::{table, text};
pub use parse::bundle as parse_bundle;
pub use verify::report as verify_report;
