//! Input layer: raw bytes in, labelled DER objects out.
//!
//! Nothing here knows what a certificate is. It only understands armour,
//! base64 and object boundaries. Keeping that separation means the parse layer
//! never has to care whether a certificate arrived as PEM, DER or a base64
//! blob pasted out of a browser.

pub mod detect;
pub mod pem;

pub use detect::{detect, DerObject, Detected, SourceFormat};
pub use pem::{encode as encode_pem, scan as scan_pem, PemBlock};
