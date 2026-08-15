//! Rendering a [`Report`] into the three output shapes the front ends share.
//!
//! Every renderer reads the same model, so the CLI, server and browser cannot
//! drift apart: the JSON a Rust unit test asserts is byte-identical to the
//! JSON the WASM build returns for the same input.

#[cfg(feature = "json")]
pub mod json;
pub mod table;
pub mod text;

pub use table::table;
pub use text::text;

#[cfg(feature = "json")]
pub use json::to_json;
