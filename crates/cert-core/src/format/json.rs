//! JSON rendering of a [`Report`].
//!
//! Pretty-printed so the output is stable and diff-friendly; the cross-platform
//! snapshot tests assert on exactly this string.

use crate::error::{CertError, Result};
use crate::model::Report;

/// Serialise `report` to pretty-printed JSON.
pub fn to_json(report: &Report) -> Result<String> {
    serde_json::to_string_pretty(report).map_err(|e| CertError::Serialization {
        reason: e.to_string(),
    })
}
