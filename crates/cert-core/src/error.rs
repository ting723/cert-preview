//! Unified error type for the whole core library.
//!
//! Every error carries a stable [`ErrorCode`]. The code — not the human
//! readable message — is the contract crossing the WASM boundary, so
//! TypeScript callers can branch on it without string matching.

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub type Result<T> = core::result::Result<T, CertError>;

/// Stable, machine-readable error discriminator.
///
/// These strings are part of the public API of the npm package and the CLI.
/// Renaming a variant is a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../../packages/cert-preview/src/generated/")
)]
pub enum ErrorCode {
    /// Input contained no bytes at all.
    EmptyInput,
    /// Input was readable but held no recognisable certificate object.
    NoObjectFound,
    /// A `-----BEGIN` marker was found but the block is not well formed.
    MalformedPem,
    /// A PEM body failed base64 decoding.
    InvalidBase64,
    /// Bytes were not valid DER for the expected structure.
    DerDecode,
    /// The object kind is recognised but not handled by this build.
    Unsupported,
    /// Input bytes were neither PEM text nor a DER sequence.
    UnknownFormat,
    /// Requested item index does not exist.
    IndexOutOfRange,
    /// The model could not be serialised to JSON.
    Serialization,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EmptyInput => "EMPTY_INPUT",
            Self::NoObjectFound => "NO_OBJECT_FOUND",
            Self::MalformedPem => "MALFORMED_PEM",
            Self::InvalidBase64 => "INVALID_BASE64",
            Self::DerDecode => "DER_DECODE",
            Self::Unsupported => "UNSUPPORTED",
            Self::UnknownFormat => "UNKNOWN_FORMAT",
            Self::IndexOutOfRange => "INDEX_OUT_OF_RANGE",
            Self::Serialization => "SERIALIZATION",
        }
    }
}

impl core::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CertError {
    #[error("input is empty")]
    EmptyInput,

    #[error("no supported certificate or key object found in input")]
    NoObjectFound,

    #[error("malformed PEM at byte offset {offset}: {reason}")]
    MalformedPem { offset: usize, reason: &'static str },

    #[error("invalid base64 payload in PEM block `{label}`")]
    InvalidBase64 { label: String },

    #[error("DER decoding failed for {object}: {reason}")]
    DerDecode { object: &'static str, reason: String },

    #[error("unsupported object type `{label}`")]
    Unsupported { label: String },

    #[error("input is neither PEM text nor a DER encoded structure")]
    UnknownFormat,

    #[error("item index {index} is out of range (bundle holds {len} items)")]
    IndexOutOfRange { index: usize, len: usize },

    #[error("serialisation failed: {reason}")]
    Serialization { reason: String },
}

impl CertError {
    /// The stable discriminator for this error.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::EmptyInput => ErrorCode::EmptyInput,
            Self::NoObjectFound => ErrorCode::NoObjectFound,
            Self::MalformedPem { .. } => ErrorCode::MalformedPem,
            Self::InvalidBase64 { .. } => ErrorCode::InvalidBase64,
            Self::DerDecode { .. } => ErrorCode::DerDecode,
            Self::Unsupported { .. } => ErrorCode::Unsupported,
            Self::UnknownFormat => ErrorCode::UnknownFormat,
            Self::IndexOutOfRange { .. } => ErrorCode::IndexOutOfRange,
            Self::Serialization { .. } => ErrorCode::Serialization,
        }
    }

    /// Byte offset in the original input, when the error can be localised.
    pub fn offset(&self) -> Option<usize> {
        match self {
            Self::MalformedPem { offset, .. } => Some(*offset),
            _ => None,
        }
    }

    pub(crate) fn der(object: &'static str, reason: impl core::fmt::Display) -> Self {
        Self::DerDecode {
            object,
            reason: reason.to_string(),
        }
    }
}

/// Wire representation handed to non-Rust callers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(
    feature = "ts",
    ts(export, export_to = "../../../packages/cert-preview/src/generated/")
)]
pub struct ErrorPayload {
    pub code: ErrorCode,
    pub message: String,
    pub offset: Option<u32>,
}

impl From<&CertError> for ErrorPayload {
    fn from(e: &CertError) -> Self {
        Self {
            code: e.code(),
            message: e.to_string(),
            offset: e.offset().map(|o| o as u32),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_stable_strings() {
        assert_eq!(ErrorCode::MalformedPem.as_str(), "MALFORMED_PEM");
        assert_eq!(
            serde_json::to_string(&ErrorCode::DerDecode).unwrap(),
            "\"DER_DECODE\""
        );
    }

    #[test]
    fn payload_carries_offset() {
        let e = CertError::MalformedPem {
            offset: 42,
            reason: "missing matching END line",
        };
        let p = ErrorPayload::from(&e);
        assert_eq!(p.code, ErrorCode::MalformedPem);
        assert_eq!(p.offset, Some(42));
    }
}
