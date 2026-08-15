//! Domain model — the single source of truth for the output schema.
//!
//! Every type here is `serde`-serialisable and, under the `ts` feature, emits a
//! matching TypeScript declaration. That is the mechanism that keeps the
//! browser, server and CLI outputs identical: there is exactly one schema
//! definition and every renderer consumes it.
//!
//! Deliberate omissions:
//!
//! * No "is expired" flag. Expiry depends on the current time, which is an
//!   input, not a property of the certificate. It lives in [`Report`] instead,
//!   so parsing stays deterministic and snapshot-testable.
//! * No private key material. [`PrivateKeyInfo`] carries metadata only.

/// Applies the shared derive set to every model type.
///
/// Declared with `macro_rules!` before the submodules, so it is in textual
/// scope for all of them without an explicit import.
macro_rules! model {
    ($($item:item)*) => {
        $(
            #[derive(Debug, Clone, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
            #[serde(rename_all = "camelCase")]
            #[cfg_attr(feature = "ts", derive(::ts_rs::TS))]
            #[cfg_attr(
                feature = "ts",
                ts(export, export_to = "../../../packages/cert-preview/src/generated/")
            )]
            $item
        )*
    };
}

/// Same as [`model!`] but for plain C-like enums, which are cheap to copy and
/// usable as map keys.
macro_rules! model_enum {
    ($($item:item)*) => {
        $(
            #[derive(
                Debug, Clone, Copy, PartialEq, Eq, Hash,
                ::serde::Serialize, ::serde::Deserialize
            )]
            #[serde(rename_all = "camelCase")]
            #[cfg_attr(feature = "ts", derive(::ts_rs::TS))]
            #[cfg_attr(
                feature = "ts",
                ts(export, export_to = "../../../packages/cert-preview/src/generated/")
            )]
            $item
        )*
    };
}

mod bundle;
mod certificate;
mod chain;
mod diagnostic;
mod extension;
mod key;
mod name;
mod report;

pub use bundle::{Bundle, BundleItem, UnsupportedItem};
pub use certificate::{CertificateInfo, Fingerprints, Validity};
pub use chain::ChainSummary;
pub use diagnostic::{Diagnostic, Severity};
pub use extension::{AccessDescription, BasicConstraintsInfo, Extensions, GeneralNameInfo, RawExtension};
pub use key::{AlgorithmInfo, PrivateKeyFormat, PrivateKeyInfo, PublicKeyInfo};
pub use name::{DistinguishedName, RdnAttribute};
pub use report::{CertificateStatus, HostnameMatch, Report, ValidityState, ValidityStatus};
