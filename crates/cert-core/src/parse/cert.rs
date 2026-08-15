//! X.509 certificate parsing.
//!
//! The diagnostics emitted here are strictly **time independent** — they are
//! properties of the bytes, not of the moment you looked at them. Anything
//! that depends on the current clock or on a hostname belongs in `verify`.
//! Keeping that line sharp is what makes a parsed [`Bundle`](crate::model::Bundle)
//! byte-for-byte reproducible, and therefore snapshot-testable across Rust,
//! Node and the browser.

use x509_parser::prelude::{FromDer, X509Certificate};

use super::{ext, name, oid};
use crate::encode;
use crate::error::{CertError, Result};
use crate::model::{CertificateInfo, Diagnostic, Validity};
use crate::util::{format_utc, hex_colon};

/// CA/Browser Forum ballot SC-22: TLS server certificates issued after
/// 2020-09-01 may not be valid for more than 398 days.
const MAX_TLS_LIFETIME_DAYS: i64 = 398;

pub struct ParsedCertificate {
    pub info: CertificateInfo,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn certificate(der: &[u8]) -> Result<ParsedCertificate> {
    let (rest, cert) =
        X509Certificate::from_der(der).map_err(|e| CertError::der("certificate", e))?;

    let mut diagnostics = Vec::new();
    if !rest.is_empty() {
        diagnostics.push(Diagnostic::warn(
            "TRAILING_BYTES",
            format!("{} byte(s) follow the certificate and were ignored", rest.len()),
        ));
    }

    let tbs = &cert.tbs_certificate;
    let subject = name::distinguished_name(&tbs.subject);
    let issuer = name::distinguished_name(&tbs.issuer);
    let extensions = ext::extensions(tbs.extensions());
    let public_key = super::key::public_key(&tbs.subject_pki);
    let signature_algorithm = oid::algorithm(&cert.signature_algorithm.algorithm);

    let not_before = tbs.validity.not_before.timestamp();
    let not_after = tbs.validity.not_after.timestamp();
    let validity = Validity {
        not_before,
        not_after,
        not_before_utc: format_utc(not_before),
        not_after_utc: format_utc(not_after),
    };

    let version = u8::try_from(tbs.version.0.saturating_add(1)).unwrap_or(u8::MAX);

    let info = CertificateInfo {
        version,
        serial_number: hex_colon(tbs.raw_serial()),
        self_issued: tbs.subject.as_raw() == tbs.issuer.as_raw(),
        subject,
        issuer,
        validity,
        public_key,
        signature_algorithm,
        extensions,
        fingerprints: encode::fingerprints(&der[..der.len() - rest.len()]),
        der_len: (der.len() - rest.len()) as u32,
    };

    audit(&cert, &info, &mut diagnostics);

    Ok(ParsedCertificate { info, diagnostics })
}

/// Structural findings that need no clock and no hostname.
fn audit(cert: &X509Certificate<'_>, info: &CertificateInfo, out: &mut Vec<Diagnostic>) {
    let tbs = &cert.tbs_certificate;

    // RFC 5280 §4.1.1.2: the outer and inner signature algorithms must match.
    // A mismatch is a classic signature-substitution red flag.
    if tbs.signature.algorithm != cert.signature_algorithm.algorithm {
        out.push(Diagnostic::error(
            "SIGNATURE_ALGORITHM_MISMATCH",
            format!(
                "tbsCertificate.signature ({}) differs from the outer signatureAlgorithm ({})",
                oid::name_of(&tbs.signature.algorithm),
                info.signature_algorithm.name
            ),
        ));
    }

    if oid::is_weak_signature(&info.signature_algorithm.oid) {
        out.push(Diagnostic::warn(
            "WEAK_SIGNATURE_ALGORITHM",
            format!(
                "signed with {}, which is no longer collision resistant",
                info.signature_algorithm.name
            ),
        ));
    }

    if let Some(bits) = info.public_key.key_size_bits {
        let weak = match info.public_key.algorithm.oid.as_str() {
            "1.2.840.113549.1.1.1" | "1.2.840.10040.4.1" => bits < 2048,
            "1.2.840.10045.2.1" => bits < 224,
            _ => false,
        };
        if weak {
            out.push(Diagnostic::warn(
                "WEAK_KEY",
                format!("{} is below current minimums", info.public_key.summary()),
            ));
        }
    }

    for o in &info.extensions.unhandled_critical {
        out.push(Diagnostic::error(
            "UNHANDLED_CRITICAL_EXTENSION",
            format!("critical extension {o} is not understood by this build"),
        ));
    }

    if info.version < 3 && !tbs.extensions().is_empty() {
        out.push(Diagnostic::warn(
            "EXTENSIONS_IN_PRE_V3",
            format!("v{} certificate carries extensions", info.version),
        ));
    }

    if tbs.raw_serial().is_empty() || tbs.raw_serial().iter().all(|b| *b == 0) {
        out.push(Diagnostic::warn(
            "SERIAL_NOT_POSITIVE",
            "serial number is zero; RFC 5280 requires a positive integer",
        ));
    } else if tbs.raw_serial()[0] & 0x80 != 0 {
        out.push(Diagnostic::warn(
            "SERIAL_NEGATIVE",
            "serial number is encoded as a negative integer",
        ));
    }

    let is_ca = info.is_ca();
    if info.subject.is_empty() && info.extensions.subject_alt_names.is_empty() {
        out.push(Diagnostic::error(
            "EMPTY_SUBJECT_WITHOUT_SAN",
            "subject is empty and no subjectAltName is present; the certificate identifies nothing",
        ));
    }

    let is_tls_server = info
        .extensions
        .extended_key_usage
        .iter()
        .any(|u| u == "serverAuth" || u == "anyExtendedKeyUsage");

    if !is_ca && info.extensions.subject_alt_names.is_empty() {
        out.push(Diagnostic::warn(
            "NO_SUBJECT_ALT_NAME",
            "no subjectAltName; browsers have ignored commonName for host matching since 2017",
        ));
    }

    if is_ca && !info.extensions.key_usage.is_empty() && !info
        .extensions
        .key_usage
        .iter()
        .any(|u| u == "keyCertSign")
    {
        out.push(Diagnostic::error(
            "CA_WITHOUT_KEY_CERT_SIGN",
            "basicConstraints says CA but keyUsage omits keyCertSign",
        ));
    }

    if !is_ca && is_tls_server {
        let days = info.validity.lifetime_seconds() / 86_400;
        if days > MAX_TLS_LIFETIME_DAYS {
            out.push(Diagnostic::warn(
                "LIFETIME_TOO_LONG",
                format!(
                    "valid for {days} days; CA/Browser Forum caps TLS server certificates at {MAX_TLS_LIFETIME_DAYS}"
                ),
            ));
        }
    }

    if info.validity.not_after < info.validity.not_before {
        out.push(Diagnostic::error(
            "VALIDITY_INVERTED",
            "notAfter precedes notBefore",
        ));
    }
}
