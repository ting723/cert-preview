//! Turning raw input into a [`Bundle`].
//!
//! Dispatch is label-driven when the input was PEM and structure-driven
//! otherwise. A object that cannot be modelled becomes an
//! [`UnsupportedItem`] rather than an error: a chain file with one damaged
//! entry should still show the other three.

use crate::error::{CertError, Result};
use crate::input::detect::{self, DerObject};
use crate::model::{Bundle, BundleItem, Diagnostic, PrivateKeyFormat, UnsupportedItem};

/// Parse every object in `raw`.
///
/// The returned bundle has an empty `chains` list; chain linking is a separate
/// step in `verify` so that this function stays a pure, total mapping from
/// bytes to structure.
pub fn bundle(raw: &[u8]) -> Result<Bundle> {
    let detected = detect::detect(raw)?;

    let mut items = Vec::with_capacity(detected.objects.len());
    let mut diagnostics = Vec::new();

    for obj in &detected.objects {
        let index = items.len();
        let (item, mut diags) = classify(obj);
        for d in &mut diags {
            d.item = Some(index as u32);
        }
        diagnostics.append(&mut diags);
        items.push(item);
    }

    if items.is_empty() {
        return Err(CertError::NoObjectFound);
    }

    Ok(Bundle {
        source_format: detected.format.as_str().to_string(),
        items,
        chains: Vec::new(),
        diagnostics,
    })
}

fn classify(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    let label = obj.label.as_deref().map(str::to_ascii_uppercase);
    match label.as_deref() {
        Some("CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE") => certificate(obj),
        Some("PUBLIC KEY") => spki(obj),
        Some("RSA PUBLIC KEY") => rsa_public(obj),
        Some("PRIVATE KEY") => private(obj, PrivateKeyFormat::Pkcs8),
        Some("ENCRYPTED PRIVATE KEY") => private(obj, PrivateKeyFormat::Pkcs8Encrypted),
        Some("RSA PRIVATE KEY") => private(obj, PrivateKeyFormat::Pkcs1),
        Some("EC PRIVATE KEY") => private(obj, PrivateKeyFormat::Sec1),
        Some("CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST") => {
            unsupported(obj, "certificate signing requests are not handled by this build")
        }
        Some("X509 CRL") => unsupported(obj, "certificate revocation lists are not handled"),
        Some(other) => unsupported(obj, format!("PEM label `{other}` is not a known object type")),
        None => sniff(obj),
    }
}

/// No label: identify by structure. Certificates first, since that is what
/// almost every unlabelled `.der`/`.cer` file turns out to be.
fn sniff(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    #[cfg(feature = "x509")]
    {
        if let Ok(parsed) = crate::parse::cert::certificate(&obj.der) {
            return (
                BundleItem::Certificate(parsed.info),
                parsed.diagnostics,
            );
        }
    }
    #[cfg(feature = "key")]
    {
        if let Some(format) = crate::parse::key::sniff_format(&obj.der) {
            return private(obj, format);
        }
        if let Ok(pk) = crate::parse::key::public_key_from_der(&obj.der) {
            return (BundleItem::PublicKey(pk), Vec::new());
        }
    }
    unsupported(
        obj,
        "bytes are DER but do not match a certificate, public key or private key",
    )
}

#[cfg(feature = "x509")]
fn certificate(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    match crate::parse::cert::certificate(&obj.der) {
        Ok(parsed) => (BundleItem::Certificate(parsed.info), parsed.diagnostics),
        Err(e) => unsupported(obj, e.to_string()),
    }
}

#[cfg(not(feature = "x509"))]
fn certificate(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    unsupported(obj, "this build was compiled without the `x509` feature")
}

#[cfg(feature = "key")]
fn spki(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    match crate::parse::key::public_key_from_der(&obj.der) {
        Ok(pk) => (BundleItem::PublicKey(pk), Vec::new()),
        Err(e) => unsupported(obj, e.to_string()),
    }
}

#[cfg(feature = "key")]
fn rsa_public(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    match crate::parse::key::rsa_public_key_from_der(&obj.der) {
        Ok(pk) => (BundleItem::PublicKey(pk), Vec::new()),
        Err(e) => unsupported(obj, e.to_string()),
    }
}

#[cfg(feature = "key")]
fn private(obj: &DerObject, format: PrivateKeyFormat) -> (BundleItem, Vec<Diagnostic>) {
    use crate::parse::key;

    // A legacy `Proc-Type: 4,ENCRYPTED` header means the body is ciphertext,
    // not DER. Report the container honestly instead of failing to parse it.
    if obj.legacy_encrypted {
        return (
            BundleItem::PrivateKey(key::opaque_encrypted(obj.der.len(), format)),
            vec![Diagnostic::info(
                "LEGACY_ENCRYPTED_KEY",
                "key body is encrypted with a legacy PEM header; only the container is readable",
            )],
        );
    }

    match key::private_key(&obj.der, format) {
        Ok(info) => (BundleItem::PrivateKey(info), Vec::new()),
        Err(e) => unsupported(obj, e.to_string()),
    }
}

#[cfg(not(feature = "key"))]
fn spki(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    unsupported(obj, "this build was compiled without the `key` feature")
}

#[cfg(not(feature = "key"))]
fn rsa_public(obj: &DerObject) -> (BundleItem, Vec<Diagnostic>) {
    unsupported(obj, "this build was compiled without the `key` feature")
}

#[cfg(not(feature = "key"))]
fn private(obj: &DerObject, _format: PrivateKeyFormat) -> (BundleItem, Vec<Diagnostic>) {
    unsupported(obj, "this build was compiled without the `key` feature")
}

fn unsupported(obj: &DerObject, reason: impl Into<String>) -> (BundleItem, Vec<Diagnostic>) {
    let reason = reason.into();
    let diag = Diagnostic::warn("UNSUPPORTED_OBJECT", reason.clone());
    (
        BundleItem::Unsupported(UnsupportedItem {
            label: obj.label.clone(),
            reason,
            der_len: obj.der.len() as u32,
        }),
        vec![diag],
    )
}
