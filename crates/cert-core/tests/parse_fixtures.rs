//! End-to-end verification of the parse layer against the committed fixtures.
//!
//! These tests prove the parser produces the *structure* the renderers depend
//! on: correct object counts, preserved order, resolved names, and the
//! security-relevant facts (self-signed, weak key, long lifetime). They are
//! the Rust half of the cross-platform snapshot contract — the same fixtures
//! drive the Node/browser tests and must yield byte-identical model JSON.

use cert_core::model::*;
use cert_core::parse_bundle;

fn fixture(path: &str) -> Vec<u8> {
    let full = format!("{}/../../fixtures/{}", env!("CARGO_MANIFEST_DIR"), path);
    std::fs::read(&full).unwrap_or_else(|e| panic!("read {full}: {e}"))
}

fn bundle(path: &str) -> Bundle {
    let raw = fixture(path);
    parse_bundle(&raw).unwrap_or_else(|e| panic!("parse {path}: {e:?}"))
}

fn cert_at(b: &Bundle, i: usize) -> &CertificateInfo {
    match &b.items[i] {
        BundleItem::Certificate(c) => c,
        other => panic!("item {i} is `{}`, expected certificate", other.kind()),
    }
}

fn private_at(b: &Bundle, i: usize) -> &PrivateKeyInfo {
    match &b.items[i] {
        BundleItem::PrivateKey(k) => k,
        other => panic!("item {i} is `{}`, expected private key", other.kind()),
    }
}

fn public_at(b: &Bundle, i: usize) -> &PublicKeyInfo {
    match &b.items[i] {
        BundleItem::PublicKey(k) => k,
        other => panic!("item {i} is `{}`, expected public key", other.kind()),
    }
}

fn code_seen(b: &Bundle, code: &str) -> bool {
    b.diagnostics.iter().any(|d| d.code == code)
}

// ----------------------------------------------------------------- certificates

#[test]
fn chain_pem_yields_three_certificates_in_file_order() {
    // chain.pem concatenates leaf, inter, root — order preserved (linking is
    // a verify-layer concern, not parsing).
    let b = bundle("certs/chain.pem");
    assert_eq!(b.source_format, "PEM");
    assert_eq!(b.certificate_count(), 3);
    assert_eq!(cert_at(&b, 0).subject.common_name.as_deref(), Some("www.example.org"));
    assert_eq!(cert_at(&b, 1).subject.common_name.as_deref(), Some("Example Issuing CA"));
    assert_eq!(cert_at(&b, 2).subject.common_name.as_deref(), Some("Example Root CA"));
}

#[test]
fn root_is_self_signed_ca() {
    let b = bundle("certs/root.pem");
    let c = cert_at(&b, 0);
    assert_eq!(c.version, 3);
    assert!(c.self_issued, "subject must equal issuer for a root");
    assert!(c.is_ca());
    assert_eq!(c.public_key.key_size_bits, Some(2048));
    assert!(c.extensions.key_usage.iter().any(|u| u == "keyCertSign"));
    assert!(c.extensions.key_usage.iter().any(|u| u == "cRLSign"));
    // A well-formed 2024 root carries no time-dependent or structural warnings.
    assert!(b.diagnostics.is_empty());
}

#[test]
fn leaf_certificate_is_not_a_ca_and_has_san() {
    let b = bundle("certs/leaf.pem");
    let c = cert_at(&b, 0);
    assert!(!c.is_ca());
    assert!(!c.self_issued);
    assert_eq!(c.public_key.algorithm.name, "rsaEncryption");
    assert_eq!(c.public_key.key_size_bits, Some(2048));
    let dns: Vec<&str> = c.extensions.dns_names().collect();
    assert_eq!(dns, vec!["www.example.org", "example.org"]);
    assert!(b.diagnostics.is_empty());
}

#[test]
fn rsa_leaf_with_excessive_lifetime_is_flagged() {
    let b = bundle("certs/rsa-leaf.pem");
    let c = cert_at(&b, 0);
    assert_eq!(c.subject.common_name.as_deref(), Some("example.com"));
    assert_eq!(c.signature_algorithm.name, "sha256WithRSAEncryption");
    assert_eq!(c.validity.not_before_utc, "2024-01-01T00:00:00Z");
    assert_eq!(c.validity.not_after_utc, "2034-01-01T00:00:00Z");
    // 3653 days > 398-day CA/Browser Forum cap for TLS server certificates.
    assert!(code_seen(&b, "LIFETIME_TOO_LONG"));
    // SAN is present, so NO_SUBJECT_ALT_NAME must not fire.
    assert!(!code_seen(&b, "NO_SUBJECT_ALT_NAME"));
}

#[test]
fn ec_leaf_is_prime256v1() {
    let b = bundle("certs/ec-leaf.pem");
    let c = cert_at(&b, 0);
    assert_eq!(c.subject.common_name.as_deref(), Some("ec.example.com"));
    assert_eq!(c.public_key.algorithm.name, "id-ecPublicKey");
    assert_eq!(c.public_key.curve.as_deref(), Some("prime256v1"));
    assert_eq!(c.public_key.key_size_bits, Some(256));
    assert_eq!(c.signature_algorithm.name, "ecdsa-with-SHA256");
}

#[test]
fn parser_does_not_reorder_a_shuffled_chain() {
    // chain-shuffled.pem is root, leaf, inter. The parser must surface them in
    // file order; reordering would be a verify-layer job.
    let b = bundle("certs/chain-shuffled.pem");
    assert_eq!(b.certificate_count(), 3);
    assert_eq!(cert_at(&b, 0).subject.common_name.as_deref(), Some("Example Root CA"));
    assert_eq!(cert_at(&b, 1).subject.common_name.as_deref(), Some("www.example.org"));
    assert_eq!(cert_at(&b, 2).subject.common_name.as_deref(), Some("Example Issuing CA"));
}

#[test]
fn incomplete_chain_is_a_single_certificate() {
    let b = bundle("certs/chain-incomplete.pem");
    assert_eq!(b.certificate_count(), 1);
}

#[test]
fn der_rsa_leaf_parses_without_pem_armour() {
    let b = bundle("certs/rsa-leaf.der");
    assert_eq!(b.source_format, "DER");
    assert_eq!(b.certificate_count(), 1);
    assert_eq!(cert_at(&b, 0).subject.common_name.as_deref(), Some("example.com"));
}

// ----------------------------------------------------------------------- keys

#[test]
fn rsa_pkcs8_reports_metadata_only() {
    let b = bundle("keys/rsa-2048.pkcs8.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Pkcs8);
    assert_eq!(k.algorithm.name, "rsaEncryption");
    assert_eq!(k.key_size_bits, Some(2048));
    assert!(!k.encrypted);
    // The public half is embedded and must be derivable.
    let pubkey = k.public_key.as_ref().expect("PKCS#8 carries the public half");
    assert_eq!(pubkey.key_size_bits, Some(2048));
    assert!(!pubkey.spki_sha256.is_empty());
}

#[test]
fn rsa_pkcs1_reports_modulus_size() {
    let b = bundle("keys/rsa-2048.pkcs1.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Pkcs1);
    assert_eq!(k.key_size_bits, Some(2048));
    assert!(k.public_key.is_some());
}

#[test]
fn rsa_spki_is_a_public_key() {
    let b = bundle("keys/rsa-2048.spki.pem");
    let k = public_at(&b, 0);
    assert_eq!(k.algorithm.name, "rsaEncryption");
    assert_eq!(k.key_size_bits, Some(2048));
    assert!(!k.spki_sha256.is_empty());
}

#[test]
fn rsa_pkcs1_public_key_wraps_into_spki() {
    let b = bundle("keys/rsa-2048.pkcs1-pub.pem");
    let k = public_at(&b, 0);
    assert_eq!(k.algorithm.name, "rsaEncryption");
    assert_eq!(k.key_size_bits, Some(2048));
    assert!(!k.spki_sha256.is_empty());
}

#[test]
fn ec_pkcs8_is_p256() {
    let b = bundle("keys/ec-p256.pkcs8.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Pkcs8);
    assert_eq!(k.curve.as_deref(), Some("prime256v1"));
    assert_eq!(k.key_size_bits, Some(256));
    assert!(k.public_key.is_some());
}

#[test]
fn ec_sec1_is_detected() {
    let b = bundle("keys/ec-p256.sec1.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Sec1);
    assert_eq!(k.curve.as_deref(), Some("prime256v1"));
    assert_eq!(k.key_size_bits, Some(256));
}

#[test]
fn ed25519_pkcs8_resolves_algorithm_and_size() {
    let b = bundle("keys/ed25519.pkcs8.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Pkcs8);
    assert_eq!(k.algorithm.name, "Ed25519");
    assert_eq!(k.key_size_bits, Some(256));
    // This fixture's PKCS#8 omits the public half (OpenSSL packs only the
    // 32-byte seed), so no pinning key can be derived — and the parser must
    // not fabricate one.
    assert!(k.public_key.is_none());
}

#[test]
fn encrypted_pkcs8_reports_container_only() {
    let b = bundle("keys/rsa-2048.encrypted.pem");
    let k = private_at(&b, 0);
    assert_eq!(k.format, PrivateKeyFormat::Pkcs8Encrypted);
    assert!(k.encrypted);
    assert!(k.key_size_bits.is_none(), "no key material may be recovered");
    assert!(k.public_key.is_none(), "no key material may be recovered");
    assert_eq!(k.algorithm.name, "PBES2");
}
