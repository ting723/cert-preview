//! Public key and private key **metadata** extraction.
//!
//! Security posture: [`PrivateKeyInfo`] has no field able to carry key
//! material, and this module never copies a private component anywhere. The
//! secret parts are read only to measure them (modulus bit length) and then
//! dropped. What a user actually wants from a private key in a viewer is
//! "which algorithm, what size, and does it match this certificate?" — the
//! last question is answered by [`PublicKeyInfo::spki_sha256`], derived from
//! the public half, never from the secret.

use x509_parser::prelude::{FromDer, SubjectPublicKeyInfo};
use x509_parser::public_key::PublicKey;

use super::der::{self, Tlv};
use super::oid;
use crate::encode;
use crate::error::{CertError, Result};
use crate::model::{AlgorithmInfo, PrivateKeyFormat, PrivateKeyInfo, PublicKeyInfo};

/// DER for `AlgorithmIdentifier { rsaEncryption, NULL }`.
const RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];
/// DER for the `id-ecPublicKey` OID.
const EC_PUBLIC_KEY_OID: [u8; 9] = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";

// ---------------------------------------------------------------- public key

/// Map a parsed SubjectPublicKeyInfo onto the domain model.
pub fn public_key(spki: &SubjectPublicKeyInfo<'_>) -> PublicKeyInfo {
    let mut algorithm = oid::algorithm(&spki.algorithm.algorithm);

    // For EC the AlgorithmIdentifier parameters hold the named curve.
    let curve = spki
        .algorithm
        .parameters
        .as_ref()
        .filter(|p| p.tag().0 == u32::from(der::OID))
        .and_then(|p| der::oid_string(p.data))
        .and_then(|d| oid::curve_name(&d).map(str::to_string));
    if let Some(c) = &curve {
        algorithm.parameters = Some(c.clone());
    }

    let parsed = spki.parsed().ok();
    let key_size_bits = match &parsed {
        Some(pk) if pk.key_size() > 0 => Some(pk.key_size() as u32),
        // Ed25519/X25519 and friends encode no parameters and no INTEGERs,
        // so their size comes from the algorithm identity alone.
        _ => curve
            .as_deref()
            .or(Some(algorithm.name.as_str()))
            .and_then(oid::curve_bits),
    };

    let rsa_exponent = match &parsed {
        Some(PublicKey::RSA(rsa)) => Some(match rsa.try_exponent() {
            Ok(e) => e.to_string(),
            Err(_) => format!("0x{}", crate::util::hex(rsa.exponent)),
        }),
        _ => None,
    };

    PublicKeyInfo {
        algorithm,
        key_size_bits,
        curve,
        rsa_exponent,
        spki_sha256: encode::spki_pin(spki.raw),
        der_len: spki.raw.len() as u32,
    }
}

/// Parse a standalone DER SubjectPublicKeyInfo (PEM label `PUBLIC KEY`).
pub fn public_key_from_der(der_bytes: &[u8]) -> Result<PublicKeyInfo> {
    let (rest, spki) = SubjectPublicKeyInfo::from_der(der_bytes)
        .map_err(|e| CertError::der("SubjectPublicKeyInfo", e))?;
    if !rest.is_empty() {
        return Err(CertError::der(
            "SubjectPublicKeyInfo",
            "unexpected trailing bytes",
        ));
    }
    Ok(public_key(&spki))
}

/// Parse a PKCS#1 `RSAPublicKey` (PEM label `RSA PUBLIC KEY`).
///
/// Wrapped into an SPKI first so that there is exactly one code path
/// producing a [`PublicKeyInfo`], and so the pin matches the one computed for
/// the same key inside a certificate.
pub fn rsa_public_key_from_der(der_bytes: &[u8]) -> Result<PublicKeyInfo> {
    let tlv = der::read_exact(der_bytes, "RSAPublicKey")?;
    if !tlv.is(der::SEQUENCE) {
        return Err(CertError::der("RSAPublicKey", "expected a SEQUENCE"));
    }
    let spki = der::write_sequence(&[&RSA_ALGORITHM_ID, &der::write_bit_string(der_bytes)]);
    public_key_from_der(&spki)
}

// --------------------------------------------------------------- private key

/// Identify a private key container from its structure alone.
///
/// Returns `None` when the bytes are not a private key, which is how the
/// bundle dispatcher tells an unlabelled key from an unlabelled certificate.
pub fn sniff_format(der_bytes: &[u8]) -> Option<PrivateKeyFormat> {
    let tlv = der::read_exact(der_bytes, "privateKey").ok()?;
    if !tlv.is(der::SEQUENCE) {
        return None;
    }
    let kids = der::children(tlv.content, "privateKey").ok()?;
    match kids.first()?.tag {
        // EncryptedPrivateKeyInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }
        der::SEQUENCE if kids.len() == 2 && kids[1].is(der::OCTET_STRING) => {
            Some(PrivateKeyFormat::Pkcs8Encrypted)
        }
        der::INTEGER => {
            // PrivateKeyInfo ::= SEQUENCE { INTEGER, AlgorithmIdentifier, OCTET STRING, ... }
            if kids.len() >= 3 && kids[1].is(der::SEQUENCE) && kids[2].is(der::OCTET_STRING) {
                Some(PrivateKeyFormat::Pkcs8)
            // RSAPrivateKey ::= SEQUENCE { INTEGER x 9 or more }
            } else if kids.len() >= 9 && kids[..9].iter().all(|k| k.is(der::INTEGER)) {
                Some(PrivateKeyFormat::Pkcs1)
            // ECPrivateKey ::= SEQUENCE { INTEGER, OCTET STRING, [0], [1] }
            } else if kids.len() >= 2 && kids[1].is(der::OCTET_STRING) {
                Some(PrivateKeyFormat::Sec1)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Extract metadata for a private key of a known container format.
pub fn private_key(der_bytes: &[u8], format: PrivateKeyFormat) -> Result<PrivateKeyInfo> {
    match format {
        PrivateKeyFormat::Pkcs8 => pkcs8(der_bytes),
        PrivateKeyFormat::Pkcs8Encrypted => pkcs8_encrypted(der_bytes),
        PrivateKeyFormat::Pkcs1 => pkcs1(der_bytes),
        PrivateKeyFormat::Sec1 => sec1(der_bytes),
    }
}

/// A key whose body is encrypted with a legacy PEM header. The bytes are
/// ciphertext, so only the declared container type is knowable.
pub fn opaque_encrypted(der_len: usize, format: PrivateKeyFormat) -> PrivateKeyInfo {
    PrivateKeyInfo {
        format,
        algorithm: AlgorithmInfo::new("", "unknown (encrypted)"),
        key_size_bits: None,
        curve: None,
        encrypted: true,
        public_key: None,
        der_len: der_len as u32,
    }
}

fn pkcs8(bytes: &[u8]) -> Result<PrivateKeyInfo> {
    const OBJ: &str = "PrivateKeyInfo";
    let kids = sequence(bytes, OBJ)?;
    if kids.len() < 3 {
        return Err(CertError::der(OBJ, "too few fields"));
    }
    let alg_tlv = kids[1];
    let (mut algorithm, curve) = algorithm_identifier(alg_tlv, OBJ)?;
    let inner = kids[2].content;

    let mut key_size_bits = curve.as_deref().and_then(oid::curve_bits);
    let mut spki = None;

    // RFC 5958 stores the public half in an IMPLICIT [1] BIT STRING.
    if let Some(pk) = kids
        .iter()
        .find(|k| k.tag == der::context_primitive(1) || k.tag == der::context(1))
    {
        let bits = if pk.tag == der::context(1) {
            der::read_exact(pk.content, OBJ)?.content
        } else {
            pk.content
        };
        spki = Some(der::write_sequence(&[
            alg_tlv.raw,
            &der::write_tlv(der::BIT_STRING, bits),
        ]));
    }

    match algorithm.oid.as_str() {
        OID_RSA => {
            let rsa = rsa_components(inner)?;
            key_size_bits = der::integer_bit_length(rsa.0.content);
            if spki.is_none() {
                spki = Some(rsa_spki(rsa));
            }
        }
        OID_EC => {
            let ec = ec_components(inner)?;
            if let Some(c) = ec.curve.clone() {
                key_size_bits = oid::curve_bits(&c);
                if algorithm.parameters.is_none() {
                    algorithm.parameters = Some(c);
                }
            }
            if spki.is_none() {
                spki = ec_spki(&ec, alg_tlv);
            }
        }
        _ => {}
    }

    if key_size_bits.is_none() {
        key_size_bits = oid::curve_bits(&algorithm.name);
    }

    Ok(PrivateKeyInfo {
        format: PrivateKeyFormat::Pkcs8,
        algorithm,
        key_size_bits,
        curve,
        encrypted: false,
        public_key: spki.as_deref().and_then(|s| public_key_from_der(s).ok()),
        der_len: bytes.len() as u32,
    })
}

fn pkcs8_encrypted(bytes: &[u8]) -> Result<PrivateKeyInfo> {
    const OBJ: &str = "EncryptedPrivateKeyInfo";
    let kids = sequence(bytes, OBJ)?;
    if kids.len() != 2 {
        return Err(CertError::der(OBJ, "expected two fields"));
    }
    let (algorithm, _) = algorithm_identifier(kids[0], OBJ)?;
    Ok(PrivateKeyInfo {
        format: PrivateKeyFormat::Pkcs8Encrypted,
        algorithm,
        key_size_bits: None,
        curve: None,
        encrypted: true,
        public_key: None,
        der_len: bytes.len() as u32,
    })
}

fn pkcs1(bytes: &[u8]) -> Result<PrivateKeyInfo> {
    const OBJ: &str = "RSAPrivateKey";
    let kids = sequence(bytes, OBJ)?;
    if kids.len() < 3 {
        return Err(CertError::der(OBJ, "too few fields"));
    }
    let modulus = kids[1];
    let exponent = kids[2];
    let spki = rsa_spki((modulus, exponent));
    Ok(PrivateKeyInfo {
        format: PrivateKeyFormat::Pkcs1,
        algorithm: AlgorithmInfo::new(OID_RSA, "rsaEncryption"),
        key_size_bits: der::integer_bit_length(modulus.content),
        curve: None,
        encrypted: false,
        public_key: public_key_from_der(&spki).ok(),
        der_len: bytes.len() as u32,
    })
}

fn sec1(bytes: &[u8]) -> Result<PrivateKeyInfo> {
    let ec = ec_components(bytes)?;
    let mut algorithm = AlgorithmInfo::new(OID_EC, "id-ecPublicKey");
    algorithm.parameters = ec.curve.clone();
    let alg_der = der::write_sequence(&[&EC_PUBLIC_KEY_OID, ec.curve_oid_der.as_deref().unwrap_or(&[])]);
    let spki = ec
        .public_bits
        .as_ref()
        .map(|bits| der::write_sequence(&[&alg_der, &der::write_tlv(der::BIT_STRING, bits)]));
    Ok(PrivateKeyInfo {
        format: PrivateKeyFormat::Sec1,
        algorithm,
        key_size_bits: ec.curve.as_deref().and_then(oid::curve_bits),
        curve: ec.curve,
        encrypted: false,
        public_key: spki.as_deref().and_then(|s| public_key_from_der(s).ok()),
        der_len: bytes.len() as u32,
    })
}

// ------------------------------------------------------------------- helpers

fn sequence<'a>(bytes: &'a [u8], object: &'static str) -> Result<Vec<Tlv<'a>>> {
    let tlv = der::read_exact(bytes, object)?;
    if !tlv.is(der::SEQUENCE) {
        return Err(CertError::der(object, "expected a SEQUENCE"));
    }
    der::children(tlv.content, object)
}

/// `AlgorithmIdentifier ::= SEQUENCE { OBJECT IDENTIFIER, ANY OPTIONAL }`
fn algorithm_identifier(
    tlv: Tlv<'_>,
    object: &'static str,
) -> Result<(AlgorithmInfo, Option<String>)> {
    if !tlv.is(der::SEQUENCE) {
        return Err(CertError::der(object, "AlgorithmIdentifier is not a SEQUENCE"));
    }
    let kids = der::children(tlv.content, object)?;
    let head = kids
        .first()
        .filter(|k| k.is(der::OID))
        .ok_or_else(|| CertError::der(object, "AlgorithmIdentifier has no OID"))?;
    let dotted = der::oid_string(head.content)
        .ok_or_else(|| CertError::der(object, "malformed algorithm OID"))?;

    let curve = kids
        .get(1)
        .filter(|k| k.is(der::OID))
        .and_then(|k| der::oid_string(k.content))
        .and_then(|d| oid::curve_name(&d).map(str::to_string));

    let name = oid::curve_name(&dotted)
        .or_else(|| oid::eku_name(&dotted))
        .map(str::to_string)
        .unwrap_or_else(|| lookup_name(&dotted));

    let mut info = AlgorithmInfo::new(dotted, name);
    info.parameters = curve.clone();
    Ok((info, curve))
}

/// Resolve a dotted OID without needing an `Oid` value.
fn lookup_name(dotted: &str) -> String {
    // The registry lookup requires an Oid, which we would have to re-encode;
    // the local table already covers every algorithm we can act on, and
    // anything else is honestly reported as its OID.
    match dotted {
        OID_RSA => "rsaEncryption".to_string(),
        OID_EC => "id-ecPublicKey".to_string(),
        "1.2.840.10040.4.1" => "id-dsa".to_string(),
        "1.3.101.110" => "X25519".to_string(),
        "1.3.101.111" => "X448".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        "1.2.840.113549.1.5.13" => "PBES2".to_string(),
        "1.2.840.113549.1.12.1.3" => "pbeWithSHA1And3-KeyTripleDES-CBC".to_string(),
        other => other.to_string(),
    }
}

/// `(modulus, publicExponent)` from a PKCS#1 RSAPrivateKey body.
fn rsa_components(bytes: &[u8]) -> Result<(Tlv<'_>, Tlv<'_>)> {
    let kids = sequence(bytes, "RSAPrivateKey")?;
    if kids.len() < 3 || !kids[1].is(der::INTEGER) || !kids[2].is(der::INTEGER) {
        return Err(CertError::der("RSAPrivateKey", "missing modulus or exponent"));
    }
    Ok((kids[1], kids[2]))
}

fn rsa_spki((modulus, exponent): (Tlv<'_>, Tlv<'_>)) -> Vec<u8> {
    let rsa_pub = der::write_sequence(&[modulus.raw, exponent.raw]);
    der::write_sequence(&[&RSA_ALGORITHM_ID, &der::write_bit_string(&rsa_pub)])
}

#[derive(Default)]
struct EcComponents {
    curve: Option<String>,
    curve_oid_der: Option<Vec<u8>>,
    public_bits: Option<Vec<u8>>,
}

/// Curve and public point from a SEC1 ECPrivateKey body, ignoring the secret.
fn ec_components(bytes: &[u8]) -> Result<EcComponents> {
    const OBJ: &str = "ECPrivateKey";
    let kids = sequence(bytes, OBJ)?;
    let mut out = EcComponents::default();
    for k in &kids {
        if k.tag == der::context(0) {
            let inner = der::read_exact(k.content, OBJ)?;
            if inner.is(der::OID) {
                out.curve_oid_der = Some(inner.raw.to_vec());
                out.curve = der::oid_string(inner.content)
                    .and_then(|d| oid::curve_name(&d).map(str::to_string));
            }
        } else if k.tag == der::context(1) {
            let inner = der::read_exact(k.content, OBJ)?;
            if inner.is(der::BIT_STRING) && !inner.content.is_empty() {
                // Drop the unused-bit-count octet; the writer re-adds it.
                out.public_bits = Some(inner.content[1..].to_vec());
            }
        }
    }
    Ok(out)
}

fn ec_spki(ec: &EcComponents, alg_tlv: Tlv<'_>) -> Option<Vec<u8>> {
    let bits = ec.public_bits.as_ref()?;
    // `ec_components` already dropped the leading unused-bit-count octet, so
    // re-add it via `write_bit_string` to emit a valid BIT STRING.
    Some(der::write_sequence(&[
        alg_tlv.raw,
        &der::write_bit_string(bits),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sniffs_pkcs8() {
        // SEQUENCE { INTEGER 0, SEQUENCE {}, OCTET STRING {} }
        let der_bytes = [0x30, 0x09, 0x02, 0x01, 0x00, 0x30, 0x00, 0x04, 0x02, 0xaa, 0xbb];
        assert_eq!(sniff_format(&der_bytes), Some(PrivateKeyFormat::Pkcs8));
    }

    #[test]
    fn sniffs_encrypted_pkcs8() {
        // SEQUENCE { SEQUENCE {}, OCTET STRING {} }
        let der_bytes = [0x30, 0x06, 0x30, 0x00, 0x04, 0x02, 0xaa, 0xbb];
        assert_eq!(
            sniff_format(&der_bytes),
            Some(PrivateKeyFormat::Pkcs8Encrypted)
        );
    }

    #[test]
    fn sniffs_sec1() {
        // SEQUENCE { INTEGER 1, OCTET STRING {} }
        let der_bytes = [0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0xaa, 0xbb];
        assert_eq!(sniff_format(&der_bytes), Some(PrivateKeyFormat::Sec1));
    }

    #[test]
    fn rejects_non_keys() {
        // An SPKI: SEQUENCE { SEQUENCE {}, BIT STRING }
        let spki = [0x30, 0x06, 0x30, 0x00, 0x03, 0x02, 0x00, 0xff];
        assert_eq!(sniff_format(&spki), None);
        assert_eq!(sniff_format(&[0x02, 0x01, 0x00]), None);
    }

    #[test]
    fn opaque_encrypted_reports_only_the_container() {
        let k = opaque_encrypted(1234, PrivateKeyFormat::Pkcs1);
        assert!(k.encrypted);
        assert!(k.key_size_bits.is_none());
        assert!(k.public_key.is_none());
        assert_eq!(k.der_len, 1234);
    }
}
