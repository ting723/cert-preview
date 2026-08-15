//! Byte level encoding: digests, fingerprints, PEM re-encoding.
//!
//! Kept separate from `parse` so that the hash implementations are the only
//! place in the crate that touches a crypto dependency. Nothing here performs
//! signature verification — see the crate docs for why that is out of scope.

use base64::{engine::general_purpose::STANDARD, Engine};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::model::Fingerprints;
use crate::util::hex_colon;

/// SHA-1 over `data`. Used for fingerprints only — never for validation.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Both conventional fingerprints of a DER encoded certificate.
///
/// The digest is taken over the complete certificate, signature included,
/// which is what `openssl x509 -fingerprint` reports.
pub fn fingerprints(der: &[u8]) -> Fingerprints {
    Fingerprints {
        sha1: hex_colon(&sha1(der)),
        sha256: hex_colon(&sha256(der)),
    }
}

/// Base64 SHA-256 over a DER SubjectPublicKeyInfo — the HPKP / RFC 7469 pin.
///
/// This is the value that lets a caller answer "does this private key belong
/// to this certificate?" without ever handling key material.
pub fn spki_pin(spki_der: &[u8]) -> String {
    STANDARD.encode(sha256(spki_der))
}

/// Re-export: DER -> PEM using the shared 64 column writer.
pub use crate::input::pem::encode as to_pem;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_digests() {
        // NIST vectors for the empty string.
        assert_eq!(
            crate::util::hex(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            crate::util::hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn fingerprints_are_colon_hex() {
        let f = fingerprints(b"abc");
        assert_eq!(f.sha1.len(), 20 * 3 - 1);
        assert_eq!(f.sha256.len(), 32 * 3 - 1);
        assert!(f.sha256.starts_with("ba:78:16:bf"));
    }

    #[test]
    fn pin_is_base64() {
        assert_eq!(spki_pin(b""), "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=");
    }
}
