//! Format sniffing: turn raw bytes into a list of labelled DER objects.

use base64::{engine::general_purpose::STANDARD, Engine};

use super::pem::{self, PemBlock};
use crate::error::{CertError, Result};

/// How the input was encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFormat {
    Pem,
    Der,
    /// Base64 without PEM armour, as pasted from a browser or a config file.
    BareBase64,
}

impl SourceFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pem => "PEM",
            Self::Der => "DER",
            Self::BareBase64 => "BASE64",
        }
    }
}

/// A DER object plus the label it was announced with, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerObject {
    /// PEM label when the source was armoured, otherwise `None`.
    pub label: Option<String>,
    pub der: Vec<u8>,
    pub legacy_encrypted: bool,
    pub offset: usize,
}

impl From<PemBlock> for DerObject {
    fn from(b: PemBlock) -> Self {
        let legacy_encrypted = b.is_legacy_encrypted();
        Self {
            label: Some(b.label),
            der: b.der,
            legacy_encrypted,
            offset: b.offset,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Detected {
    pub format: SourceFormat,
    pub objects: Vec<DerObject>,
}

/// DER structures we care about all start with a SEQUENCE tag.
const DER_SEQUENCE: u8 = 0x30;

/// Identify the encoding of `raw` and extract every DER object it holds.
pub fn detect(raw: &[u8]) -> Result<Detected> {
    if raw.is_empty() {
        return Err(CertError::EmptyInput);
    }

    // Binary DER first: cheapest check, and it cannot be confused with text.
    if raw[0] == DER_SEQUENCE && core::str::from_utf8(raw).is_err() {
        return Ok(Detected {
            format: SourceFormat::Der,
            objects: vec![DerObject {
                label: None,
                der: raw.to_vec(),
                legacy_encrypted: false,
                offset: 0,
            }],
        });
    }

    let Ok(text) = core::str::from_utf8(raw) else {
        // Not UTF-8 and not a leading SEQUENCE.
        return Err(CertError::UnknownFormat);
    };

    if pem::looks_like_pem(text) {
        let blocks = pem::scan(text)?;
        if blocks.is_empty() {
            return Err(CertError::NoObjectFound);
        }
        return Ok(Detected {
            format: SourceFormat::Pem,
            objects: blocks.into_iter().map(DerObject::from).collect(),
        });
    }

    if let Some(der) = try_bare_base64(text) {
        return Ok(Detected {
            format: SourceFormat::BareBase64,
            objects: vec![DerObject {
                label: None,
                der,
                legacy_encrypted: false,
                offset: 0,
            }],
        });
    }

    // Valid UTF-8 that happens to be DER (rare but possible for short inputs).
    if raw[0] == DER_SEQUENCE {
        return Ok(Detected {
            format: SourceFormat::Der,
            objects: vec![DerObject {
                label: None,
                der: raw.to_vec(),
                legacy_encrypted: false,
                offset: 0,
            }],
        });
    }

    Err(CertError::UnknownFormat)
}

fn try_bare_base64(text: &str) -> Option<Vec<u8>> {
    let compact: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() < 8 {
        return None;
    }
    if !compact
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
    {
        return None;
    }
    let der = STANDARD.decode(compact.as_bytes()).ok()?;
    // Only accept it if the result actually looks like DER, otherwise any
    // alphanumeric string would be "successfully" decoded into noise.
    (der.first() == Some(&DER_SEQUENCE)).then_some(der)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_pem_chain() {
        let input = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n\
                     -----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
        let d = detect(input.as_bytes()).unwrap();
        assert_eq!(d.format, SourceFormat::Pem);
        assert_eq!(d.objects.len(), 2);
        assert_eq!(d.objects[0].label.as_deref(), Some("CERTIFICATE"));
    }

    #[test]
    fn detects_binary_der() {
        let raw = [0x30u8, 0x82, 0x01, 0x00, 0xff, 0xfe];
        let d = detect(&raw).unwrap();
        assert_eq!(d.format, SourceFormat::Der);
        assert_eq!(d.objects[0].der, raw);
        assert!(d.objects[0].label.is_none());
    }

    #[test]
    fn detects_bare_base64() {
        // DER without PEM armour, as pasted from a browser or a config snippet.
        // Uses a realistic blob (SEQUENCE wrapping INTEGER 65537 + an empty
        // SEQUENCE) so it clears the short-string guard that exists to avoid
        // misdetecting prose like "MACE" as DER.
        let der = [
            0x30u8, 0x07, 0x02, 0x03, 0x01, 0x00, 0x01, 0x30, 0x00,
        ];
        let b64 = STANDARD.encode(der);
        let d = detect(b64.as_bytes()).unwrap();
        assert_eq!(d.format, SourceFormat::BareBase64);
        assert_eq!(d.objects[0].der, der);
        assert!(d.objects[0].label.is_none());
    }

    #[test]
    fn rejects_plain_prose() {
        assert_eq!(
            detect(b"hello there, this is not a certificate").unwrap_err(),
            CertError::UnknownFormat
        );
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(detect(b"").unwrap_err(), CertError::EmptyInput);
    }
}
