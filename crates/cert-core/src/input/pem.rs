//! Hand-written RFC 7468 PEM scanner.
//!
//! Replaces the previous regex-based implementation. Two reasons:
//!
//! 1. `regex` costs roughly 200 KB in a wasm32 build for what amounts to
//!    matching two fixed ASCII prefixes.
//! 2. The old implementation stripped *all* `-----BEGIN/END-----` markers from
//!    the whole input and concatenated whatever was left, which silently
//!    corrupted any multi-object input such as a certificate chain.
//!
//! This scanner walks the input block by block and preserves object boundaries.

use base64::{engine::general_purpose::STANDARD, Engine};

use crate::error::{CertError, Result};

const BEGIN: &[u8] = b"-----BEGIN ";
const END: &[u8] = b"-----END ";
const DASHES: &[u8] = b"-----";

/// One decoded PEM block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PemBlock {
    /// Label between the dashes, e.g. `CERTIFICATE`, `PRIVATE KEY`.
    pub label: String,
    /// Base64-decoded body.
    pub der: Vec<u8>,
    /// RFC 1421 headers (`Proc-Type`, `DEK-Info`) when present.
    pub headers: Vec<(String, String)>,
    /// Byte offset of the `-----BEGIN` marker within the original input.
    pub offset: usize,
}

impl PemBlock {
    /// Legacy OpenSSL encrypted PEM is signalled by `Proc-Type: 4,ENCRYPTED`.
    pub fn is_legacy_encrypted(&self) -> bool {
        self.headers
            .iter()
            .any(|(k, v)| k.eq_ignore_ascii_case("Proc-Type") && v.contains("ENCRYPTED"))
    }
}

/// True when the input looks like it contains at least one PEM block.
pub fn looks_like_pem(input: &str) -> bool {
    find(input.as_bytes(), BEGIN).is_some()
}

/// Scan every PEM block in `input`, in document order.
///
/// Text between blocks (explanatory headers produced by `openssl x509 -text`,
/// for instance) is ignored. A `BEGIN` marker without a matching `END` is a
/// hard error rather than a silent skip, because silently dropping half a
/// chain is far more damaging than a loud failure.
pub fn scan(input: &str) -> Result<Vec<PemBlock>> {
    let bytes = input.as_bytes();
    let mut blocks = Vec::new();
    let mut cursor = 0usize;

    while let Some(rel) = find(&bytes[cursor..], BEGIN) {
        let begin_at = cursor + rel;
        let label_start = begin_at + BEGIN.len();

        let label_end = label_start
            + find(&bytes[label_start..], DASHES).ok_or(CertError::MalformedPem {
                offset: begin_at,
                reason: "BEGIN line is not terminated by `-----`",
            })?;

        let label = input[label_start..label_end].trim().to_string();
        if label.is_empty() {
            return Err(CertError::MalformedPem {
                offset: begin_at,
                reason: "BEGIN marker has an empty label",
            });
        }

        let body_start = label_end + DASHES.len();
        let end_marker = build_end_marker(&label);
        let end_at = body_start
            + find(&bytes[body_start..], &end_marker).ok_or(CertError::MalformedPem {
                offset: begin_at,
                reason: "missing matching END line for this block",
            })?;

        let (headers, b64) = split_headers(&input[body_start..end_at]);
        let der = decode_body(&b64, &label)?;

        blocks.push(PemBlock {
            label,
            der,
            headers,
            offset: begin_at,
        });
        cursor = end_at + end_marker.len();
    }

    Ok(blocks)
}

fn build_end_marker(label: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(END.len() + label.len() + DASHES.len());
    m.extend_from_slice(END);
    m.extend_from_slice(label.as_bytes());
    m.extend_from_slice(DASHES);
    m
}

/// Split optional RFC 1421 headers from the base64 body.
///
/// Headers only exist when the first non-blank line contains a colon before any
/// base64 data, and they are terminated by a blank line.
fn split_headers(body: &str) -> (Vec<(String, String)>, String) {
    let mut headers = Vec::new();
    let mut rest = body;

    let mut probe = body.trim_start_matches(['\r', '\n']);
    if probe
        .lines()
        .next()
        .is_some_and(|l| l.contains(':') && !l.trim().is_empty())
    {
        let mut consumed = 0usize;
        for line in probe.split_inclusive('\n') {
            let trimmed = line.trim();
            consumed += line.len();
            if trimmed.is_empty() {
                break;
            }
            match trimmed.split_once(':') {
                Some((k, v)) => headers.push((k.trim().to_string(), v.trim().to_string())),
                // Not a header after all — abandon header parsing entirely.
                None => return (Vec::new(), body.to_string()),
            }
        }
        probe = &probe[consumed.min(probe.len())..];
        rest = probe;
    }

    (headers, rest.to_string())
}

fn decode_body(body: &str, label: &str) -> Result<Vec<u8>> {
    let mut compact = String::with_capacity(body.len());
    for c in body.chars() {
        if !c.is_ascii_whitespace() {
            compact.push(c);
        }
    }
    if compact.is_empty() {
        return Ok(Vec::new());
    }
    STANDARD
        .decode(compact.as_bytes())
        .map_err(|_| CertError::InvalidBase64 {
            label: label.to_string(),
        })
}

/// Naive substring search. Inputs are small (a chain is a few KB) so the
/// simplicity is worth more than sublinear asymptotics here.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Re-encode DER bytes as a PEM block with 64-character lines (RFC 7468 §3).
pub fn encode(label: &str, der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let line_count = b64.len().div_ceil(64);
    let mut out = String::with_capacity(b64.len() + line_count + label.len() * 2 + 32);

    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // Safe: base64 output is ASCII, so chunking on bytes is chunking on chars.
        out.push_str(core::str::from_utf8(chunk).expect("base64 output is ascii"));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----\n";
    const B: &str = "-----BEGIN CERTIFICATE-----\nWFla\n-----END CERTIFICATE-----\n";

    #[test]
    fn scans_single_block() {
        let blocks = scan(A).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].label, "CERTIFICATE");
        assert_eq!(blocks[0].der, b"ABC");
        assert_eq!(blocks[0].offset, 0);
    }

    /// The regression that motivated rewriting this module: the old regex
    /// implementation merged both bodies into one invalid base64 run.
    #[test]
    fn keeps_chain_blocks_separate() {
        let chain = format!("{A}{B}");
        let blocks = scan(&chain).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0].der, b"ABC");
        assert_eq!(blocks[1].der, b"XYZ");
    }

    #[test]
    fn ignores_text_between_blocks() {
        let input = format!("subject=/CN=a\n{A}\nissuer=/CN=b\n{B}trailing junk");
        let blocks = scan(&input).unwrap();
        assert_eq!(blocks.len(), 2);
    }

    #[test]
    fn handles_crlf() {
        let input = "-----BEGIN CERTIFICATE-----\r\nQUJD\r\n-----END CERTIFICATE-----\r\n";
        assert_eq!(scan(input).unwrap()[0].der, b"ABC");
    }

    #[test]
    fn parses_legacy_encryption_headers() {
        let input = "-----BEGIN RSA PRIVATE KEY-----\n\
                     Proc-Type: 4,ENCRYPTED\n\
                     DEK-Info: AES-128-CBC,0102\n\
                     \n\
                     QUJD\n\
                     -----END RSA PRIVATE KEY-----\n";
        let b = &scan(input).unwrap()[0];
        assert_eq!(b.headers.len(), 2);
        assert!(b.is_legacy_encrypted());
        assert_eq!(b.der, b"ABC");
    }

    #[test]
    fn unterminated_block_is_an_error() {
        let err = scan("-----BEGIN CERTIFICATE-----\nQUJD\n").unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::MalformedPem);
        assert_eq!(err.offset(), Some(0));
    }

    #[test]
    fn bad_base64_is_reported_with_label() {
        let err = scan("-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----").unwrap_err();
        assert_eq!(err.code(), crate::error::ErrorCode::InvalidBase64);
    }

    #[test]
    fn encode_wraps_at_64_columns() {
        let der = vec![0u8; 100];
        let pem = encode("CERTIFICATE", &der);
        let body: Vec<&str> = pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        assert_eq!(body[0].len(), 64);
        assert!(body.last().unwrap().len() <= 64);
        // Round-trips.
        assert_eq!(scan(&pem).unwrap()[0].der, der);
    }

    /// Exercises the exact off-by-one the old `to_pem` had: a body whose
    /// base64 length is an exact multiple of 64.
    #[test]
    fn encode_handles_exact_multiple_of_64() {
        let der = vec![7u8; 48]; // 48 bytes -> exactly 64 base64 chars
        let pem = encode("CERTIFICATE", &der);
        assert_eq!(pem.lines().count(), 3);
        assert_eq!(scan(&pem).unwrap()[0].der, der);
    }

    #[test]
    fn empty_input_yields_no_blocks() {
        assert!(scan("").unwrap().is_empty());
    }
}
