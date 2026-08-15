//! A deliberately tiny DER reader and writer.
//!
//! `x509-parser` covers certificates, but private key containers (PKCS#8,
//! PKCS#1, SEC1) are not certificates and pulling in a second full ASN.1
//! stack for them would cost more WASM bytes than the ~150 lines below.
//!
//! Scope is intentionally narrow:
//!
//! * definite-length, single-byte tags only — anything else is rejected
//!   rather than guessed at,
//! * no BER, no indefinite length, no constructed strings,
//! * the writer emits only what is needed to rebuild a SubjectPublicKeyInfo.

use crate::error::{CertError, Result};

pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const NULL: u8 = 0x05;
pub const SEQUENCE: u8 = 0x30;

/// Constructed, context-specific tag `[n]`.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// Primitive, context-specific tag `[n]` — how IMPLICIT primitives encode.
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// One tag-length-value triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The value octets.
    pub content: &'a [u8],
    /// The complete encoding, header included. Handy for copying a
    /// sub-structure verbatim instead of re-encoding it.
    pub raw: &'a [u8],
}

impl<'a> Tlv<'a> {
    pub fn is(&self, tag: u8) -> bool {
        self.tag == tag
    }
}

/// Read one TLV from the front of `input`, returning it and the remainder.
pub fn read<'a>(input: &'a [u8], object: &'static str) -> Result<(Tlv<'a>, &'a [u8])> {
    let fail = |reason: &str| CertError::der(object, reason);

    if input.len() < 2 {
        return Err(fail("truncated TLV header"));
    }
    let tag = input[0];
    if tag & 0x1f == 0x1f {
        return Err(fail("multi-byte tags are not supported"));
    }

    let first = input[1];
    let (len, header_len) = if first < 0x80 {
        (first as usize, 2)
    } else {
        let n = (first & 0x7f) as usize;
        if n == 0 {
            return Err(fail("indefinite length is not valid DER"));
        }
        if n > 4 {
            return Err(fail("length field is implausibly large"));
        }
        if input.len() < 2 + n {
            return Err(fail("truncated length field"));
        }
        let mut len = 0usize;
        for b in &input[2..2 + n] {
            len = (len << 8) | *b as usize;
        }
        (len, 2 + n)
    };

    let end = header_len
        .checked_add(len)
        .ok_or_else(|| fail("length overflow"))?;
    if input.len() < end {
        return Err(fail("value is shorter than its declared length"));
    }

    Ok((
        Tlv {
            tag,
            content: &input[header_len..end],
            raw: &input[..end],
        },
        &input[end..],
    ))
}

/// Read the single TLV that makes up `input`, rejecting trailing bytes.
pub fn read_exact<'a>(input: &'a [u8], object: &'static str) -> Result<Tlv<'a>> {
    let (tlv, rest) = read(input, object)?;
    if !rest.is_empty() {
        return Err(CertError::der(object, "unexpected trailing bytes"));
    }
    Ok(tlv)
}

/// Split the contents of a constructed value into its children.
pub fn children<'a>(mut content: &'a [u8], object: &'static str) -> Result<Vec<Tlv<'a>>> {
    let mut out = Vec::new();
    while !content.is_empty() {
        let (tlv, rest) = read(content, object)?;
        out.push(tlv);
        content = rest;
    }
    Ok(out)
}

/// Decode OID value octets into dotted decimal form.
pub fn oid_string(content: &[u8]) -> Option<String> {
    if content.is_empty() {
        return None;
    }
    let mut arcs: Vec<u128> = Vec::new();
    let mut cur: u128 = 0;
    let mut in_progress = false;
    for &b in content {
        if !in_progress && b == 0x80 {
            // Leading 0x80 means a non-minimal encoding; reject rather than
            // silently normalise, because OIDs are matched as strings later.
            return None;
        }
        in_progress = true;
        cur = cur.checked_mul(128)?.checked_add((b & 0x7f) as u128)?;
        if b & 0x80 == 0 {
            arcs.push(cur);
            cur = 0;
            in_progress = false;
        }
    }
    if in_progress || arcs.is_empty() {
        return None;
    }

    let first = arcs.remove(0);
    let (a1, a2) = if first < 80 {
        (first / 40, first % 40)
    } else {
        (2, first - 80)
    };
    let mut out = format!("{a1}.{a2}");
    for a in arcs {
        out.push('.');
        out.push_str(itoa(a).as_str());
    }
    Some(out)
}

fn itoa(v: u128) -> String {
    v.to_string()
}

/// Bit length of a DER INTEGER's value octets, ignoring the sign padding byte.
///
/// This is what "2048 bit RSA key" means: the bit length of the modulus.
pub fn integer_bit_length(content: &[u8]) -> Option<u32> {
    let bytes = content.strip_prefix(&[0x00]).unwrap_or(content);
    let first = *bytes.first()?;
    if first == 0 {
        return Some(0);
    }
    let high = 8 - first.leading_zeros();
    Some((bytes.len() as u32 - 1) * 8 + high)
}

/// Encode one TLV.
pub fn write_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    write_len(&mut out, content.len());
    out.extend_from_slice(content);
    out
}

/// Encode a SEQUENCE whose contents are the concatenation of `parts`.
pub fn write_sequence(parts: &[&[u8]]) -> Vec<u8> {
    let total: usize = parts.iter().map(|p| p.len()).sum();
    let mut body = Vec::with_capacity(total);
    for p in parts {
        body.extend_from_slice(p);
    }
    write_tlv(SEQUENCE, &body)
}

/// Encode a BIT STRING with no unused trailing bits.
pub fn write_bit_string(bits: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bits.len() + 1);
    body.push(0x00);
    body.extend_from_slice(bits);
    write_tlv(BIT_STRING, &body)
}

fn write_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
        return;
    }
    let bytes = len.to_be_bytes();
    let first = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len() - 1);
    out.push(0x80 | (bytes.len() - first) as u8);
    out.extend_from_slice(&bytes[first..]);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_form() {
        let input = [0x02, 0x01, 0x05, 0xff];
        let (tlv, rest) = read(&input, "test").unwrap();
        assert_eq!(tlv.tag, INTEGER);
        assert_eq!(tlv.content, &[0x05]);
        assert_eq!(tlv.raw, &[0x02, 0x01, 0x05]);
        assert_eq!(rest, &[0xff]);
    }

    #[test]
    fn reads_long_form() {
        let mut input = vec![0x04, 0x82, 0x01, 0x00];
        input.extend(std::iter::repeat_n(0xaa, 256));
        let tlv = read_exact(&input, "test").unwrap();
        assert_eq!(tlv.tag, OCTET_STRING);
        assert_eq!(tlv.content.len(), 256);
    }

    #[test]
    fn rejects_indefinite_length() {
        let err = read(&[0x30, 0x80, 0x00, 0x00], "test").unwrap_err();
        assert!(matches!(err, CertError::DerDecode { .. }));
    }

    #[test]
    fn rejects_truncated_value() {
        assert!(read(&[0x04, 0x08, 0x00], "test").is_err());
    }

    #[test]
    fn splits_children() {
        // SEQUENCE { INTEGER 0, NULL }
        let seq = [0x30, 0x05, 0x02, 0x01, 0x00, 0x05, 0x00];
        let tlv = read_exact(&seq, "test").unwrap();
        let kids = children(tlv.content, "test").unwrap();
        assert_eq!(kids.len(), 2);
        assert!(kids[0].is(INTEGER));
        assert!(kids[1].is(NULL));
    }

    #[test]
    fn decodes_oids() {
        // 1.2.840.113549.1.1.1 (rsaEncryption)
        let content = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
        assert_eq!(oid_string(&content).unwrap(), "1.2.840.113549.1.1.1");
        // 2.5.4.3 (commonName) — exercises the >= 80 first-arc branch boundary.
        assert_eq!(oid_string(&[0x55, 0x04, 0x03]).unwrap(), "2.5.4.3");
        // 1.3.101.112 (Ed25519)
        assert_eq!(oid_string(&[0x2b, 0x65, 0x70]).unwrap(), "1.3.101.112");
        // 2.999.1 — first arc 2 with a large second arc.
        assert_eq!(oid_string(&[0x88, 0x37, 0x01]).unwrap(), "2.999.1");
        assert!(oid_string(&[]).is_none());
        assert!(oid_string(&[0x80, 0x01]).is_none());
        assert!(oid_string(&[0x81]).is_none());
    }

    #[test]
    fn integer_bit_lengths() {
        assert_eq!(integer_bit_length(&[0x00, 0xff]), Some(8));
        assert_eq!(integer_bit_length(&[0x01]), Some(1));
        assert_eq!(integer_bit_length(&[0x00, 0x80]), Some(8));
        // A 2048 bit modulus: 0x00 pad plus 256 octets with the top bit set.
        let mut m = vec![0x00, 0xc0];
        m.extend(std::iter::repeat_n(0x11, 255));
        assert_eq!(integer_bit_length(&m), Some(2048));
    }

    #[test]
    fn writer_round_trips() {
        let seq = write_sequence(&[&write_tlv(INTEGER, &[0x2a]), &write_tlv(NULL, &[])]);
        let tlv = read_exact(&seq, "test").unwrap();
        assert!(tlv.is(SEQUENCE));
        assert_eq!(children(tlv.content, "test").unwrap().len(), 2);
    }

    #[test]
    fn writer_uses_long_form_when_needed() {
        let big = vec![0u8; 300];
        let out = write_tlv(OCTET_STRING, &big);
        assert_eq!(&out[..4], &[0x04, 0x82, 0x01, 0x2c]);
        assert_eq!(read_exact(&out, "test").unwrap().content.len(), 300);
    }

    #[test]
    fn bit_string_prefixes_unused_bit_count() {
        let out = write_bit_string(&[0xde, 0xad]);
        assert_eq!(out, vec![0x03, 0x03, 0x00, 0xde, 0xad]);
    }
}
