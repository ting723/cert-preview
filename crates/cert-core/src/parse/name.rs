//! X.501 Distinguished Name extraction.
//!
//! Two things the previous implementation got wrong are fixed here:
//!
//! 1. the complete RDN sequence is preserved, not just six hard-coded
//!    attributes, so EV fields survive;
//! 2. the string form follows RFC 4514 — escaped and in reverse order — so it
//!    matches what browsers, Java and .NET display.

use x509_parser::prelude::{AttributeTypeAndValue, X509Name};

use super::oid;
use crate::model::{DistinguishedName, RdnAttribute};
use crate::util::hex;

/// Convert a parsed name into the domain model.
pub fn distinguished_name(name: &X509Name<'_>) -> DistinguishedName {
    let mut rdns = Vec::new();
    // Multi-valued RDNs (`OU=a+OU=b`) are rare but legal; keep the grouping
    // for the string form while flattening the list form.
    let mut groups: Vec<Vec<String>> = Vec::new();

    for rdn in name.iter_rdn() {
        let mut group = Vec::new();
        for attr in rdn.iter() {
            let dotted = oid::dotted(attr.attr_type());
            let short = oid::rdn_short_name(&dotted);
            let value = attribute_value(attr);
            group.push(format!(
                "{}={}",
                short.unwrap_or(&dotted),
                escape_rfc4514(&value)
            ));
            rdns.push(RdnAttribute {
                oid: dotted,
                short_name: short.map(str::to_string),
                value,
            });
        }
        if !group.is_empty() {
            groups.push(group);
        }
    }

    // RFC 4514 §2.1: the output is the RDNSequence in reverse order.
    let rfc4514 = groups
        .iter()
        .rev()
        .map(|g| g.join("+"))
        .collect::<Vec<_>>()
        .join(",");

    let pick = |target: &str| {
        rdns.iter()
            .find(|r| r.oid == target)
            .map(|r| r.value.clone())
    };

    DistinguishedName {
        common_name: pick("2.5.4.3"),
        organization: pick("2.5.4.10"),
        organizational_unit: pick("2.5.4.11"),
        country: pick("2.5.4.6"),
        state: pick("2.5.4.8"),
        locality: pick("2.5.4.7"),
        email: pick("1.2.840.113549.1.9.1"),
        rdns,
        rfc4514,
    }
}

/// Attribute values are usually one of the ASN.1 string types. When they are
/// not — BMPString with a lone surrogate, or a genuinely binary value — RFC
/// 4514 §2.4 says to emit `#` followed by the hex of the encoded value rather
/// than dropping it.
fn attribute_value(attr: &AttributeTypeAndValue<'_>) -> String {
    match attr.as_str() {
        Ok(s) => s.to_string(),
        Err(_) => format!("#{}", hex(attr.as_slice())),
    }
}

/// RFC 4514 §2.4 escaping.
fn escape_rfc4514(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let chars: Vec<char> = value.chars().collect();
    for (i, c) in chars.iter().copied().enumerate() {
        let first = i == 0;
        let last = i + 1 == chars.len();
        match c {
            '"' | '+' | ',' | ';' | '<' | '>' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            '\0' => out.push_str("\\00"),
            '#' if first => out.push_str("\\#"),
            ' ' if first || last => out.push_str("\\ "),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_special_characters() {
        assert_eq!(escape_rfc4514("Example, Inc."), "Example\\, Inc.");
        assert_eq!(escape_rfc4514("a+b"), "a\\+b");
        assert_eq!(escape_rfc4514("#hash"), "\\#hash");
        assert_eq!(escape_rfc4514(" pad "), "\\ pad\\ ");
        assert_eq!(escape_rfc4514("mid # ok"), "mid # ok");
        assert_eq!(escape_rfc4514("plain"), "plain");
    }
}
