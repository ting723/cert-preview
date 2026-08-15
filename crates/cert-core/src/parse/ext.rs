//! Extension extraction.
//!
//! Every extension present in the certificate ends up somewhere: the ten that
//! a viewer needs get structured fields, the rest are listed in
//! [`Extensions::others`] with their OID, criticality and length. Nothing is
//! silently discarded, because "the field is missing" and "the field exists
//! but this tool ignores it" are very different statements to a user
//! debugging a TLS handshake.

use std::net::{Ipv4Addr, Ipv6Addr};

use x509_parser::prelude::{
    DistributionPointName, ExtendedKeyUsage, GeneralName, KeyUsage, ParsedExtension, X509Extension,
};

use super::oid;
use crate::model::{
    AccessDescription, BasicConstraintsInfo, Extensions, GeneralNameInfo, RawExtension,
};
use crate::util::{hex, hex_colon};

/// RFC 5280 §4.2.1.3, in wire bit order.
const KEY_USAGE_NAMES: [&str; 9] = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
];

pub fn extensions(list: &[X509Extension<'_>]) -> Extensions {
    let mut out = Extensions::default();

    for ext in list {
        let dotted = oid::dotted(&ext.oid);
        let mut modelled = true;

        match ext.parsed_extension() {
            ParsedExtension::SubjectAlternativeName(san) => {
                out.subject_alt_names
                    .extend(san.general_names.iter().map(general_name));
            }
            ParsedExtension::IssuerAlternativeName(ian) => {
                out.issuer_alt_names
                    .extend(ian.general_names.iter().map(general_name));
            }
            ParsedExtension::BasicConstraints(bc) => {
                out.basic_constraints = Some(BasicConstraintsInfo {
                    ca: bc.ca,
                    path_len_constraint: bc.path_len_constraint,
                });
            }
            ParsedExtension::KeyUsage(ku) => out.key_usage = key_usage(ku),
            ParsedExtension::ExtendedKeyUsage(eku) => out.extended_key_usage = extended_key_usage(eku),
            ParsedExtension::SubjectKeyIdentifier(id) => {
                out.subject_key_id = Some(hex_colon(id.0));
            }
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                out.authority_key_id = aki.key_identifier.as_ref().map(|k| hex_colon(k.0));
            }
            ParsedExtension::CRLDistributionPoints(points) => {
                for point in points.points.iter() {
                    match &point.distribution_point {
                        Some(DistributionPointName::FullName(names)) => out
                            .crl_distribution_points
                            .extend(names.iter().map(|n| general_name(n).value)),
                        Some(DistributionPointName::NameRelativeToCRLIssuer(rdn)) => {
                            let parts: Vec<String> = rdn
                                .iter()
                                .map(|a| a.as_str().map(str::to_string).unwrap_or_default())
                                .collect();
                            out.crl_distribution_points.push(parts.join("+"));
                        }
                        None => {}
                    }
                }
            }
            ParsedExtension::AuthorityInfoAccess(aia) => {
                out.authority_info_access
                    .extend(aia.accessdescs.iter().map(|ad| {
                        let m = oid::dotted(&ad.access_method);
                        AccessDescription {
                            method: oid::access_method(&m).map(str::to_string).unwrap_or(m),
                            location: general_name(&ad.access_location).value,
                        }
                    }));
            }
            ParsedExtension::CertificatePolicies(policies) => {
                out.certificate_policies.extend(policies.iter().map(|p| {
                    let d = oid::dotted(&p.policy_id);
                    match oid::policy_name(&d) {
                        Some(n) => format!("{n} ({d})"),
                        None => d,
                    }
                }));
            }
            _ => modelled = false,
        }

        if !modelled {
            if ext.critical {
                // RFC 5280 §4.2: an unrecognised critical extension must cause
                // the certificate to be rejected. We cannot make that call for
                // the caller, but we can make it impossible to miss.
                out.unhandled_critical.push(dotted.clone());
            }
            out.others.push(RawExtension {
                name: oid::extension_name(&dotted)
                    .map(str::to_string)
                    .or_else(|| {
                        let n = oid::name_of(&ext.oid);
                        (n != dotted).then_some(n)
                    }),
                oid: dotted,
                critical: ext.critical,
                value_len: ext.value.len() as u32,
            });
        }
    }

    out
}

fn key_usage(ku: &KeyUsage) -> Vec<String> {
    KEY_USAGE_NAMES
        .iter()
        .enumerate()
        .filter(|(i, _)| ku.flags & (1 << i) != 0)
        .map(|(_, n)| n.to_string())
        .collect()
}

fn extended_key_usage(eku: &ExtendedKeyUsage<'_>) -> Vec<String> {
    let mut out = Vec::new();
    for (flag, name) in [
        (eku.any, "anyExtendedKeyUsage"),
        (eku.server_auth, "serverAuth"),
        (eku.client_auth, "clientAuth"),
        (eku.code_signing, "codeSigning"),
        (eku.email_protection, "emailProtection"),
        (eku.time_stamping, "timeStamping"),
        (eku.ocsp_signing, "OCSPSigning"),
    ] {
        if flag {
            out.push(name.to_string());
        }
    }
    for o in &eku.other {
        let d = oid::dotted(o);
        out.push(oid::eku_name(&d).map(str::to_string).unwrap_or(d));
    }
    out
}

/// Flatten a GeneralName to a `(kind, value)` pair.
pub fn general_name(name: &GeneralName<'_>) -> GeneralNameInfo {
    let (kind, value) = match name {
        GeneralName::DNSName(s) => ("dns", (*s).to_string()),
        GeneralName::RFC822Name(s) => ("email", (*s).to_string()),
        GeneralName::URI(s) => ("uri", (*s).to_string()),
        GeneralName::IPAddress(bytes) => ("ip", render_ip(bytes)),
        GeneralName::DirectoryName(n) => ("dirName", n.to_string()),
        GeneralName::RegisteredID(o) => ("rid", oid::dotted(o)),
        GeneralName::OtherName(o, _) => ("other", oid::dotted(o)),
        GeneralName::X400Address(_) => ("x400Address", String::new()),
        GeneralName::EDIPartyName(_) => ("ediPartyName", String::new()),
        GeneralName::Invalid(tag, bytes) => ("invalid", format!("[{}] {}", tag.0, hex(bytes))),
    };
    GeneralNameInfo {
        kind: kind.to_string(),
        value,
    }
}

fn render_ip(bytes: &[u8]) -> String {
    match bytes.len() {
        4 => Ipv4Addr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string(),
        16 => {
            let mut a = [0u8; 16];
            a.copy_from_slice(bytes);
            Ipv6Addr::from(a).to_string()
        }
        // Name constraints carry address + mask.
        8 => format!("{}/{}", render_ip(&bytes[..4]), render_ip(&bytes[4..])),
        32 => format!("{}/{}", render_ip(&bytes[..16]), render_ip(&bytes[16..])),
        _ => hex(bytes),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use x509_parser::prelude::KeyUsage;

    #[test]
    fn key_usage_flags_map_to_names() {
        // digitalSignature | keyEncipherment
        let ku = KeyUsage { flags: 0b0000_0101 };
        assert_eq!(key_usage(&ku), vec!["digitalSignature", "keyEncipherment"]);
        // keyCertSign | cRLSign — the classic CA pair.
        let ca = KeyUsage { flags: 0b0110_0000 };
        assert_eq!(key_usage(&ca), vec!["keyCertSign", "cRLSign"]);
        assert!(key_usage(&KeyUsage { flags: 0 }).is_empty());
    }

    #[test]
    fn ip_rendering() {
        assert_eq!(render_ip(&[192, 0, 2, 1]), "192.0.2.1");
        let v6 = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(render_ip(&v6), "2001:db8::1");
        assert_eq!(
            render_ip(&[10, 0, 0, 0, 255, 0, 0, 0]),
            "10.0.0.0/255.0.0.0"
        );
        assert_eq!(render_ip(&[1, 2, 3]), "010203");
    }
}
