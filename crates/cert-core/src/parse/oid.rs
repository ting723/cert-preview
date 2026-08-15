//! OID to human name resolution.
//!
//! The local tables are consulted **before** the `x509-parser` registry. That
//! ordering is deliberate: it pins the exact strings that appear in the JSON
//! output, so a dependency bump cannot silently rewrite every snapshot test,
//! and it lets us name the OIDs the registry does not carry (named curves, CA/B
//! Forum policy identifiers, Microsoft jurisdiction attributes).
//!
//! Resolution order is: local table -> registry short name -> dotted OID.
//! The result is therefore never empty.

use x509_parser::asn1_rs::Oid;
use x509_parser::objects::{oid2sn, oid_registry};

use crate::model::AlgorithmInfo;

/// Dotted decimal form of an OID.
pub fn dotted(oid: &Oid) -> String {
    oid.to_id_string()
}

/// Best available name, falling back to the dotted form.
pub fn name_of(oid: &Oid) -> String {
    let d = dotted(oid);
    if let Some(n) = well_known(&d) {
        return n.to_string();
    }
    match oid2sn(oid, oid_registry()) {
        Ok(sn) => sn.to_string(),
        Err(_) => d,
    }
}

/// An [`AlgorithmInfo`] with the name resolved and no parameters set.
pub fn algorithm(oid: &Oid) -> AlgorithmInfo {
    AlgorithmInfo {
        oid: dotted(oid),
        name: name_of(oid),
        parameters: None,
    }
}

/// Short attribute label used inside a Distinguished Name, e.g. `CN`.
///
/// RFC 4514 §3 only standardises a handful; the rest follow the labels
/// OpenSSL prints, because that is what users will be comparing against.
pub fn rdn_short_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "serialNumber",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "street",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "title",
        "2.5.4.13" => "description",
        "2.5.4.15" => "businessCategory",
        "2.5.4.16" => "postalAddress",
        "2.5.4.17" => "postalCode",
        "2.5.4.20" => "telephoneNumber",
        "2.5.4.41" => "name",
        "2.5.4.42" => "givenName",
        "2.5.4.43" => "initials",
        "2.5.4.44" => "generationQualifier",
        "2.5.4.46" => "dnQualifier",
        "2.5.4.65" => "pseudonym",
        "2.5.4.97" => "organizationIdentifier",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "emailAddress",
        "1.3.6.1.4.1.311.60.2.1.1" => "jurisdictionL",
        "1.3.6.1.4.1.311.60.2.1.2" => "jurisdictionST",
        "1.3.6.1.4.1.311.60.2.1.3" => "jurisdictionC",
        _ => return None,
    })
}

/// Named elliptic curve, using the label OpenSSL prints.
pub fn curve_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "1.2.840.10045.3.1.1" => "prime192v1",
        "1.2.840.10045.3.1.7" => "prime256v1",
        "1.3.132.0.1" => "sect163k1",
        "1.3.132.0.10" => "secp256k1",
        "1.3.132.0.33" => "secp224r1",
        "1.3.132.0.34" => "secp384r1",
        "1.3.132.0.35" => "secp521r1",
        "1.3.36.3.3.2.8.1.1.7" => "brainpoolP256r1",
        "1.3.36.3.3.2.8.1.1.9" => "brainpoolP320r1",
        "1.3.36.3.3.2.8.1.1.11" => "brainpoolP384r1",
        "1.3.36.3.3.2.8.1.1.13" => "brainpoolP512r1",
        _ => return None,
    })
}

/// Field size in bits for a named curve, or for an edwards/montgomery key.
pub fn curve_bits(name: &str) -> Option<u32> {
    Some(match name {
        "prime192v1" => 192,
        "secp224r1" => 224,
        "prime256v1" | "secp256k1" | "brainpoolP256r1" => 256,
        "brainpoolP320r1" => 320,
        "secp384r1" | "brainpoolP384r1" => 384,
        "brainpoolP512r1" => 512,
        "secp521r1" => 521,
        "sect163k1" => 163,
        "Ed25519" | "X25519" => 256,
        "Ed448" => 456,
        "X448" => 448,
        _ => return None,
    })
}

/// Extended key usage purpose.
pub fn eku_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "2.5.29.37.0" => "anyExtendedKeyUsage",
        "1.3.6.1.5.5.7.3.1" => "serverAuth",
        "1.3.6.1.5.5.7.3.2" => "clientAuth",
        "1.3.6.1.5.5.7.3.3" => "codeSigning",
        "1.3.6.1.5.5.7.3.4" => "emailProtection",
        "1.3.6.1.5.5.7.3.5" => "ipsecEndSystem",
        "1.3.6.1.5.5.7.3.6" => "ipsecTunnel",
        "1.3.6.1.5.5.7.3.7" => "ipsecUser",
        "1.3.6.1.5.5.7.3.8" => "timeStamping",
        "1.3.6.1.5.5.7.3.9" => "OCSPSigning",
        "1.3.6.1.4.1.311.10.3.4" => "msEncryptingFileSystem",
        "1.3.6.1.4.1.311.20.2.2" => "msSmartCardLogon",
        _ => return None,
    })
}

/// Authority Information Access method.
pub fn access_method(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "1.3.6.1.5.5.7.48.1" => "ocsp",
        "1.3.6.1.5.5.7.48.2" => "caIssuers",
        "1.3.6.1.5.5.7.48.3" => "timeStamping",
        "1.3.6.1.5.5.7.48.5" => "caRepository",
        _ => return None,
    })
}

/// Certificate policy identifier, where it has an agreed meaning.
pub fn policy_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "2.5.29.32.0" => "anyPolicy",
        "2.23.140.1.1" => "extended-validation",
        "2.23.140.1.2.1" => "domain-validated",
        "2.23.140.1.2.2" => "organization-validated",
        "2.23.140.1.2.3" => "individual-validated",
        "2.23.140.1.4.1" => "code-signing-requirements",
        _ => return None,
    })
}

/// Standard extension name, used when reporting an extension we do not model.
pub fn extension_name(dotted: &str) -> Option<&'static str> {
    Some(match dotted {
        "2.5.29.9" => "subjectDirectoryAttributes",
        "2.5.29.14" => "subjectKeyIdentifier",
        "2.5.29.15" => "keyUsage",
        "2.5.29.16" => "privateKeyUsagePeriod",
        "2.5.29.17" => "subjectAltName",
        "2.5.29.18" => "issuerAltName",
        "2.5.29.19" => "basicConstraints",
        "2.5.29.30" => "nameConstraints",
        "2.5.29.31" => "cRLDistributionPoints",
        "2.5.29.32" => "certificatePolicies",
        "2.5.29.33" => "policyMappings",
        "2.5.29.35" => "authorityKeyIdentifier",
        "2.5.29.36" => "policyConstraints",
        "2.5.29.37" => "extKeyUsage",
        "2.5.29.46" => "freshestCRL",
        "2.5.29.54" => "inhibitAnyPolicy",
        "1.3.6.1.5.5.7.1.1" => "authorityInfoAccess",
        "1.3.6.1.5.5.7.1.11" => "subjectInfoAccess",
        "1.3.6.1.5.5.7.1.24" => "tlsFeature",
        "1.3.6.1.4.1.11129.2.4.2" => "ctPrecertificateSCTs",
        "1.3.6.1.4.1.11129.2.4.3" => "ctPrecertificatePoison",
        "2.16.840.1.113730.1.1" => "nsCertType",
        "2.16.840.1.113730.1.13" => "nsComment",
        _ => return None,
    })
}

/// Algorithm and structural OIDs we want stable names for.
fn well_known(dotted: &str) -> Option<&'static str> {
    if let Some(n) = curve_name(dotted) {
        return Some(n);
    }
    Some(match dotted {
        // Public key algorithms.
        "1.2.840.113549.1.1.1" => "rsaEncryption",
        "1.2.840.113549.1.1.10" => "RSASSA-PSS",
        "1.2.840.113549.1.1.7" => "RSAES-OAEP",
        "1.2.840.10045.2.1" => "id-ecPublicKey",
        "1.2.840.10040.4.1" => "id-dsa",
        "1.3.101.110" => "X25519",
        "1.3.101.111" => "X448",
        "1.3.101.112" => "Ed25519",
        "1.3.101.113" => "Ed448",
        // Signature algorithms.
        "1.2.840.113549.1.1.4" => "md5WithRSAEncryption",
        "1.2.840.113549.1.1.5" => "sha1WithRSAEncryption",
        "1.2.840.113549.1.1.11" => "sha256WithRSAEncryption",
        "1.2.840.113549.1.1.12" => "sha384WithRSAEncryption",
        "1.2.840.113549.1.1.13" => "sha512WithRSAEncryption",
        "1.2.840.113549.1.1.14" => "sha224WithRSAEncryption",
        "1.2.840.10045.4.1" => "ecdsa-with-SHA1",
        "1.2.840.10045.4.3.1" => "ecdsa-with-SHA224",
        "1.2.840.10045.4.3.2" => "ecdsa-with-SHA256",
        "1.2.840.10045.4.3.3" => "ecdsa-with-SHA384",
        "1.2.840.10045.4.3.4" => "ecdsa-with-SHA512",
        "1.2.840.10040.4.3" => "dsa-with-SHA1",
        "2.16.840.1.101.3.4.3.2" => "dsa-with-SHA256",
        // Digests, seen inside RSASSA-PSS parameters.
        "1.3.14.3.2.26" => "sha1",
        "2.16.840.1.101.3.4.2.1" => "sha256",
        "2.16.840.1.101.3.4.2.2" => "sha384",
        "2.16.840.1.101.3.4.2.3" => "sha512",
        // Key derivation / encryption, seen in encrypted PKCS#8.
        "1.2.840.113549.1.5.13" => "PBES2",
        "1.2.840.113549.1.5.12" => "PBKDF2",
        "2.16.840.1.101.3.4.1.42" => "aes256-CBC",
        "2.16.840.1.101.3.4.1.2" => "aes128-CBC",
        _ => return None,
    })
}

/// Signature algorithms considered unfit for new certificates.
///
/// SHA-1 collisions are practical (SHAttered, 2017) and MD5 has been broken
/// since 2008, so a certificate signed with either should be flagged.
pub fn is_weak_signature(dotted: &str) -> bool {
    matches!(
        dotted,
        "1.2.840.113549.1.1.4"   // md5WithRSA
            | "1.2.840.113549.1.1.5" // sha1WithRSA
            | "1.2.840.10045.4.1"    // ecdsa-with-SHA1
            | "1.2.840.10040.4.3"    // dsa-with-SHA1
            | "1.3.14.3.2.29" // sha1WithRSA (oiw)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_table_wins_over_registry() {
        // 1.2.840.113549.1.1.11
        let oid = Oid::from(&[1, 2, 840, 113549, 1, 1, 11]).unwrap();
        assert_eq!(name_of(&oid), "sha256WithRSAEncryption");
    }

    #[test]
    fn unknown_oids_fall_back_to_dotted() {
        let oid = Oid::from(&[1, 2, 3, 4, 5, 6, 7, 8, 9]).unwrap();
        assert_eq!(name_of(&oid), "1.2.3.4.5.6.7.8.9");
    }

    #[test]
    fn curves_resolve_both_ways() {
        assert_eq!(curve_name("1.2.840.10045.3.1.7"), Some("prime256v1"));
        assert_eq!(curve_bits("prime256v1"), Some(256));
        assert_eq!(curve_bits("secp521r1"), Some(521));
        assert_eq!(curve_bits("nonexistent"), None);
    }

    #[test]
    fn weak_signatures_flagged() {
        assert!(is_weak_signature("1.2.840.113549.1.1.5"));
        assert!(!is_weak_signature("1.2.840.113549.1.1.11"));
    }
}
