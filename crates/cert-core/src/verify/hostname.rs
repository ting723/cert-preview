//! Hostname verification against subject alternative names.
//!
//! This is the structural half of what a browser does when it validates a TLS
//! certificate's identity: it checks the presented hostname against the
//! certificate's `subjectAltName` extension (DNS names, with `*.` wildcards,
//! and IP addresses). The historical `commonName` fallback is honoured only
//! when no SAN extension is present — browsers dropped CN matching in 2017, and
//! [`crate::parse::cert::certificate`] already warns about the missing SAN.

use crate::model::{CertificateInfo, GeneralNameInfo, HostnameMatch};

/// Match `hostname` against the names in `cert`.
///
/// Returns the first SAN entry (or, failing that, the CN) that matches. The
/// match is case-insensitive for DNS names and exact for IP addresses.
pub fn match_host(cert: &CertificateInfo, hostname: &str) -> HostnameMatch {
    let host = hostname.trim().to_ascii_lowercase();

    for san in &cert.extensions.subject_alt_names {
        if let Some(name) = try_match(san, &host) {
            return HostnameMatch {
                hostname: hostname.to_string(),
                matched: true,
                matched_name: Some(name),
            };
        }
    }

    // Legacy CN fallback: only when there is no SAN at all.
    if cert.extensions.subject_alt_names.is_empty() {
        if let Some(cn) = &cert.subject.common_name {
            if dns_equal(&host, &cn.to_ascii_lowercase()) {
                return HostnameMatch {
                    hostname: hostname.to_string(),
                    matched: true,
                    matched_name: Some(format!("CN={cn}")),
                };
            }
        }
    }

    HostnameMatch {
        hostname: hostname.to_string(),
        matched: false,
        matched_name: None,
    }
}

/// Try to match a single GeneralName against the (lowercased) host.
fn try_match(name: &GeneralNameInfo, host: &str) -> Option<String> {
    match name.kind.as_str() {
        "dns" => {
            if dns_equal(host, &name.value.to_ascii_lowercase()) {
                Some(format!("DNS:{}", name.value))
            } else {
                None
            }
        }
        "ip" => {
            // Compare as IP addresses so "192.0.2.10" == "192.0.2.10" but not
            // "192.0.2.10" == "192.0.2.11". IPv4 and IPv6 both handled.
            let Ok(parsed) = name.value.parse::<std::net::IpAddr>() else {
                return None;
            };
            let Ok(want) = host.parse::<std::net::IpAddr>() else {
                return None;
            };
            if parsed == want {
                Some(format!("IP:{name}", name = name.value))
            } else {
                None
            }
        }
        // email / uri / dirName are not hostname identities.
        _ => None,
    }
}

/// DNS equality with RFC 6125 §6.4.3 wildcard rules.
///
/// `*.example.com` matches exactly one label under `example.com`
/// (`www.example.com`) but not `a.b.example.com` and not `example.com`.
fn dns_equal(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if suffix.is_empty() {
            return false;
        }
        // The wildcard must stand for a single label.
        let prefix_len = host.len().saturating_sub(suffix.len() + 1);
        if prefix_len == 0 || !host.ends_with(suffix) {
            return false;
        }
        // Everything before the suffix must be one dot-free label.
        let label = &host[..prefix_len];
        !label.is_empty() && !label.contains('.') && host.as_bytes()[prefix_len] == b'.'
    } else {
        host == pattern
    }
}
