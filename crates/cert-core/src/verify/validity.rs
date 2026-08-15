//! Time-dependent evaluation: turn a [`Bundle`] plus a clock into a [`Report`].
//!
//! This is the only boundary where `now` enters the system. Keeping it here
//! (and only here) is what lets a parsed bundle be compared byte-for-byte
//! across platforms; the same bytes with two different clocks produce two
//! different reports, which is correct and expected.

use crate::model::{Bundle, CertificateStatus, Diagnostic, HostnameMatch, Report, ValidityState, ValidityStatus};
use crate::util::humanize_seconds;

use super::chain;
use super::hostname;

/// Evaluate `bundle` at Unix time `now` (seconds), optionally checking a
/// server `hostname` against each certificate's SAN.
///
/// Chain linking is performed as a side effect on the returned report's bundle.
pub fn report(bundle: Bundle, now: i64, hostname: Option<&str>) -> Report {
    let chains = chain::link(&bundle);
    let mut bundle = bundle;
    bundle.chains = chains;

    let mut certificates = Vec::with_capacity(bundle.certificate_count());
    for (i, cert) in bundle.certificates() {
        let v = &cert.validity;

        let state = if now < v.not_before {
            ValidityState::NotYetValid
        } else if now > v.not_after {
            ValidityState::Expired
        } else {
            ValidityState::Valid
        };

        let host = hostname.map(|h| hostname::match_host(cert, h));

        let diagnostics: Vec<Diagnostic> = bundle
            .diagnostics
            .iter()
            .filter(|d| d.item == Some(i as u32))
            .cloned()
            .collect();

        certificates.push(CertificateStatus {
            index: i as u32,
            validity: ValidityStatus {
                state,
                seconds_remaining: v.not_after - now,
                seconds_until_valid: v.not_before - now,
            },
            hostname: host,
            diagnostics,
        });
    }

    Report {
        bundle,
        evaluated_at: now,
        certificates,
    }
}

impl ValidityStatus {
    /// Human-readable lifetime summary, e.g. `valid for 342 days`.
    pub fn summary(&self) -> String {
        match self.state {
            ValidityState::Valid => format!("valid, {} remaining", humanize_seconds(self.seconds_remaining)),
            ValidityState::Expired => format!("expired {} ago", humanize_seconds(-self.seconds_remaining)),
            ValidityState::NotYetValid => {
                format!("not valid for {}", humanize_seconds(self.seconds_until_valid))
            }
        }
    }
}

impl HostnameMatch {
    /// Short verdict for rendering.
    pub fn summary(&self) -> String {
        if self.matched {
            format!(
                "matches {}",
                self.matched_name.as_deref().unwrap_or("a SAN entry")
            )
        } else {
            format!("no SAN matches `{}`", self.hostname)
        }
    }
}
