use super::{Bundle, Diagnostic};

model_enum! {
    pub enum ValidityState {
        NotYetValid,
        Valid,
        Expired,
    }
}

model! {
    /// Time-dependent validity, evaluated against a caller-supplied clock.
    pub struct ValidityStatus {
        pub state: ValidityState,
        /// Seconds until `not_after`. Negative once expired.
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        pub seconds_remaining: i64,
        /// Seconds until `not_before`. Negative once the certificate has started.
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        pub seconds_until_valid: i64,
    }

    /// Result of matching a hostname against subject alternative names.
    pub struct HostnameMatch {
        pub hostname: String,
        pub matched: bool,
        /// The SAN entry that matched, when one did.
        pub matched_name: Option<String>,
    }

    pub struct CertificateStatus {
        /// Index into [`Bundle::items`].
        pub index: u32,
        pub validity: ValidityStatus,
        pub hostname: Option<HostnameMatch>,
        pub diagnostics: Vec<Diagnostic>,
    }

    /// A [`Bundle`] plus everything that depends on the current time or on
    /// caller-supplied context.
    ///
    /// Splitting this from `Bundle` is what allows parse results to be
    /// snapshot-tested byte-for-byte across Rust, Node and the browser.
    pub struct Report {
        pub bundle: Bundle,
        /// The clock value the evaluation used, in Unix seconds.
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        pub evaluated_at: i64,
        pub certificates: Vec<CertificateStatus>,
    }
}

impl ValidityState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotYetValid => "notYetValid",
            Self::Valid => "valid",
            Self::Expired => "expired",
        }
    }

    pub const fn is_usable(self) -> bool {
        matches!(self, Self::Valid)
    }
}

impl core::fmt::Display for ValidityState {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Report {
    /// True when every certificate is inside its validity window and no
    /// error-level diagnostic was raised.
    pub fn is_healthy(&self) -> bool {
        self.certificates
            .iter()
            .all(|c| c.validity.state.is_usable())
            && !self.has_errors()
    }

    pub fn has_errors(&self) -> bool {
        let in_bundle = self
            .bundle
            .diagnostics
            .iter()
            .any(|d| d.level == super::Severity::Error);
        let in_chains = self
            .bundle
            .chains
            .iter()
            .flat_map(|c| &c.diagnostics)
            .any(|d| d.level == super::Severity::Error);
        let in_certs = self
            .certificates
            .iter()
            .flat_map(|c| &c.diagnostics)
            .any(|d| d.level == super::Severity::Error);
        in_bundle || in_chains || in_certs
    }

    pub fn status_for(&self, index: usize) -> Option<&CertificateStatus> {
        self.certificates.iter().find(|c| c.index as usize == index)
    }
}
