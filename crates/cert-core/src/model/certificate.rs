use super::{AlgorithmInfo, DistinguishedName, Extensions, PublicKeyInfo};

model! {
    pub struct Validity {
        /// Unix seconds.
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        pub not_before: i64,
        /// Unix seconds.
        #[cfg_attr(feature = "ts", ts(type = "number"))]
        pub not_after: i64,
        /// `YYYY-MM-DDTHH:MM:SSZ`.
        pub not_before_utc: String,
        /// `YYYY-MM-DDTHH:MM:SSZ`.
        pub not_after_utc: String,
    }

    pub struct Fingerprints {
        /// Hex, colon separated, over the full DER certificate.
        pub sha1: String,
        /// Hex, colon separated, over the full DER certificate.
        pub sha256: String,
    }

    pub struct CertificateInfo {
        /// 1, 2 or 3 (the wire encoding is zero-based; this is the human number).
        pub version: u8,
        /// Hex, colon separated.
        pub serial_number: String,
        pub subject: DistinguishedName,
        pub issuer: DistinguishedName,
        pub validity: Validity,
        pub public_key: PublicKeyInfo,
        pub signature_algorithm: AlgorithmInfo,
        pub extensions: Extensions,
        pub fingerprints: Fingerprints,
        /// Subject equals issuer. Note this is a *structural* observation, not
        /// proof of a self-signature — verifying that needs the signature
        /// check, which this build deliberately does not perform.
        pub self_issued: bool,
        pub der_len: u32,
    }
}

impl Validity {
    /// Seconds between `not_before` and `not_after`.
    pub fn lifetime_seconds(&self) -> i64 {
        self.not_after - self.not_before
    }
}

impl CertificateInfo {
    /// Best available display name.
    pub fn label(&self) -> &str {
        self.subject.label()
    }

    /// A leaf certificate is one that is not a CA.
    pub fn is_ca(&self) -> bool {
        self.extensions.is_ca()
    }
}
