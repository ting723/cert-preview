model! {
    /// One attribute inside a Distinguished Name.
    pub struct RdnAttribute {
        /// Dotted OID, e.g. `2.5.4.3`.
        pub oid: String,
        /// Conventional short name when known, e.g. `CN`.
        pub short_name: Option<String>,
        pub value: String,
    }

    /// An X.501 Distinguished Name.
    ///
    /// The full `rdns` sequence is preserved in document order. The named
    /// convenience fields are lookups into it — the previous implementation
    /// exposed *only* six hard-coded fields, which silently dropped
    /// `serialNumber`, `businessCategory`, `jurisdictionCountryName` and every
    /// other attribute an EV certificate carries.
    pub struct DistinguishedName {
        pub rdns: Vec<RdnAttribute>,
        pub common_name: Option<String>,
        pub organization: Option<String>,
        pub organizational_unit: Option<String>,
        pub country: Option<String>,
        pub state: Option<String>,
        pub locality: Option<String>,
        pub email: Option<String>,
        /// RFC 4514 string form, e.g. `CN=example.com,O=Example Inc,C=US`.
        pub rfc4514: String,
    }
}

impl DistinguishedName {
    pub fn is_empty(&self) -> bool {
        self.rdns.is_empty()
    }

    /// Best available human label for this name.
    pub fn label(&self) -> &str {
        self.common_name
            .as_deref()
            .or(self.organization.as_deref())
            .unwrap_or(&self.rfc4514)
    }

    /// First value carried under `oid`.
    pub fn get(&self, oid: &str) -> Option<&str> {
        self.rdns
            .iter()
            .find(|r| r.oid == oid)
            .map(|r| r.value.as_str())
    }
}

impl core::fmt::Display for DistinguishedName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.rfc4514)
    }
}
