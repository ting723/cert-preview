model! {
    /// A GeneralName, flattened to a kind tag plus a rendered value.
    pub struct GeneralNameInfo {
        /// One of `dns`, `ip`, `email`, `uri`, `dirName`, `rid`, `other`.
        pub kind: String,
        pub value: String,
    }

    pub struct BasicConstraintsInfo {
        pub ca: bool,
        pub path_len_constraint: Option<u32>,
    }

    /// An entry of Authority Information Access.
    pub struct AccessDescription {
        /// `ocsp`, `caIssuers`, or the dotted OID.
        pub method: String,
        pub location: String,
    }

    /// An extension this build does not model structurally.
    pub struct RawExtension {
        pub oid: String,
        pub name: Option<String>,
        pub critical: bool,
        pub value_len: u32,
    }

    /// The extensions a certificate viewer actually needs to show.
    ///
    /// Anything not modelled here still surfaces in `others`, so no extension
    /// is silently dropped.
    pub struct Extensions {
        pub subject_alt_names: Vec<GeneralNameInfo>,
        pub issuer_alt_names: Vec<GeneralNameInfo>,
        pub basic_constraints: Option<BasicConstraintsInfo>,
        pub key_usage: Vec<String>,
        pub extended_key_usage: Vec<String>,
        /// Hex, colon separated.
        pub subject_key_id: Option<String>,
        /// Hex, colon separated.
        pub authority_key_id: Option<String>,
        pub crl_distribution_points: Vec<String>,
        pub authority_info_access: Vec<AccessDescription>,
        pub certificate_policies: Vec<String>,
        /// OIDs marked critical that this build does not understand. RFC 5280
        /// says a relying party must reject such a certificate, so callers
        /// need to see them.
        pub unhandled_critical: Vec<String>,
        pub others: Vec<RawExtension>,
    }
}

#[allow(clippy::derivable_impls)]
impl Default for Extensions {
    fn default() -> Self {
        Self {
            subject_alt_names: Vec::new(),
            issuer_alt_names: Vec::new(),
            basic_constraints: None,
            key_usage: Vec::new(),
            extended_key_usage: Vec::new(),
            subject_key_id: None,
            authority_key_id: None,
            crl_distribution_points: Vec::new(),
            authority_info_access: Vec::new(),
            certificate_policies: Vec::new(),
            unhandled_critical: Vec::new(),
            others: Vec::new(),
        }
    }
}

impl Extensions {
    /// DNS names from the SAN extension, in order.
    pub fn dns_names(&self) -> impl Iterator<Item = &str> {
        self.subject_alt_names
            .iter()
            .filter(|n| n.kind == "dns")
            .map(|n| n.value.as_str())
    }

    pub fn is_ca(&self) -> bool {
        self.basic_constraints.as_ref().is_some_and(|bc| bc.ca)
    }
}
