use super::{CertificateInfo, ChainSummary, Diagnostic, PrivateKeyInfo, PublicKeyInfo,
};

model! {
    /// An object that was recognised as PEM/DER but could not be modelled.
    pub struct UnsupportedItem {
        pub label: Option<String>,
        pub reason: String,
        pub der_len: u32,
    }

    /// One parsed object.
    ///
    /// Serialised with an internal `kind` tag, which gives TypeScript a clean
    /// discriminated union:
    /// `{ kind: "certificate", version: 3, ... } | { kind: "privateKey", ... }`
    #[serde(tag = "kind")]
    #[allow(clippy::large_enum_variant)]
    pub enum BundleItem {
        Certificate(CertificateInfo),
        PublicKey(PublicKeyInfo),
        PrivateKey(PrivateKeyInfo),
        Unsupported(UnsupportedItem),
    }

    /// The complete result of parsing one input.
    ///
    /// Deterministic: given the same bytes it always serialises identically,
    /// which is what makes the cross-platform snapshot tests meaningful.
    pub struct Bundle {
        /// `PEM`, `DER` or `BASE64`.
        pub source_format: String,
        pub items: Vec<BundleItem>,
        pub chains: Vec<ChainSummary>,
        pub diagnostics: Vec<Diagnostic>,
    }
}

impl BundleItem {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Certificate(_) => "certificate",
            Self::PublicKey(_) => "publicKey",
            Self::PrivateKey(_) => "privateKey",
            Self::Unsupported(_) => "unsupported",
        }
    }

    pub fn as_certificate(&self) -> Option<&CertificateInfo> {
        match self {
            Self::Certificate(c) => Some(c),
            _ => None,
        }
    }
}

impl Bundle {
    /// Every certificate in the bundle, paired with its item index.
    pub fn certificates(&self) -> impl Iterator<Item = (usize, &CertificateInfo)> {
        self.items
            .iter()
            .enumerate()
            .filter_map(|(i, it)| it.as_certificate().map(|c| (i, c)))
    }

    pub fn certificate_count(&self) -> usize {
        self.certificates().count()
    }

    pub fn get(&self, index: usize) -> Option<&BundleItem> {
        self.items.get(index)
    }
}
