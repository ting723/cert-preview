use super::{Diagnostic};

model! {
    /// A certificate path assembled from the objects in a bundle.
    ///
    /// Linking is structural: issuer/subject name equality reinforced by
    /// Authority Key Identifier / Subject Key Identifier when both are
    /// present. No signature is verified, so a chain being `complete` means
    /// "the names line up all the way to a self-issued certificate", not "this
    /// chain is cryptographically valid".
    pub struct ChainSummary {
        /// Indices into [`Bundle::items`](super::Bundle::items), leaf first.
        pub indices: Vec<u32>,
        /// The topmost certificate is self-issued.
        pub complete: bool,
        /// The chain consists of a single self-issued certificate.
        pub self_signed_only: bool,
        pub diagnostics: Vec<Diagnostic>,
    }
}

impl ChainSummary {
    pub fn len(&self) -> usize {
        self.indices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.indices.is_empty()
    }

    pub fn leaf(&self) -> Option<u32> {
        self.indices.first().copied()
    }

    pub fn root(&self) -> Option<u32> {
        self.indices.last().copied()
    }
}
