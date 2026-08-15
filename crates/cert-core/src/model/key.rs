model_enum! {
    pub enum PrivateKeyFormat {
        /// RFC 5208 / 5958 `PrivateKeyInfo`, PEM label `PRIVATE KEY`.
        Pkcs8,
        /// RFC 5958 `EncryptedPrivateKeyInfo`, PEM label `ENCRYPTED PRIVATE KEY`.
        Pkcs8Encrypted,
        /// PKCS#1 `RSAPrivateKey`, PEM label `RSA PRIVATE KEY`.
        Pkcs1,
        /// SEC1 `ECPrivateKey`, PEM label `EC PRIVATE KEY`.
        Sec1,
    }
}

model! {
    /// An algorithm identifier, resolved to a readable name where possible.
    pub struct AlgorithmInfo {
        pub oid: String,
        /// Resolved name, e.g. `sha256WithRSAEncryption`. Falls back to the
        /// dotted OID when unknown, so this field is never empty.
        pub name: String,
        /// Rendered parameters, e.g. the named curve for an EC key.
        pub parameters: Option<String>,
    }

    pub struct PublicKeyInfo {
        pub algorithm: AlgorithmInfo,
        /// Modulus size for RSA, field size for EC, `None` when undetermined.
        pub key_size_bits: Option<u32>,
        /// Named curve for EC keys, e.g. `prime256v1`.
        pub curve: Option<String>,
        /// RSA public exponent in decimal, e.g. `65537`.
        pub rsa_exponent: Option<String>,
        /// Base64 SHA-256 over the DER SubjectPublicKeyInfo — the value used
        /// for HPKP-style pinning and for matching a key to a certificate.
        pub spki_sha256: String,
        pub der_len: u32,
    }

    /// Private key **metadata**.
    ///
    /// This struct intentionally has no field capable of carrying key
    /// material. A viewer should never be able to leak a private key through
    /// its own output, so the secret components are dropped during parsing
    /// rather than filtered during rendering.
    pub struct PrivateKeyInfo {
        pub format: PrivateKeyFormat,
        pub algorithm: AlgorithmInfo,
        pub key_size_bits: Option<u32>,
        pub curve: Option<String>,
        pub encrypted: bool,
        /// Derived public half, when it is embedded in the key structure.
        pub public_key: Option<PublicKeyInfo>,
        pub der_len: u32,
    }
}

impl AlgorithmInfo {
    pub fn new(oid: impl Into<String>, name: impl Into<String>) -> Self {
        Self {
            oid: oid.into(),
            name: name.into(),
            parameters: None,
        }
    }

    pub fn with_parameters(mut self, p: impl Into<String>) -> Self {
        self.parameters = Some(p.into());
        self
    }

    /// An OID with no registry entry: show the dotted form as the name.
    pub fn unresolved(oid: impl Into<String>) -> Self {
        let oid = oid.into();
        Self {
            name: oid.clone(),
            oid,
            parameters: None,
        }
    }
}

impl PrivateKeyFormat {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pkcs8 => "PKCS#8",
            Self::Pkcs8Encrypted => "PKCS#8 (encrypted)",
            Self::Pkcs1 => "PKCS#1",
            Self::Sec1 => "SEC1",
        }
    }
}

impl core::fmt::Display for PrivateKeyFormat {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl PublicKeyInfo {
    /// Short one-line summary, e.g. `RSA 2048 bit` or `EC prime256v1`.
    pub fn summary(&self) -> String {
        match (&self.curve, self.key_size_bits) {
            (Some(c), _) => format!("{} {c}", self.algorithm.name),
            (None, Some(bits)) => format!("{} {bits} bit", self.algorithm.name),
            (None, None) => self.algorithm.name.clone(),
        }
    }
}
