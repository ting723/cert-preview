model_enum! {
    /// Severity of a non-fatal finding.
    ///
    /// A `Diagnostic` is never a parse failure — those are `CertError`. These
    /// describe things the caller should probably know about a successfully
    /// parsed object.
    pub enum Severity {
        Info,
        Warning,
        Error,
    }
}

model! {
    pub struct Diagnostic {
        pub level: Severity,
        /// Stable machine-readable code, e.g. `CHAIN_BROKEN`, `WEAK_KEY`.
        pub code: String,
        pub message: String,
        /// Index into [`Bundle::items`](super::Bundle::items), when scoped to
        /// one object.
        pub item: Option<u32>,
    }
}

impl Diagnostic {
    pub fn info(code: &str, message: impl Into<String>) -> Self {
        Self::new(Severity::Info, code, message)
    }

    pub fn warn(code: &str, message: impl Into<String>) -> Self {
        Self::new(Severity::Warning, code, message)
    }

    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self::new(Severity::Error, code, message)
    }

    pub fn new(level: Severity, code: &str, message: impl Into<String>) -> Self {
        Self {
            level,
            code: code.to_string(),
            message: message.into(),
            item: None,
        }
    }

    pub fn at(mut self, item: usize) -> Self {
        self.item = Some(item as u32);
        self
    }
}

impl Severity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

impl core::fmt::Display for Severity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.as_str())
    }
}
