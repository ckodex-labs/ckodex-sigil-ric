pub const FULCIO_URL: &str = "https://fulcio.sigstore.dev";
/// Rekor production endpoint.
pub const REKOR_URL: &str = "https://rekor.sigstore.dev";

/// Ambient OIDC credential errors.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SigstoreError {
    #[error("no OIDC token: set SIGSTORE_ID_TOKEN or provide a token explicitly")]
    MissingOidcToken,
    #[error("CSR construction failed")]
    CsrFailed,
    #[error("Fulcio exchange failed: {0}")]
    Fulcio(String),
    #[error("Rekor upload failed: {0}")]
    Rekor(String),
    #[error("bundle parse/convert failed: {0}")]
    Bundle(String),
}

/// Where the OIDC identity token comes from.
#[derive(Clone, Debug)]
pub enum OidcSource {
    /// Read `SIGSTORE_ID_TOKEN` from the environment at construction time
    /// (CI workload identity — the decided credential source).
    Ambient,
    /// An explicit OIDC identity token.
    Token(String),
}

/// Environment variable read by [`OidcSource::Ambient`].
pub(crate) const AMBIENT_TOKEN_VAR: &str = "SIGSTORE_ID_TOKEN";

impl OidcSource {
    pub(crate) fn resolve(&self) -> Result<String, SigstoreError> {
        self.resolve_with(|var| std::env::var(var).ok())
    }

    /// Resolution with the environment lookup injected, so the ambient path is
    /// testable without mutating process state.
    pub(crate) fn resolve_with(
        &self,
        lookup: impl FnOnce(&str) -> Option<String>,
    ) -> Result<String, SigstoreError> {
        match self {
            OidcSource::Ambient => lookup(AMBIENT_TOKEN_VAR)
                .filter(|token| !token.is_empty())
                .ok_or(SigstoreError::MissingOidcToken),
            OidcSource::Token(token) if token.is_empty() => Err(SigstoreError::MissingOidcToken),
            OidcSource::Token(token) => Ok(token.clone()),
        }
    }
}
