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

impl OidcSource {
    pub(crate) fn resolve(&self) -> Result<String, SigstoreError> {
        match self {
            OidcSource::Ambient => std::env::var("SIGSTORE_ID_TOKEN")
                .ok()
                .filter(|token| !token.is_empty())
                .ok_or(SigstoreError::MissingOidcToken),
            OidcSource::Token(token) if token.is_empty() => Err(SigstoreError::MissingOidcToken),
            OidcSource::Token(token) => Ok(token.clone()),
        }
    }
}
