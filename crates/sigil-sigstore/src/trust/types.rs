use serde::{Deserialize, Serialize};
pub struct TrustRoot {
    /// DER-encoded Fulcio root CA certificate.
    pub fulcio_root_der: Vec<u8>,
    /// DER-encoded Fulcio intermediate CA certificate(s).
    pub fulcio_intermediates_der: Vec<Vec<u8>>,
    /// Rekor's P-256 public key (raw uncompressed point, 65 bytes).
    pub rekor_public_key: Vec<u8>,
    /// Rekor log ID (SHA-256 of the DER-encoded Rekor public key, hex).
    pub rekor_log_id: String,
    /// CT log keys trusted for embedded-SCT verification, as
    /// `(log_id, spki_der)` pairs distributed by the trust root
    /// (`TrustedRoot::ctfe_keys_with_ids`). `log_id` is SHA-256 of the
    /// DER-encoded SubjectPublicKeyInfo. Empty means CT is not provisioned
    /// for this root — the embedded production root always carries keys.
    pub ctfe_keys: Vec<(Vec<u8>, Vec<u8>)>,
}
/// A Rekor transparency-log entry (v1 shape).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RekorEntry {
    /// Base64-encoded canonicalized body (the hashedrekord JSON).
    pub body: String,
    /// Unix timestamp (seconds) when the entry was integrated.
    pub integrated_time: i64,
    /// SHA-256 of the Rekor public key (hex, 64 chars).
    pub log_id: String,
    /// Global log index.
    pub log_index: i64,
    /// Base64-encoded Signed Entry Timestamp (Rekor's P-256 signature).
    pub signed_entry_timestamp: Option<String>,
    /// Inclusion proof (optional — present in full bundles).
    pub inclusion_proof: Option<InclusionProof>,
}
/// RFC 6962 inclusion proof.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub log_index: u64,
    pub root_hash: String,
    pub tree_size: u64,
    /// Base64-encoded sibling hashes (audit path, leaf → root).
    pub hashes: Vec<String>,
}
/// Errors from chain-of-trust validation.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TrustError {
    #[error("bundle media type mismatch: expected {expected}, got {got}")]
    MediaType { expected: String, got: String },
    #[error("empty certificate chain in bundle")]
    EmptyChain,
    #[error("certificate parse failed: {0}")]
    CertParse(String),
    #[error("chain validation failed: {0}")]
    ChainValidation(String),
    #[error("leaf certificate expired at signing time")]
    Expired,
    #[error("leaf certificate not yet valid at signing time")]
    NotYetValid,
    #[error("SAN identity mismatch: expected {expected}, got {got}")]
    SanMismatch { expected: String, got: String },
    #[error("Rekor log ID mismatch: expected {expected}, got {got}")]
    LogIdMismatch { expected: String, got: String },
    #[error("SET verification failed: {0}")]
    SetFailed(String),
    #[error("inclusion proof verification failed: {0}")]
    InclusionProofFailed(String),
    #[error("missing SET (signed entry timestamp)")]
    MissingSet,
    #[error("missing inclusion proof")]
    MissingInclusionProof,
    #[error("signature verification failed: {0}")]
    SignatureFailed(String),
    #[error("Rekor entry binding failed: {0}")]
    RekorBinding(String),
    #[error("missing embedded SCT extension (OID 1.3.6.1.4.1.11129.2.4.2)")]
    MissingSct,
    #[error("SCT verification failed: {0}")]
    SctFailed(String),
    #[error("unsupported bundle content: {0}")]
    BundleUnsupported(String),
}
