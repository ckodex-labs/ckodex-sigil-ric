//! TUF root distribution for Sigstore keyless verification.
//!
//! The Sigstore trust root (Fulcio certificates, Rekor public keys, CT log
//! keys, TSA certificates) is distributed via TUF (The Update Framework)
//! from `https://tuf-repo-cdn.sigstore.dev/`. The `sigstore-trust-root`
//! crate embeds a verified snapshot of `trusted_root.json` (the TUF
//! target) so verification can proceed without network access.
//!
//! This module bridges `sigstore_trust_root::TrustedRoot` (the official
//! Rust parsing crate) to our `crate::trust::TrustRoot` (the struct our
//! verification code consumes).
//!
//! **Trust anchor:** the embedded root is pinned at crate build time. For
//! production freshness, callers SHOULD periodically update the crate or
//! use the async `TrustedRoot::production()` method (behind the `tuf`
//! feature) to fetch the latest trust root via the full TUF protocol.
//! The embedded root is sufficient for offline verification of signatures
//! created while the embedded root was current.

use base64::Engine as _;
use sigstore_trust_root::SigstoreInstance;
use sigstore_trust_root::TrustedRoot as SigstoreTrustedRoot;

use crate::trust::TrustRoot;
use crate::SigstoreError;

/// Load the embedded production trust root and convert it to our
/// `TrustRoot` struct. No network access required.
///
/// The embedded root is a verified snapshot of `trusted_root.json` from
/// `https://tuf-repo-cdn.sigstore.dev/`, pinned at `sigstore-trust-root`
/// crate build time. It contains the Fulcio root + intermediate
/// certificates and the Rekor P-256 public key(s).
pub fn trust_root_from_embedded() -> Result<TrustRoot, SigstoreError> {
    let trusted = SigstoreTrustedRoot::from_embedded(SigstoreInstance::PublicGood)
        .map_err(|e| SigstoreError::Fulcio(format!("embedded trust root: {e}")))?;
    convert_trusted_root(&trusted)
}

/// Load the embedded staging trust root (for testing against the
/// Sigstore staging instance).
pub fn trust_root_from_embedded_staging() -> Result<TrustRoot, SigstoreError> {
    let trusted = SigstoreTrustedRoot::from_embedded(SigstoreInstance::Staging)
        .map_err(|e| SigstoreError::Fulcio(format!("embedded staging trust root: {e}")))?;
    convert_trusted_root(&trusted)
}

/// Convert a `sigstore_trust_root::TrustedRoot` into our `TrustRoot`.
///
/// Extracts:
/// - Fulcio root certificate (self-signed, last in the chain)
/// - Fulcio intermediate certificates (all others)
/// - Rekor public key + log ID (first active key)
fn convert_trusted_root(trusted: &SigstoreTrustedRoot) -> Result<TrustRoot, SigstoreError> {
    // Fulcio certificates: split into root (self-signed) and intermediates.
    let fulcio_certs = trusted
        .fulcio_certs()
        .map_err(|e| SigstoreError::Fulcio(format!("fulcio_certs: {e}")))?;

    if fulcio_certs.is_empty() {
        return Err(SigstoreError::Fulcio(
            "no Fulcio certificates in trust root".to_string(),
        ));
    }

    // The root is the last certificate (self-signed). The rest are
    // intermediates. This matches the Fulcio trust bundle layout
    // (leaf-first ordering, root last).
    let (intermediates, root) = fulcio_certs.split_at(fulcio_certs.len() - 1);
    let fulcio_root_der = root[0].as_ref().to_vec();
    let fulcio_intermediates_der: Vec<Vec<u8>> =
        intermediates.iter().map(|c| c.as_ref().to_vec()).collect();

    // Rekor public keys: pick the first active key.
    let rekor_keys = trusted
        .rekor_keys()
        .map_err(|e| SigstoreError::Fulcio(format!("rekor_keys: {e}")))?;

    if rekor_keys.is_empty() {
        return Err(SigstoreError::Fulcio(
            "no Rekor public keys in trust root".to_string(),
        ));
    }

    // Take the first key. The key ID from `sigstore-trust-root` is
    // base64-encoded; the Rekor entry's `logID` field is hex. Convert.
    let (rekor_log_id_b64, rekor_public_key) = rekor_keys
        .iter()
        .next()
        .ok_or(SigstoreError::Fulcio("empty rekor keys".to_string()))?;
    let rekor_log_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(rekor_log_id_b64)
        .map_err(|e| SigstoreError::Fulcio(format!("rekor log ID base64: {e}")))?;
    let rekor_log_id = hex::encode(&rekor_log_id_bytes);

    // CT log keys for embedded-SCT verification: (log_id, SPKI DER).
    let ctfe_keys = trusted
        .ctfe_keys_with_ids()
        .map_err(|e| SigstoreError::Fulcio(format!("ctfe_keys: {e}")))?
        .into_iter()
        .map(|(log_id, key)| (log_id, key.as_bytes().to_vec()))
        .collect();

    Ok(TrustRoot {
        fulcio_root_der,
        fulcio_intermediates_der,
        rekor_public_key: rekor_public_key.clone(),
        rekor_log_id,
        ctfe_keys,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_production_root_loads() {
        let root = trust_root_from_embedded().expect("embedded root");
        assert!(!root.fulcio_root_der.is_empty());
        assert!(!root.rekor_public_key.is_empty());
        assert!(!root.rekor_log_id.is_empty());
        // Log ID is a hex SHA-256 (64 chars).
        assert_eq!(root.rekor_log_id.len(), 64);
        // Rekor public key is a DER-encoded SPKI (starts with 0x30 SEQUENCE).
        assert_eq!(root.rekor_public_key[0], 0x30);
        // The production root provisions CT log keys — SCT verification
        // is mandatory for Fulcio-issued certs.
        assert!(!root.ctfe_keys.is_empty());
    }

    #[test]
    fn embedded_staging_root_loads() {
        let root = trust_root_from_embedded_staging().expect("staging root");
        assert!(!root.fulcio_root_der.is_empty());
        assert!(!root.rekor_public_key.is_empty());
    }

    #[test]
    fn fulcio_root_is_der_certificate() {
        let root = trust_root_from_embedded().expect("root");
        // DER certificate starts with SEQUENCE tag (0x30).
        assert_eq!(root.fulcio_root_der[0], 0x30);
    }

    #[test]
    fn rekor_log_id_is_hex_sha256() {
        let root = trust_root_from_embedded().expect("root");
        // Log ID must be valid hex.
        assert!(
            root.rekor_log_id.chars().all(|c| c.is_ascii_hexdigit()),
            "log ID contains non-hex chars: {}",
            root.rekor_log_id
        );
        assert_eq!(root.rekor_log_id.len(), 64, "SHA-256 hex = 64 chars");
    }
}
