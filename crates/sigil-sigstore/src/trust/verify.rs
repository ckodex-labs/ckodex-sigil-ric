use crate::trust::chain::{check_san_identity, check_validity_at, validate_chain};
use crate::trust::fetch::parse_cert;
use crate::trust::rekor::{verify_inclusion_proof, verify_rekor_entry_binding, verify_rekor_set};
use crate::trust::types::{RekorEntry, TrustError, TrustRoot};
use crate::{SigstoreBundle, BUNDLE_MEDIA_TYPE};
use base64::Engine as _;

/// Full keyless verification of a Sigstore bundle against a pinned trust root.
///
/// Verification path:
/// 1. Signature binding (message → leaf cert public key)
/// 2. Certificate chain validation (leaf → intermediate → root)
/// 3. SAN identity check against `expected_identity`
/// 4. Validity window at Rekor `integratedTime`
/// 5. Rekor SET verification
/// 6. Rekor inclusion proof verification (RFC 6962)
/// 7. Rekor entry binding — `canonicalizedBody` artifact hash and signature
///    must match the artifact and signature being verified
pub fn verify_bundle_with_trust(
    bundle: &SigstoreBundle,
    message: &[u8],
    trust: &TrustRoot,
    rekor_entry: &RekorEntry,
    expected_identity: &str,
) -> Result<(), TrustError> {
    if bundle.media_type != BUNDLE_MEDIA_TYPE {
        return Err(TrustError::MediaType {
            expected: BUNDLE_MEDIA_TYPE.to_string(),
            got: bundle.media_type.clone(),
        });
    }
    // 1. Signature binding: leaf cert public key verifies the message.
    crate::verify_bundle(bundle, message)
        .map_err(|e| TrustError::SignatureFailed(format!("{e:?}")))?;
    // 2. Certificate chain validation.
    let chain_der: Vec<Vec<u8>> = bundle
        .verification_material
        .x509_certificate_chain
        .certificates
        .iter()
        .map(|c| {
            base64::engine::general_purpose::STANDARD
                .decode(&c.raw_bytes)
                .map_err(|_| TrustError::CertParse("base64 decode failed".to_string()))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if chain_der.is_empty() {
        return Err(TrustError::EmptyChain);
    }
    validate_chain(&chain_der, trust)?;
    // 3. SAN identity check on the leaf.
    let leaf_cert = parse_cert(&chain_der[0])?;
    check_san_identity(&leaf_cert, expected_identity)?;
    // 4. Validity window at Rekor integratedTime.
    check_validity_at(&leaf_cert, rekor_entry.integrated_time)?;
    // 5. Rekor log ID check.
    if rekor_entry.log_id != trust.rekor_log_id {
        return Err(TrustError::LogIdMismatch {
            expected: trust.rekor_log_id.clone(),
            got: rekor_entry.log_id.clone(),
        });
    }
    // 6. Rekor SET verification.
    if let Some(set_b64) = &rekor_entry.signed_entry_timestamp {
        verify_rekor_set(rekor_entry, set_b64, &trust.rekor_public_key)?;
    } else {
        return Err(TrustError::MissingSet);
    }
    // 7. Rekor inclusion proof verification.
    if let Some(proof) = &rekor_entry.inclusion_proof {
        verify_inclusion_proof(rekor_entry, proof)?;
    } else {
        return Err(TrustError::MissingInclusionProof);
    }
    // 8. Rekor entry binding: the canonicalizedBody must reference THIS
    // artifact, not an arbitrary one. Without this check a bundle could
    // contain a valid Rekor entry for a different artifact (GHSA-whqx-f9j3-ch6m).
    verify_rekor_entry_binding(rekor_entry, message, bundle)?;
    Ok(())
}
