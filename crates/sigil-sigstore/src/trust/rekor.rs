use crate::trust::types::{InclusionProof, RekorEntry, TrustError};
use crate::SigstoreBundle;
use base64::Engine as _;
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use sha2::{Digest as _, Sha256};
pub(crate) fn verify_rekor_set(
    entry: &RekorEntry,
    set_b64: &str,
    rekor_public_key: &[u8],
) -> Result<(), TrustError> {
    // Construct the canonical JSON payload that the SET signs.
    // Per Rekor's openapi.yaml: {body, integratedTime, logID, logIndex}.
    // RFC 8785 requires lexicographic key ordering.
    let canonical = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        entry.body, entry.integrated_time, entry.log_id, entry.log_index
    );
    let set_bytes = base64::engine::general_purpose::STANDARD
        .decode(set_b64)
        .map_err(|e| TrustError::SetFailed(format!("base64 decode: {e}")))?;
    // Rekor uses ECDSA P-256 with SHA-256.
    let verifying_key = P256VerifyingKey::from_sec1_bytes(rekor_public_key)
        .map_err(|e| TrustError::SetFailed(format!("key parse: {e}")))?;
    // `Signature::from_slice` returns Err on wrong-length input; the
    // `GenericArray::from_slice` it replaces would panic on a malformed
    // (non-64-byte) SET from the wire.
    let signature = P256Signature::from_slice(&set_bytes)
        .map_err(|_| TrustError::SetFailed("signature parse failed".into()))?;
    verifying_key
        .verify(canonical.as_bytes(), &signature)
        .map_err(|e| TrustError::SetFailed(format!("SET verify: {e}")))
}
/// Verify a Rekor inclusion proof per RFC 6962 §2.1.1.
///
/// The Merkle tree uses domain-separated hashing:
/// - Leaf hash: `SHA256(0x00 || leaf_data)`
/// - Node hash: `SHA256(0x01 || left || right)`
///
/// The inclusion proof gives the audit path (sibling hashes) from the
/// leaf up to the root. We recompute the root and compare to `root_hash`.
///
/// The right-edge case (`fn == sn`) is handled: when the current node is
/// the rightmost at its level, its sibling is to the left (not right),
/// and a naive left/right parity test is wrong.
pub(crate) fn verify_inclusion_proof(
    entry: &RekorEntry,
    proof: &InclusionProof,
) -> Result<(), TrustError> {
    // Decode the canonicalized body (the leaf data).
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(&entry.body)
        .map_err(|e| TrustError::InclusionProofFailed(format!("body decode: {e}")))?;
    // RFC 6962 §2.1.1: leaf hash = SHA256(0x00 || leaf_data).
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00]);
    leaf_hasher.update(&body_bytes);
    let mut computed = leaf_hasher.finalize();
    // Walk the audit path per RFC 6962 §2.1.1.
    let mut node_index = proof.log_index;
    let mut last_index = proof.tree_size - 1;
    for (i, hash_b64) in proof.hashes.iter().enumerate() {
        let sibling = base64::engine::general_purpose::STANDARD
            .decode(hash_b64)
            .map_err(|e| TrustError::InclusionProofFailed(format!("hash[{i}] decode: {e}")))?;
        if node_index == last_index && (last_index & 1) == 0 {
            // Right-edge case: this node is the rightmost at its level.
            // The sibling is to the LEFT: parent = SHA256(0x01 || sibling || computed).
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(&sibling);
            hasher.update(computed);
            computed = hasher.finalize();
        } else if (node_index & 1) == 0 {
            // Left child: sibling is to the right.
            // parent = SHA256(0x01 || computed || sibling).
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(computed);
            hasher.update(&sibling);
            computed = hasher.finalize();
        } else {
            // Right child: sibling is to the left.
            // parent = SHA256(0x01 || sibling || computed).
            let mut hasher = Sha256::new();
            hasher.update([0x01]);
            hasher.update(&sibling);
            hasher.update(computed);
            computed = hasher.finalize();
        }
        node_index >>= 1;
        last_index >>= 1;
    }
    // The recomputed root must match the proof's root hash.
    let computed_hex = hex::encode(computed);
    if computed_hex != proof.root_hash {
        return Err(TrustError::InclusionProofFailed(format!(
            "root hash mismatch: computed {computed_hex}, expected {}",
            proof.root_hash
        )));
    }
    Ok(())
}
/// Verify that a Rekor entry's canonicalizedBody references the artifact
/// being verified — not an arbitrary entry from the log (GHSA-whqx-f9j3-ch6m).
///
/// The hashedrekord body is a JSON object with the shape:
/// ```json
/// {"apiVersion":"0.0.1","kind":"hashedrekord","spec":{
///   "data":{"hash":{"algorithm":"sha256","value":"<artifact_sha256_hex>"}},
///   "signature":{"content":"<base64_sig>","publicKey":{"content":"<base64_key>"}}}}
/// ```
///
/// We compare:
/// - `spec.data.hash.value` against `SHA-256(message)` — binds the entry to
///   the specific artifact bytes.
/// - `spec.signature.content` against the bundle's `message_signature.signature`
///   — binds the entry to the specific signature.
///
/// The `publicKey.content` is not compared directly because Rekor may
/// normalize it (PEM vs DER, cert vs raw key). The artifact hash and
/// signature comparisons are sufficient to prevent substitution.
pub(crate) fn verify_rekor_entry_binding(
    entry: &RekorEntry,
    message: &[u8],
    bundle: &SigstoreBundle,
) -> Result<(), TrustError> {
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(&entry.body)
        .map_err(|e| TrustError::RekorBinding(format!("body decode: {e}")))?;
    let body: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| TrustError::RekorBinding(format!("body JSON: {e}")))?;
    // spec.data.hash.value must equal SHA-256 of the artifact.
    let expected_hash = {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(message);
        hex::encode(h.finalize())
    };
    let entry_hash = body
        .pointer("/spec/data/hash/value")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TrustError::RekorBinding("missing spec.data.hash.value".into()))?;
    if entry_hash != expected_hash {
        return Err(TrustError::RekorBinding(format!(
            "artifact hash mismatch: entry={entry_hash}, expected={expected_hash}"
        )));
    }
    // spec.signature.content must equal the bundle's signature.
    let entry_sig = body
        .pointer("/spec/signature/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| TrustError::RekorBinding("missing spec.signature.content".into()))?;
    if entry_sig != bundle.message_signature.signature {
        return Err(TrustError::RekorBinding(
            "signature content mismatch: entry references a different signature".into(),
        ));
    }
    Ok(())
}
