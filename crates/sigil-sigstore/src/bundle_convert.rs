//! Hybrid boundary: parse upstream Sigstore bundles with `sigstore-types`
//! and convert them into the local `SigstoreBundle` + `RekorEntry` pair
//! that `verify_bundle_with_trust` consumes.
//!
//! The local `SigstoreBundle` model predates the current bundle spec: it
//! has no `tlogEntries` field, so cosign-produced bundle JSON (which
//! carries the Rekor entry inline) cannot be parsed by it at all.
//! Rather than hand-growing a parallel JSON schema, this module delegates
//! wire-format parsing to `sigstore-types` — the same crate
//! `sigstore-trust-root` builds on — and maps the result onto SIGIL's
//! verification inputs. Verification semantics stay local; only the wire
//! format is delegated.
//!
//! Supported upstream shapes:
//! - `SignatureContent::MessageSignature` — DSSE envelopes are rejected
//!   (`BundleUnsupported`), the local path has no DSSE verification.
//! - `VerificationMaterialContent::Certificate` (v0.3) or
//!   `X509CertificateChain` (v0.1/v0.2) — public-key material is rejected.
//! - At least one `tlogEntries` item is required; the first entry is
//!   converted (the Rekor v1 model carries exactly one).

use crate::bundle_types::*;
use crate::error::SigstoreError;
use crate::trust::{InclusionProof, RekorEntry};
use base64::Engine as _;
use sigstore_types::bundle::{
    Bundle as UpstreamBundle, MediaType, SignatureContent, VerificationMaterialContent,
};

fn unsupported(msg: impl Into<String>) -> SigstoreError {
    SigstoreError::Bundle(format!("unsupported upstream bundle: {}", msg.into()))
}

/// Parse `json` with the upstream parser and convert to the local
/// verification inputs. The returned `RekorEntry` comes from the first
/// `tlogEntries` item.
pub fn parse_upstream_bundle(json: &str) -> Result<(SigstoreBundle, RekorEntry), SigstoreError> {
    let upstream = UpstreamBundle::from_json(json)
        .map_err(|e| SigstoreError::Bundle(format!("upstream bundle parse: {e}")))?;
    convert_bundle(&upstream)
}

fn convert_bundle(
    upstream: &UpstreamBundle,
) -> Result<(SigstoreBundle, RekorEntry), SigstoreError> {
    // Normalize the v0.3 alias ("+json;version=0.3") to the canonical
    // media type; anything else passes through and is rejected by the
    // verifier's media-type check.
    let media_type = match upstream.version() {
        Ok(MediaType::Bundle0_3) => BUNDLE_MEDIA_TYPE.to_string(),
        _ => upstream.media_type.clone(),
    };

    let certificates = match &upstream.verification_material.content {
        VerificationMaterialContent::Certificate(c) => {
            vec![BundleCertificate {
                raw_bytes: c.raw_bytes.to_base64(),
            }]
        }
        VerificationMaterialContent::X509CertificateChain { certificates } => certificates
            .iter()
            .map(|c| BundleCertificate {
                raw_bytes: c.raw_bytes.to_base64(),
            })
            .collect(),
        VerificationMaterialContent::PublicKey { .. } => {
            return Err(unsupported("public-key verification material"));
        }
    };

    let message_signature = match &upstream.content {
        SignatureContent::MessageSignature(ms) => {
            let digest = ms
                .message_digest
                .as_ref()
                .ok_or_else(|| unsupported("message signature without digest"))?;
            BundleMessageSignature {
                message_digest: BundleMessageDigest {
                    algorithm: digest.algorithm.to_string(),
                    digest: base64::engine::general_purpose::STANDARD
                        .encode(digest.digest.as_bytes()),
                },
                signature: ms.signature.to_base64(),
            }
        }
        SignatureContent::DsseEnvelope(_) => {
            return Err(unsupported("DSSE envelope content"));
        }
    };

    let entry = upstream
        .verification_material
        .tlog_entries
        .first()
        .ok_or_else(|| unsupported("bundle carries no tlogEntries"))?;
    let rekor_entry = convert_tlog_entry(entry)?;

    Ok((
        SigstoreBundle {
            media_type,
            verification_material: BundleVerificationMaterial {
                x509_certificate_chain: BundleX509Chain { certificates },
            },
            message_signature,
        },
        rekor_entry,
    ))
}

fn convert_tlog_entry(
    entry: &sigstore_types::bundle::TransparencyLogEntry,
) -> Result<RekorEntry, SigstoreError> {
    // Upstream carries the log ID as base64; the local model is hex.
    let log_id_bytes = base64::engine::general_purpose::STANDARD
        .decode(entry.log_id.key_id.as_ref() as &str)
        .map_err(|e| SigstoreError::Bundle(format!("tlog log_id base64: {e}")))?;
    let inclusion_proof = entry
        .inclusion_proof
        .as_ref()
        .map(|p| {
            Ok(InclusionProof {
                log_index: p
                    .log_index
                    .as_u64()
                    .ok_or_else(|| SigstoreError::Bundle("negative log index".into()))?,
                root_hash: hex::encode(p.root_hash.as_bytes()),
                tree_size: p
                    .tree_size
                    .try_into()
                    .map_err(|_| SigstoreError::Bundle("negative tree size".into()))?,
                // Local proofs carry base64 sibling hashes; upstream
                // Sha256Hash is raw bytes.
                hashes: p.hashes.iter().map(|h| h.to_base64()).collect(),
            })
        })
        .transpose()?;
    Ok(RekorEntry {
        body: entry.canonicalized_body.to_base64(),
        integrated_time: entry.integrated_time,
        log_id: hex::encode(log_id_bytes),
        log_index: entry.log_index.value(),
        signed_entry_timestamp: entry
            .inclusion_promise
            .as_ref()
            .map(|p| p.signed_entry_timestamp.to_base64()),
        inclusion_proof,
    })
}
