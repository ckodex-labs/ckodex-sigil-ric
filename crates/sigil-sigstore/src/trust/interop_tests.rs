//! Interop tests for the hybrid boundary: a bundle in the upstream
//! `sigstore-types` wire format (with inline `tlogEntries`, as cosign
//! produces) must convert and verify through `verify_upstream_bundle`.

use crate::trust::e2e_tests::{fixture, make_bundle, make_entry, Fixture, IDENTITY};
use crate::trust::types::TrustError;
use crate::trust::verify::verify_upstream_bundle;
use crate::{parse_upstream_bundle, SigstoreBundle};

/// Render a `SigstoreBundle` + `RekorEntry` as upstream wire-format JSON:
/// v0.3 media type, single `certificate` verification material, one
/// `tlogEntries` item carrying the SET and inclusion proof.
fn upstream_json(
    _f: &Fixture,
    bundle: &SigstoreBundle,
    entry: &crate::trust::RekorEntry,
) -> String {
    let b64 = base64::Engine::encode;
    let log_id_bytes = hex::decode(&entry.log_id).expect("hex log id");
    let root_hash_bytes = hex::decode(&entry.inclusion_proof.as_ref().expect("proof").root_hash)
        .expect("hex root hash");
    let proof = entry.inclusion_proof.as_ref().expect("proof");
    serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {
            "certificate": {
                "rawBytes": bundle.verification_material.x509_certificate_chain.certificates[0].raw_bytes,
            },
            "tlogEntries": [{
                "logIndex": "0",
                "logId": {"keyId": b64(&base64::engine::general_purpose::STANDARD, &log_id_bytes)},
                "kindVersion": {"kind": "hashedrekord", "version": "0.0.1"},
                "integratedTime": entry.integrated_time.to_string(),
                "inclusionPromise": {
                    "signedEntryTimestamp": entry.signed_entry_timestamp.as_ref().expect("set"),
                },
                "inclusionProof": {
                    "logIndex": "0",
                    "rootHash": b64(&base64::engine::general_purpose::STANDARD, &root_hash_bytes),
                    "treeSize": proof.tree_size.to_string(),
                    "hashes": proof.hashes,
                },
                "canonicalizedBody": entry.body,
            }],
        },
        "messageSignature": {
            "messageDigest": {
                "algorithm": bundle.message_signature.message_digest.algorithm,
                "digest": bundle.message_signature.message_digest.digest,
            },
            "signature": bundle.message_signature.signature,
        },
    })
    .to_string()
}

#[test]
fn upstream_bundle_with_tlog_entries_verifies() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    let json = upstream_json(&f, &bundle, &entry);
    verify_upstream_bundle(&json, message, &f.trust, IDENTITY)
        .expect("a cosign-shaped bundle must verify end-to-end");
}

#[test]
fn upstream_v03_media_type_alias_normalizes() {
    // Upstream also accepts "…bundle+json;version=0.3"; conversion must
    // normalize it to the canonical v0.3 media type so the local check
    // accepts it.
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    let json = upstream_json(&f, &bundle, &entry).replace(
        "application/vnd.dev.sigstore.bundle.v0.3+json",
        "application/vnd.dev.sigstore.bundle+json;version=0.3",
    );
    let (converted, _) = parse_upstream_bundle(&json).expect("alias parses");
    assert_eq!(converted.media_type, crate::BUNDLE_MEDIA_TYPE);
}

#[test]
fn upstream_dsse_envelope_is_rejected() {
    let json = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": "AA=="}},
        "dsseEnvelope": {"payloadType": "x", "payload": "AA==", "signatures": []},
    })
    .to_string();
    let err = parse_upstream_bundle(&json).expect_err("DSSE must be rejected");
    assert!(matches!(err, crate::SigstoreError::Bundle(_)));
}

#[test]
fn upstream_bundle_without_tlog_entries_is_rejected() {
    let json = serde_json::json!({
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": "AA=="}},
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_384", "digest": "AA=="},
            "signature": "AA==",
        },
    })
    .to_string();
    let err = parse_upstream_bundle(&json).expect_err("missing tlogEntries must fail");
    assert!(matches!(err, crate::SigstoreError::Bundle(_)));
}

#[test]
fn real_cosign_dsse_bundle_parses_upstream_then_rejects() {
    // Real cosign-produced v0.3 bundle (sigstore-rs tests/data) — DSSE
    // envelope content. `sigstore-types` must parse the real wire format
    // (certificate + tlogEntries + timestampVerificationData); the
    // boundary then rejects DSSE explicitly — the local path verifies
    // message-signature bundles only.
    let json = include_str!("../../tests/fixtures/bundle_v03_dsse.json");
    let err = parse_upstream_bundle(json).expect_err("DSSE bundle must be rejected");
    assert!(matches!(err, crate::SigstoreError::Bundle(_)));
    assert!(err.to_string().contains("DSSE"), "unexpected error: {err}");
}

#[test]
fn upstream_non_v03_media_type_fails_at_verify() {
    // A v0.2 bundle parses but must be rejected by the media-type check
    // in verify_bundle_with_trust.
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    let json = upstream_json(&f, &bundle, &entry).replace(
        "application/vnd.dev.sigstore.bundle.v0.3+json",
        "application/vnd.dev.sigstore.bundle+json;version=0.2",
    );
    let err = verify_upstream_bundle(&json, message, &f.trust, IDENTITY)
        .expect_err("v0.2 media type must be rejected");
    assert!(matches!(err, TrustError::MediaType { .. }));
}
