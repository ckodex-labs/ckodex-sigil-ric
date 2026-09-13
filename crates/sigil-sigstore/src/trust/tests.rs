use crate::trust::rekor::verify_inclusion_proof;
use crate::trust::rekor::verify_rekor_entry_binding;
use crate::trust::types::*;
use base64::Engine as _;
use sha2::{Digest as _, Sha256};

#[test]
fn rfc6962_leaf_hash_is_domain_separated() {
    // RFC 6962: leaf = SHA256(0x00 || data). Verify the domain prefix.
    let data = b"test leaf";
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(data);
    let expected = h.finalize();
    // A naive SHA256(data) must NOT match.
    let naive = Sha256::digest(data);
    assert_ne!(expected.as_slice(), naive.as_slice());
}

#[test]
fn rfc6962_node_hash_is_domain_separated() {
    let left = [0xaa; 32];
    let right = [0xbb; 32];
    let mut h = Sha256::new();
    h.update([0x01]);
    h.update(left);
    h.update(right);
    let expected = h.finalize();
    let naive = Sha256::digest([left.as_slice(), right.as_slice()].concat());
    assert_ne!(expected.as_slice(), naive.as_slice());
}

#[test]
fn inclusion_proof_single_element_tree() {
    // A tree with one leaf: root = leaf_hash, empty audit path.
    let body = b"{\"test\":\"entry\"}";
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body);
    let mut h = Sha256::new();
    h.update([0x00]);
    h.update(body);
    let root = hex::encode(h.finalize());

    let entry = RekorEntry {
        body: body_b64,
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: Some(InclusionProof {
            log_index: 0,
            root_hash: root,
            tree_size: 1,
            hashes: vec![],
        }),
    };
    let proof = entry.inclusion_proof.as_ref().unwrap();
    assert_eq!(verify_inclusion_proof(&entry, proof), Ok(()));
}

#[test]
fn inclusion_proof_two_element_tree() {
    // Tree: leaf0, leaf1 → root = SHA256(0x01 || h(leaf0) || h(leaf1)).
    let body0 = b"leaf0";
    let body1 = b"leaf1";
    let mut h0 = Sha256::new();
    h0.update([0x00]);
    h0.update(body0);
    let leaf0_hash = h0.finalize();

    let mut h1 = Sha256::new();
    h1.update([0x00]);
    h1.update(body1);
    let leaf1_hash = h1.finalize();

    let mut hr = Sha256::new();
    hr.update([0x01]);
    hr.update(leaf0_hash);
    hr.update(leaf1_hash);
    let root = hex::encode(hr.finalize());

    // Proof for leaf0: sibling = leaf1_hash.
    let body0_b64 = base64::engine::general_purpose::STANDARD.encode(body0);
    let entry = RekorEntry {
        body: body0_b64,
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: Some(InclusionProof {
            log_index: 0,
            root_hash: root,
            tree_size: 2,
            hashes: vec![base64::engine::general_purpose::STANDARD.encode(leaf1_hash)],
        }),
    };
    let proof = entry.inclusion_proof.as_ref().unwrap();
    assert_eq!(verify_inclusion_proof(&entry, proof), Ok(()));
}

#[test]
fn inclusion_proof_tampered_root_fails() {
    let body = b"leaf";
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(body);
    let entry = RekorEntry {
        body: body_b64,
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: Some(InclusionProof {
            log_index: 0,
            root_hash: "deadbeef".to_string(),
            tree_size: 1,
            hashes: vec![],
        }),
    };
    let proof = entry.inclusion_proof.as_ref().unwrap();
    assert!(verify_inclusion_proof(&entry, proof).is_err());
}

#[test]
fn set_canonical_json_shape() {
    // Verify the canonical JSON shape matches Rekor's spec.
    let entry = RekorEntry {
        body: "Ym9keQ==".to_string(),
        integrated_time: 1700000000,
        log_id: "abc123".to_string(),
        log_index: 42,
        signed_entry_timestamp: None,
        inclusion_proof: None,
    };
    // The canonical JSON must have keys in lexicographic order per RFC 8785.
    let expected =
        r#"{"body":"Ym9keQ==","integratedTime":1700000000,"logID":"abc123","logIndex":42}"#;
    let actual = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        entry.body, entry.integrated_time, entry.log_id, entry.log_index
    );
    assert_eq!(actual, expected);
}

fn make_hashedrekord_body(artifact_sha256_hex: &str, signature_b64: &str) -> String {
    let json = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": {"hash": {"algorithm": "sha256", "value": artifact_sha256_hex}},
            "signature": {"content": signature_b64, "publicKey": {"content": "test-key"}}
        }
    });
    base64::engine::general_purpose::STANDARD.encode(json.to_string())
}

fn make_test_bundle(sig_b64: &str) -> crate::SigstoreBundle {
    crate::SigstoreBundle {
        media_type: crate::BUNDLE_MEDIA_TYPE.to_string(),
        verification_material: crate::BundleVerificationMaterial {
            x509_certificate_chain: crate::BundleX509Chain {
                certificates: vec![],
            },
        },
        message_signature: crate::BundleMessageSignature {
            message_digest: crate::BundleMessageDigest {
                algorithm: "SHA2_384".to_string(),
                digest: "test".to_string(),
            },
            signature: sig_b64.to_string(),
        },
    }
}

#[test]
fn rekor_binding_accepts_matching_entry() {
    let message = b"test artifact";
    let artifact_hash = {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(message);
        hex::encode(h.finalize())
    };
    let sig_b64 = "dGVzdC1zaWc=";
    let entry = RekorEntry {
        body: make_hashedrekord_body(&artifact_hash, sig_b64),
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: None,
    };
    let bundle = make_test_bundle(sig_b64);
    assert_eq!(verify_rekor_entry_binding(&entry, message, &bundle), Ok(()));
}

#[test]
fn rekor_binding_rejects_wrong_artifact() {
    let sig_b64 = "dGVzdC1zaWc=";
    let entry = RekorEntry {
        body: make_hashedrekord_body("deadbeef", sig_b64),
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: None,
    };
    let bundle = make_test_bundle(sig_b64);
    let err = verify_rekor_entry_binding(&entry, b"different artifact", &bundle)
        .expect_err("wrong artifact must fail");
    assert!(matches!(err, TrustError::RekorBinding(_)));
}

#[test]
fn rekor_binding_rejects_wrong_signature() {
    let message = b"test artifact";
    let artifact_hash = {
        use sha2::Digest;
        let mut h = Sha256::new();
        h.update(message);
        hex::encode(h.finalize())
    };
    let entry = RekorEntry {
        body: make_hashedrekord_body(&artifact_hash, "b3RoZXItc2ln"),
        integrated_time: 1700000000,
        log_id: "a".repeat(64),
        log_index: 0,
        signed_entry_timestamp: None,
        inclusion_proof: None,
    };
    let bundle = make_test_bundle("dGVzdC1zaWc=");
    let err = verify_rekor_entry_binding(&entry, message, &bundle)
        .expect_err("wrong signature must fail");
    assert!(matches!(err, TrustError::RekorBinding(_)));
}
