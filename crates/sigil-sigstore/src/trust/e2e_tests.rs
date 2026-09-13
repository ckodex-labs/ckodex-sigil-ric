use crate::trust::types::{InclusionProof, RekorEntry, TrustError, TrustRoot};
use crate::trust::verify::verify_bundle_with_trust;
use crate::{build_bundle, SigstoreBundle};
use base64::Engine as _;
use der::asn1::{BitString, Ia5String, OctetString, UtcTime};
use der::Encode as _;
use p256::ecdsa::{
    signature::Signer as _, Signature as P256Signature, SigningKey as P256SigningKey,
};
use p384::ecdsa::SigningKey as P384SigningKey;
use sha2::{Digest as _, Sha256};
use std::str::FromStr as _;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_cert::certificate::{Certificate, TbsCertificate, Version};
use x509_cert::ext::pkix::name::{GeneralName, GeneralNames};
use x509_cert::ext::Extension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};
use x509_cert::time::{Time, Validity};

const IDENTITY: &str = "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main";

/// Synthetic but cryptographically valid trust material: a self-signed P-256
/// CA root, a P-384 leaf signed by it (DER ECDSA-Sig-Value, as real Fulcio
/// certs carry), and a P-256 Rekor key. `rekor_log_id` is derived the way
/// Sigstore derives it: SHA-256 of the Rekor public key's SPKI DER.
struct Fixture {
    trust: TrustRoot,
    leaf_der: Vec<u8>,
    leaf_key: P384SigningKey,
    rekor_key: P256SigningKey,
    integrated_time: i64,
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs() as i64
}

fn utc_time(secs: i64) -> Time {
    Time::UtcTime(
        UtcTime::from_unix_duration(Duration::from_secs(secs.max(0) as u64)).expect("time"),
    )
}

fn ecdsa_sha256_alg() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_256,
        parameters: None,
    }
}

/// Build a TBS cert and sign it with a P-256 issuer key. The signature is
/// stored DER-encoded — the X.509 ECDSA-Sig-Value encoding — which also
/// exercises `verify_cert_signature`'s DER parse path.
fn signed_cert(
    serial: u8,
    subject: &str,
    issuer: &str,
    spki: SubjectPublicKeyInfoOwned,
    extensions: Vec<Extension>,
    issuer_key: &P256SigningKey,
) -> Certificate {
    let t = now_secs();
    let algorithm = ecdsa_sha256_alg();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: algorithm.clone(),
        issuer: Name::from_str(issuer).expect("dn"),
        validity: Validity {
            not_before: utc_time(t - 3600),
            not_after: utc_time(t + 3600),
        },
        subject: Name::from_str(subject).expect("dn"),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: if extensions.is_empty() {
            None
        } else {
            Some(extensions)
        },
    };
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature: P256Signature = issuer_key.sign(&tbs_der);
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: algorithm,
        signature: BitString::new(0, signature.to_der().as_bytes().to_vec()).expect("bitstring"),
    }
}

fn uri_san_extension(identity: &str) -> Extension {
    let names: GeneralNames = vec![GeneralName::UniformResourceIdentifier(
        Ia5String::new(identity).expect("ia5"),
    )];
    Extension {
        extn_id: const_oid::ObjectIdentifier::new_unwrap("2.5.29.17"),
        critical: false,
        extn_value: OctetString::new(names.to_der().expect("san der")).expect("octets"),
    }
}

fn fixture() -> Fixture {
    let ca_key = P256SigningKey::from_slice(&[3u8; 32]).expect("ca key");
    let leaf_key = P384SigningKey::from_slice(&[5u8; 48]).expect("leaf key");
    let rekor_key = P256SigningKey::from_slice(&[9u8; 32]).expect("rekor key");

    let ca_spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).expect("ca spki");
    let root = signed_cert(
        1,
        "CN=sigil-test-root",
        "CN=sigil-test-root",
        ca_spki,
        vec![],
        &ca_key,
    );
    let leaf_spki =
        SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key()).expect("leaf spki");
    let leaf = signed_cert(
        2,
        "CN=sigil-test-leaf",
        "CN=sigil-test-root",
        leaf_spki,
        vec![uri_san_extension(IDENTITY)],
        &ca_key,
    );

    let rekor_spki_der = SubjectPublicKeyInfoOwned::from_key(*rekor_key.verifying_key())
        .expect("rekor spki")
        .to_der()
        .expect("rekor spki der");
    let rekor_log_id = hex::encode(Sha256::digest(&rekor_spki_der));

    Fixture {
        trust: TrustRoot {
            fulcio_root_der: root.to_der().expect("root der"),
            fulcio_intermediates_der: vec![],
            rekor_public_key: rekor_key
                .verifying_key()
                .to_encoded_point(false)
                .as_bytes()
                .to_vec(),
            rekor_log_id,
        },
        leaf_der: leaf.to_der().expect("leaf der"),
        leaf_key,
        rekor_key,
        integrated_time: now_secs(),
    }
}

fn hashedrekord_body(artifact_sha256_hex: &str, signature_b64: &str) -> String {
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

/// Sign `message` with the leaf key and wrap it in a bundle carrying the
/// leaf cert — the same shape `sign_with_sigstore` produces.
fn make_bundle(f: &Fixture, message: &[u8]) -> SigstoreBundle {
    let signature: p384::ecdsa::Signature = f.leaf_key.sign(message);
    build_bundle(message, &signature.to_bytes(), &f.leaf_der).expect("bundle")
}

/// Construct the Rekor entry Rekor would return for `bundle`: hashedrekord
/// body bound to the artifact hash and signature, a real SET over the
/// canonical entry JSON, and a single-leaf RFC 6962 inclusion proof.
fn make_entry(f: &Fixture, message: &[u8], bundle: &SigstoreBundle) -> RekorEntry {
    let artifact_hash = hex::encode(Sha256::digest(message));
    let body = hashedrekord_body(&artifact_hash, &bundle.message_signature.signature);
    let canonical = format!(
        r#"{{"body":"{}","integratedTime":{},"logID":"{}","logIndex":{}}}"#,
        body, f.integrated_time, f.trust.rekor_log_id, 0
    );
    let set: P256Signature = f.rekor_key.sign(canonical.as_bytes());
    let body_bytes = base64::engine::general_purpose::STANDARD
        .decode(&body)
        .expect("body decode");
    let mut leaf_hasher = Sha256::new();
    leaf_hasher.update([0x00]);
    leaf_hasher.update(&body_bytes);
    RekorEntry {
        body,
        integrated_time: f.integrated_time,
        log_id: f.trust.rekor_log_id.clone(),
        log_index: 0,
        signed_entry_timestamp: Some(
            base64::engine::general_purpose::STANDARD.encode(set.to_bytes()),
        ),
        inclusion_proof: Some(InclusionProof {
            log_index: 0,
            root_hash: hex::encode(leaf_hasher.finalize()),
            tree_size: 1,
            hashes: vec![],
        }),
    }
}

#[test]
fn verify_bundle_with_trust_full_chain_passes() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    assert_eq!(
        verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY),
        Ok(())
    );
}

#[test]
fn orchestrator_rejects_wrong_identity() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    let err = verify_bundle_with_trust(
        &bundle,
        message,
        &f.trust,
        &entry,
        "alice@example.com.evil.example",
    )
    .expect_err("wrong identity must fail at the SAN step");
    assert!(matches!(err, TrustError::SanMismatch { .. }));
}

#[test]
fn orchestrator_rejects_foreign_log_id() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let mut entry = make_entry(&f, message, &bundle);
    entry.log_id = "d".repeat(64);
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("foreign log id must fail");
    assert!(matches!(err, TrustError::LogIdMismatch { .. }));
}

#[test]
fn orchestrator_rejects_tampered_artifact() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let entry = make_entry(&f, message, &bundle);
    let err = verify_bundle_with_trust(&bundle, b"tampered", &f.trust, &entry, IDENTITY)
        .expect_err("tampered message must fail signature binding");
    assert!(matches!(err, TrustError::SignatureFailed(_)));
}

#[test]
fn orchestrator_rejects_missing_set() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let mut entry = make_entry(&f, message, &bundle);
    entry.signed_entry_timestamp = None;
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("missing SET must fail");
    assert!(matches!(err, TrustError::MissingSet));
}

#[test]
fn orchestrator_rejects_tampered_inclusion_root() {
    let f = fixture();
    let message = b"sigil test artifact";
    let bundle = make_bundle(&f, message);
    let mut entry = make_entry(&f, message, &bundle);
    if let Some(proof) = entry.inclusion_proof.as_mut() {
        proof.root_hash = "0".repeat(64);
    }
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("tampered proof must fail");
    assert!(matches!(err, TrustError::InclusionProofFailed(_)));
}
