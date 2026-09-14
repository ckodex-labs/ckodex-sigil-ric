use crate::trust::types::{InclusionProof, RekorEntry, TrustError, TrustRoot};
use crate::trust::verify::verify_bundle_with_trust;
use crate::{build_bundle, SigstoreBundle};
use base64::Engine as _;
use der::asn1::{BitString, Ia5String, OctetString, UtcTime};
use der::{Decode as _, Encode as _};
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

pub(crate) const IDENTITY: &str =
    "https://github.com/org/repo/.github/workflows/release.yml@refs/heads/main";

/// Synthetic but cryptographically valid trust material: a self-signed P-256
/// CA root, a P-384 leaf signed by it (DER ECDSA-Sig-Value, as real Fulcio
/// certs carry), and a P-256 Rekor key. `rekor_log_id` is derived the way
/// Sigstore derives it: SHA-256 of the Rekor public key's SPKI DER.
pub(crate) struct Fixture {
    pub(crate) trust: TrustRoot,
    leaf_der: Vec<u8>,
    pub(crate) leaf_key: P384SigningKey,
    rekor_key: P256SigningKey,
    pub(crate) integrated_time: i64,
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

/// Sign a TBS with a P-256 issuer key. The signature is stored
/// DER-encoded — the X.509 ECDSA-Sig-Value encoding — which also
/// exercises `verify_cert_signature`'s DER parse path.
fn sign_tbs(tbs: TbsCertificate, issuer_key: &P256SigningKey) -> Certificate {
    let tbs_der = tbs.to_der().expect("tbs der");
    let signature: P256Signature = issuer_key.sign(&tbs_der);
    Certificate {
        tbs_certificate: tbs,
        signature_algorithm: ecdsa_sha256_alg(),
        signature: BitString::new(0, signature.to_der().as_bytes().to_vec()).expect("bitstring"),
    }
}

/// Build a TBS cert and sign it with a P-256 issuer key.
fn signed_cert(
    serial: u8,
    subject: &str,
    issuer: &str,
    spki: SubjectPublicKeyInfoOwned,
    extensions: Vec<Extension>,
    issuer_key: &P256SigningKey,
) -> Certificate {
    let t = now_secs();
    let tbs = TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[serial]).expect("serial"),
        signature: ecdsa_sha256_alg(),
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
    sign_tbs(tbs, issuer_key)
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

/// OID 1.3.6.1.4.1.11129.2.4.2 — embedded SCT list extension.
const SCT_EXT_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

/// The test leaf's TBS (serial 2, SAN identity only — the SCT extension
/// is layered on by `build_leaf`).
fn leaf_tbs(spki: SubjectPublicKeyInfoOwned, extensions: Vec<Extension>) -> TbsCertificate {
    let t = now_secs();
    TbsCertificate {
        version: Version::V3,
        serial_number: SerialNumber::new(&[2]).expect("serial"),
        signature: ecdsa_sha256_alg(),
        issuer: Name::from_str("CN=sigil-test-root").expect("dn"),
        validity: Validity {
            not_before: utc_time(t - 3600),
            not_after: utc_time(t + 3600),
        },
        subject: Name::from_str("CN=sigil-test-leaf").expect("dn"),
        subject_public_key_info: spki,
        issuer_unique_id: None,
        subject_unique_id: None,
        extensions: if extensions.is_empty() {
            None
        } else {
            Some(extensions)
        },
    }
}

/// Build a real RFC 6962 v1 SCT extension: sign the precertificate
/// signature input with `sct_signer`, claiming `log_id`. Callers can
/// forge either half — an untrusted `log_id` or a `sct_signer` whose key
/// is not the one the log_id belongs to.
fn sct_extension(
    sct_signer: &P256SigningKey,
    log_id: [u8; 32],
    issuer_spki_der: &[u8],
    precert_tbs_der: &[u8],
) -> Extension {
    let ts_ms = (now_secs() as u64) * 1000;
    // RFC 6962 §3.5 precertificate signature input.
    let mut input = vec![0u8, 0u8];
    input.extend_from_slice(&ts_ms.to_be_bytes());
    input.extend_from_slice(&[0x04, 0x01]);
    input.extend_from_slice(&Sha256::digest(issuer_spki_der));
    input.extend_from_slice(precert_tbs_der);
    input.extend_from_slice(&0u16.to_be_bytes()); // empty extensions
    let sig: P256Signature = sct_signer.sign(&input);
    let sig_der = sig.to_der().as_bytes().to_vec();
    // SCT body: version || log_id || timestamp || ext_len || exts ||
    //           DigitallySigned{hash_alg, sig_alg, sig_len, sig}
    let mut sct = vec![0u8];
    sct.extend_from_slice(&log_id);
    sct.extend_from_slice(&ts_ms.to_be_bytes());
    sct.extend_from_slice(&0u16.to_be_bytes());
    sct.push(4u8); // HashAlgorithm::sha256
    sct.push(3u8); // SignatureAlgorithm::ecdsa
    sct.extend_from_slice(&(sig_der.len() as u16).to_be_bytes());
    sct.extend_from_slice(&sig_der);
    // SerializedSCTList framing.
    let mut list = Vec::new();
    list.extend_from_slice(&((sct.len() + 2) as u16).to_be_bytes());
    list.extend_from_slice(&(sct.len() as u16).to_be_bytes());
    list.extend_from_slice(&sct);
    // The extension value is a DER OCTET STRING wrapping the list.
    let inner = OctetString::new(list)
        .expect("sct list octets")
        .to_der()
        .expect("sct list der");
    Extension {
        extn_id: SCT_EXT_OID,
        critical: false,
        extn_value: OctetString::new(inner).expect("extn octets"),
    }
}

/// Build the leaf certificate. `sct_for_precert`, when given, receives the
/// precertificate TBS DER (final TBS minus the SCT extension) and returns
/// the SCT extension to embed — mirroring Fulcio's precertificate flow.
fn build_leaf(
    ca_key: &P256SigningKey,
    leaf_spki: SubjectPublicKeyInfoOwned,
    sct_for_precert: Option<impl FnOnce(&[u8]) -> Extension>,
) -> Certificate {
    let base = leaf_tbs(leaf_spki, vec![uri_san_extension(IDENTITY)]);
    let mut tbs = base.clone();
    if let Some(make_sct) = sct_for_precert {
        let precert_der = base.to_der().expect("precert der");
        let sct = make_sct(&precert_der);
        tbs.extensions = Some(vec![uri_san_extension(IDENTITY), sct]);
    }
    sign_tbs(tbs, ca_key)
}

fn ct_log_id(ct_key: &P256SigningKey) -> ([u8; 32], Vec<u8>) {
    let spki_der = SubjectPublicKeyInfoOwned::from_key(*ct_key.verifying_key())
        .expect("ct spki")
        .to_der()
        .expect("ct spki der");
    (Sha256::digest(&spki_der).into(), spki_der)
}

pub(crate) fn fixture() -> Fixture {
    let ca_key = P256SigningKey::from_slice(&[3u8; 32]).expect("ca key");
    let ct_key = P256SigningKey::from_slice(&[7u8; 32]).expect("ct key");
    let leaf_key = P384SigningKey::from_slice(&[5u8; 48]).expect("leaf key");
    let rekor_key = P256SigningKey::from_slice(&[9u8; 32]).expect("rekor key");

    let ca_spki = SubjectPublicKeyInfoOwned::from_key(*ca_key.verifying_key()).expect("ca spki");
    let ca_spki_der = ca_spki.to_der().expect("ca spki der");
    let root = signed_cert(
        1,
        "CN=sigil-test-root",
        "CN=sigil-test-root",
        ca_spki,
        vec![],
        &ca_key,
    );
    let (log_id, ct_spki_der) = ct_log_id(&ct_key);
    let leaf_spki =
        SubjectPublicKeyInfoOwned::from_key(*leaf_key.verifying_key()).expect("leaf spki");
    let leaf = build_leaf(
        &ca_key,
        leaf_spki,
        Some(|precert_der: &[u8]| sct_extension(&ct_key, log_id, &ca_spki_der, precert_der)),
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
            ctfe_keys: vec![(log_id.to_vec(), ct_spki_der)],
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
pub(crate) fn make_bundle(f: &Fixture, message: &[u8]) -> SigstoreBundle {
    let signature: p384::ecdsa::Signature = f.leaf_key.sign(message);
    build_bundle(message, &signature.to_bytes(), &f.leaf_der).expect("bundle")
}

/// Construct the Rekor entry Rekor would return for `bundle`: hashedrekord
/// body bound to the artifact hash and signature, a real SET over the
/// canonical entry JSON, and a single-leaf RFC 6962 inclusion proof.
pub(crate) fn make_entry(f: &Fixture, message: &[u8], bundle: &SigstoreBundle) -> RekorEntry {
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

/// Rebuild a leaf cert with a caller-controlled SCT extension (or none)
/// and a fresh bundle+entry pair for it. Lets negative tests forge the
/// SCT without duplicating the fixture.
fn leaf_variant_fixture(
    f: &Fixture,
    sct: Option<Extension>,
    message: &[u8],
) -> (SigstoreBundle, RekorEntry) {
    let ca_key = P256SigningKey::from_slice(&[3u8; 32]).expect("ca key");
    let leaf_spki =
        SubjectPublicKeyInfoOwned::from_key(*f.leaf_key.verifying_key()).expect("leaf spki");
    let leaf = build_leaf(&ca_key, leaf_spki, sct.map(|ext| move |_: &[u8]| ext));
    let leaf_der = leaf.to_der().expect("leaf der");
    let signature: p384::ecdsa::Signature = f.leaf_key.sign(message);
    let bundle = build_bundle(message, &signature.to_bytes(), &leaf_der).expect("bundle");
    let entry = make_entry(f, message, &bundle);
    (bundle, entry)
}

#[test]
fn orchestrator_rejects_leaf_without_sct() {
    let f = fixture();
    let message = b"sigil test artifact";
    // The trust root provisions CT keys, so a leaf with no SCT extension
    // was never CT-logged — reject.
    let (bundle, entry) = leaf_variant_fixture(&f, None, message);
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("leaf without SCT must fail");
    assert!(matches!(err, TrustError::MissingSct));
}

#[test]
fn orchestrator_rejects_sct_signed_by_rogue_key() {
    let f = fixture();
    let message = b"sigil test artifact";
    // SCT claims the trusted CT log_id but is signed by a rogue key.
    let rogue = P256SigningKey::from_slice(&[11u8; 32]).expect("rogue key");
    let trusted_log_id: [u8; 32] = f.trust.ctfe_keys[0].0.clone().try_into().expect("32 bytes");
    let ca_spki_der = {
        let root = Certificate::from_der(&f.trust.fulcio_root_der).expect("root");
        root.tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki der")
    };
    // Rebuild with the forged SCT.
    let ca_key = P256SigningKey::from_slice(&[3u8; 32]).expect("ca key");
    let leaf_spki =
        SubjectPublicKeyInfoOwned::from_key(*f.leaf_key.verifying_key()).expect("leaf spki");
    let leaf = build_leaf(
        &ca_key,
        leaf_spki,
        Some(|precert: &[u8]| sct_extension(&rogue, trusted_log_id, &ca_spki_der, precert)),
    );
    let leaf_der = leaf.to_der().expect("leaf der");
    let signature: p384::ecdsa::Signature = f.leaf_key.sign(message);
    let bundle = build_bundle(message, &signature.to_bytes(), &leaf_der).expect("bundle");
    let entry = make_entry(&f, message, &bundle);
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("SCT signed by a non-log key must fail");
    assert!(matches!(err, TrustError::SctFailed(_)));
}

#[test]
fn orchestrator_rejects_sct_from_untrusted_ct_log() {
    let f = fixture();
    let message = b"sigil test artifact";
    // SCT is well-formed but the claimed log_id is not in the trust root.
    let rogue = P256SigningKey::from_slice(&[13u8; 32]).expect("rogue key");
    let (rogue_log_id, _) = ct_log_id(&rogue);
    let ca_key = P256SigningKey::from_slice(&[3u8; 32]).expect("ca key");
    let ca_spki_der = {
        let root = Certificate::from_der(&f.trust.fulcio_root_der).expect("root");
        root.tbs_certificate
            .subject_public_key_info
            .to_der()
            .expect("spki der")
    };
    let leaf_spki =
        SubjectPublicKeyInfoOwned::from_key(*f.leaf_key.verifying_key()).expect("leaf spki");
    let leaf = build_leaf(
        &ca_key,
        leaf_spki,
        Some(|precert: &[u8]| sct_extension(&rogue, rogue_log_id, &ca_spki_der, precert)),
    );
    let leaf_der = leaf.to_der().expect("leaf der");
    let signature: p384::ecdsa::Signature = f.leaf_key.sign(message);
    let bundle = build_bundle(message, &signature.to_bytes(), &leaf_der).expect("bundle");
    let entry = make_entry(&f, message, &bundle);
    let err = verify_bundle_with_trust(&bundle, message, &f.trust, &entry, IDENTITY)
        .expect_err("SCT from an untrusted CT log must fail");
    assert!(matches!(err, TrustError::SctFailed(_)));
}
