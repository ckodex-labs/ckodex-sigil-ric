use crate::bundle_ops::*;
use crate::bundle_types::*;
use p384::ecdsa::{signature::Signer as _, Signature, SigningKey};
use p384::elliptic_curve::generic_array::GenericArray;
use sigil_core::signing::SignatureVerifyError;
use x509_cert::spki::AlgorithmIdentifierOwned;

#[test]
fn bundle_roundtrip_verifies_offline() {
    // Simulate the keyless shape: sign with a P-384 key and package the
    // "Fulcio certificate" — here a self-made certificate carrying the
    // same public key, built with the same x509-cert stack Fulcio uses.
    let signing_key =
        SigningKey::from_bytes(GenericArray::from_slice(&[9u8; 48])).expect("valid scalar");
    let message = b"bundle verification probe";

    let certificate_der = self_signed_certificate(&signing_key);
    let signature: Signature = signing_key.sign(message);

    let bundle = build_bundle(message, &signature.to_bytes(), &certificate_der).expect("bundle");
    assert_eq!(bundle.media_type, BUNDLE_MEDIA_TYPE);
    assert_eq!(
        bundle.message_signature.message_digest.algorithm,
        "SHA2_384"
    );

    // Offline verification: leaf-cert public key must verify the message.
    assert_eq!(verify_bundle(&bundle, message), Ok(()));

    // Tampered message must fail.
    assert_eq!(
        verify_bundle(&bundle, b"tampered message"),
        Err(SignatureVerifyError::Mismatch)
    );
}

#[test]
fn bundle_rejects_wrong_media_type() {
    let signing_key =
        SigningKey::from_bytes(GenericArray::from_slice(&[9u8; 48])).expect("valid scalar");
    let certificate_der = self_signed_certificate(&signing_key);
    let signature: Signature = signing_key.sign(b"probe");
    let mut bundle =
        build_bundle(b"probe", &signature.to_bytes(), &certificate_der).expect("bundle");
    bundle.media_type = "application/json".to_string();
    assert!(matches!(
        verify_bundle(&bundle, b"probe"),
        Err(SignatureVerifyError::UnsupportedAlgorithm(_))
    ));
}

/// Build a minimal self-signed X.509 certificate carrying the signing
/// key's public key — stands in for the Fulcio-issued leaf in offline
/// tests (the real leaf comes from the Fulcio exchange). Constructed
/// directly from the x509-cert 0.2 DER types (no builder module there).
fn self_signed_certificate(signing_key: &SigningKey) -> Vec<u8> {
    use der::asn1::{BitString, UtcTime};
    use der::Encode;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};
    use x509_cert::certificate::{Certificate, TbsCertificate};
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Time;
    use x509_cert::time::Validity;

    let public_key = p384::PublicKey::from(signing_key.verifying_key());
    let spki = SubjectPublicKeyInfoOwned::from_key(public_key).expect("spki");
    let algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
        parameters: None,
    };
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock");
    let not_before =
        UtcTime::from_unix_duration(Duration::from_secs(now.as_secs() - 60)).expect("time");
    let not_after =
        UtcTime::from_unix_duration(Duration::from_secs(now.as_secs() + 3600)).expect("time");
    let signature: Signature = signing_key.sign(b"self-signature");

    let certificate = Certificate {
        tbs_certificate: TbsCertificate {
            version: x509_cert::certificate::Version::V3,
            serial_number: SerialNumber::new(&[1]).expect("serial"),
            signature: algorithm.clone(),
            issuer: Name::default(),
            validity: Validity {
                not_before: Time::UtcTime(not_before),
                not_after: Time::UtcTime(not_after),
            },
            subject: Name::default(),
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        },
        signature_algorithm: algorithm,
        signature: BitString::new(0, signature.to_bytes().to_vec()).expect("bitstring"),
    };
    certificate.to_der().expect("der")
}
