//! DEV-5 closed: a receipt that binds a consumed media representation is
//! attested under the v4 predicate, which carries the consumed block, and a
//! receipt without one keeps the v2 statement byte for byte.

use base64::Engine as _;
use sigil_core::attestation::{
    PREDICATE_TYPE, PREDICATE_TYPE_V4, attest_receipt, attest_representation, verify_attestation,
};
use sigil_core::signing::{EcdsaP384Signer, SignatureVerifyError};
use sigil_core::types::RepresentationReceipt;

const V4_PERCEIVE: &str = include_str!("../../../tests/fixtures/receipts/v4_perceive_qwen.json");
const V4_TOKENIZE: &str = include_str!("../../../tests/fixtures/receipts/v4_tokenize.json");

fn signer() -> EcdsaP384Signer {
    EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar")
}

fn receipt(json: &str) -> RepresentationReceipt {
    serde_json::from_str(json).expect("fixture")
}

fn statement(envelope: &sigil_core::DsseEnvelope) -> serde_json::Value {
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .expect("base64");
    serde_json::from_slice(&payload).expect("statement")
}

#[test]
fn a_media_receipt_is_attested_with_its_consumed_block() {
    let signer = signer();
    let media = receipt(V4_PERCEIVE);
    let envelope = attest_representation(&media, &signer).expect("attest");
    assert_eq!(
        verify_attestation(&envelope, &signer.verification_key_hex()),
        Ok(())
    );

    let statement = statement(&envelope);
    assert_eq!(statement["predicateType"], PREDICATE_TYPE_V4);
    assert_eq!(statement["predicate"]["receipt_version"], 4);
    let consumed = media.consumed.as_ref().expect("consumed");
    assert_eq!(
        statement["predicate"]["consumed"],
        serde_json::to_value(consumed).expect("consumed json")
    );
    // The consumed pixels are an in-toto subject next to the admission.
    assert_eq!(statement["subject"][1]["name"], "sigil:consumed");
    assert_eq!(
        statement["subject"][1]["digest"]["sha384"],
        consumed.digest.as_str()
    );
}

#[test]
fn changing_the_attested_consumed_block_fails() {
    let signer = signer();
    let mut envelope = attest_representation(&receipt(V4_PERCEIVE), &signer).expect("attest");
    let mut tampered = statement(&envelope);
    tampered["predicate"]["consumed"]["digest"] = serde_json::json!("06801a38".repeat(12));
    envelope.payload = base64::engine::general_purpose::STANDARD
        .encode(serde_json::to_vec(&tampered).expect("reserialize"));
    assert_eq!(
        verify_attestation(&envelope, &signer.verification_key_hex()),
        Err(SignatureVerifyError::Mismatch)
    );
}

#[test]
fn a_receipt_without_consumed_keeps_the_v2_statement() {
    let signer = signer();
    let text = receipt(V4_TOKENIZE);
    let new = attest_representation(&text, &signer).expect("attest");
    let old = attest_receipt(
        &text.raw_digest,
        &text.canonical_digest,
        &text.digest_algorithm,
        &text.normalization,
        &text.vocab,
        text.token_count,
        &signer,
    )
    .expect("attest");
    assert_eq!(
        new, old,
        "same payload and, with RFC 6979, the same signature"
    );
    assert_eq!(statement(&new)["predicateType"], PREDICATE_TYPE);
}
