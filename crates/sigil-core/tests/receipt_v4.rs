//! RIC-MM-001 WP5: receipt v4 binds the consumed media representation.
//!
//! CV-RIC-033: a v4 receipt with a consumed block signs and verifies, also
//! after a JSON round trip.
//! CV-RIC-034: receipts signed before v4 (by the binary at 52dbd81) still
//! verify, and so do the v4 receipts the binary signed. There is no v3
//! fixture: v3 belongs to the remediation line, which this repo lacks.
//! CV-RIC-035: changing, adding or removing any consumed field, or
//! relabelling the version, fails verification.

use std::sync::Arc;

use sigil_core::policy::Policy;
use sigil_core::receipt::{ReceiptVerifyError, verify_receipt};
use sigil_core::signing::{EcdsaP384Signer, SignatureVerifyError};
use sigil_core::types::{Provenance, RepresentationReceipt, TextSegment};
use sigil_core::{ConsumedParity, ConsumedView, RECEIPT_VERSION, Sigil, Vocab};

const FIXTURE_KEY: &str = include_str!("../../../tests/fixtures/receipts/signer.pub.hex");
const V2_KEY: &str = include_str!("../../../tests/fixtures/receipts/v2_signer.pub.hex");
const V2_TOKENIZE: &str = include_str!("../../../tests/fixtures/receipts/v2_tokenize.json");
const V4_TOKENIZE: &str = include_str!("../../../tests/fixtures/receipts/v4_tokenize.json");
const V4_PERCEIVE: &str = include_str!("../../../tests/fixtures/receipts/v4_perceive_qwen.json");

fn signer() -> Arc<EcdsaP384Signer> {
    Arc::new(EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar"))
}

fn view() -> ConsumedView {
    ConsumedView {
        profile: "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow".to_string(),
        profile_digest: "a1".repeat(48),
        digest: "b2".repeat(48),
        parity: ConsumedParity::ReferenceMatched,
        extractor: Some("c3".repeat(48)),
        placeholders: Some(529),
        placeholder_stream_digest: None,
        interpreter: None,
    }
}

fn signed_media_receipt() -> (RepresentationReceipt, String) {
    let signer = signer();
    let key = signer.verification_key_hex();
    let engine = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
        .expect("engine")
        .with_receipt_signer(signer);
    let output = engine
        .process_text_segments_bound(
            &[TextSegment {
                text: "Q3 revenue by region",
                provenance: Provenance::McpTool,
            }],
            Some(view()),
        )
        .expect("process");
    (output.receipt, key)
}

fn fixture(json: &str) -> RepresentationReceipt {
    serde_json::from_str(json).expect("fixture receipt")
}

#[test]
fn cv_ric_033_a_v4_receipt_binds_and_verifies_its_consumed_block() {
    let (receipt, key) = signed_media_receipt();
    assert_eq!(receipt.receipt_version, RECEIPT_VERSION);
    assert_eq!(receipt.consumed, Some(view()));
    assert!(verify_receipt(&receipt, &key).is_ok());

    let wire = serde_json::to_string(&receipt).expect("serialize");
    let back: RepresentationReceipt = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(back, receipt);
    assert!(verify_receipt(&back, &key).is_ok());
}

#[test]
fn cv_ric_034_a_receipt_signed_before_v4_still_verifies() {
    let receipt = fixture(V2_TOKENIZE);
    assert!(
        !V2_TOKENIZE.contains("receipt_version"),
        "made before the field"
    );
    assert_eq!(receipt.receipt_version, 2);
    assert_eq!(receipt.consumed, None);
    assert!(verify_receipt(&receipt, V2_KEY).is_ok());
}

#[test]
fn cv_ric_034_receipts_the_binary_signed_as_v4_verify() {
    for json in [V4_TOKENIZE, V4_PERCEIVE] {
        let receipt = fixture(json);
        assert_eq!(receipt.receipt_version, 4);
        assert!(verify_receipt(&receipt, FIXTURE_KEY).is_ok(), "{json}");
    }
    let media = fixture(V4_PERCEIVE).consumed.expect("consumed block");
    assert!(
        media.digest.starts_with("94c72b7a"),
        "the specimen's 644² view"
    );
    assert_eq!(media.placeholders, Some(529));
}

#[test]
fn cv_ric_034_relabelling_the_version_fails() {
    let mut v2_as_v4 = fixture(V2_TOKENIZE);
    v2_as_v4.receipt_version = 4;
    assert_mismatch(&v2_as_v4, V2_KEY);

    let mut v4_as_v2 = fixture(V4_TOKENIZE);
    v4_as_v2.receipt_version = 2;
    assert_mismatch(&v4_as_v2, FIXTURE_KEY);

    let mut v3 = fixture(V4_TOKENIZE);
    v3.receipt_version = 3;
    assert_eq!(
        verify_receipt(&v3, FIXTURE_KEY),
        Err(ReceiptVerifyError::UnsupportedVersion(3))
    );
}

#[test]
fn cv_ric_035_a_v2_label_cannot_carry_an_unsigned_consumed_block() {
    let mut downgraded = fixture(V4_PERCEIVE);
    downgraded.receipt_version = 2;
    assert_eq!(
        verify_receipt(&downgraded, FIXTURE_KEY),
        Err(ReceiptVerifyError::UnsignedConsumedBlock)
    );
}

type Tamper = (&'static str, fn(&mut ConsumedView));

fn assert_mismatch(receipt: &RepresentationReceipt, key: &str) {
    assert_eq!(
        verify_receipt(receipt, key),
        Err(ReceiptVerifyError::Signature(
            SignatureVerifyError::Mismatch
        ))
    );
}

#[test]
fn cv_ric_035_tampering_with_any_consumed_field_fails() {
    let (receipt, key) = signed_media_receipt();
    let tampers: Vec<Tamper> = vec![
        ("profile", |v| {
            v.profile = "thumbnail/nearest-80".to_string()
        }),
        ("profile_digest", |v| v.profile_digest = "a2".repeat(48)),
        ("digest", |v| v.digest = "b3".repeat(48)),
        ("parity", |v| v.parity = ConsumedParity::Approximate),
        ("extractor removed", |v| v.extractor = None),
        ("extractor changed", |v| v.extractor = Some("c4".repeat(48))),
        ("placeholders changed", |v| v.placeholders = Some(530)),
        ("placeholders removed", |v| v.placeholders = None),
        ("placeholder stream added", |v| {
            v.placeholder_stream_digest = Some("d5".repeat(48));
        }),
        ("interpreter added", |v| {
            v.interpreter = Some("e6".repeat(48))
        }),
        // A byte moved across a field boundary: the length prefixes see it.
        ("boundary shift", |v| {
            let moved = v.profile.pop().expect("non-empty");
            v.profile_digest.insert(0, moved);
        }),
    ];
    for (name, tamper) in tampers {
        let mut tampered = receipt.clone();
        tamper(tampered.consumed.as_mut().expect("consumed"));
        assert_ne!(tampered, receipt, "{name}: the tamper changed nothing");
        assert_mismatch(&tampered, &key);
    }
}

#[test]
fn cv_ric_035_removing_or_adding_the_consumed_block_fails() {
    let (receipt, key) = signed_media_receipt();
    let mut stripped = receipt.clone();
    stripped.consumed = None;
    assert_mismatch(&stripped, &key);

    let mut text = fixture(V4_TOKENIZE);
    text.consumed = Some(view());
    assert_mismatch(&text, FIXTURE_KEY);
}

#[test]
fn cv_ric_035_changing_the_bound_interpreter_or_stream_fails() {
    let receipt = fixture(V4_PERCEIVE);
    let mut other_interpreter = receipt.clone();
    other_interpreter
        .consumed
        .as_mut()
        .expect("consumed")
        .interpreter = Some("f7".repeat(48));
    assert_mismatch(&other_interpreter, FIXTURE_KEY);
    let mut no_stream = receipt;
    no_stream
        .consumed
        .as_mut()
        .expect("consumed")
        .placeholder_stream_digest = None;
    assert_mismatch(&no_stream, FIXTURE_KEY);
}

#[test]
fn an_unsigned_receipt_does_not_verify() {
    let mut receipt = fixture(V4_TOKENIZE);
    receipt.signature = None;
    assert_eq!(
        verify_receipt(&receipt, FIXTURE_KEY),
        Err(ReceiptVerifyError::Unsigned)
    );
}
