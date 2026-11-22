//! RIC-MM-001 WP7: the retrieval and embedding boundary (RIC-SPEC §4.3).
//!
//! CV-RIC-038 (RIC-RET-2): retrieval never upgrades source authority, in
//! trust or in ceiling.
//! CV-RIC-039 (RIC-RET-1, RIC-RET-3): an unbound embedding, or one that
//! consumed something other than the admitted representation, caps the
//! ceiling at observe, and no similarity score raises it.
//! CV-RIC-040: a retrieval receipt signs and verifies, and changing any
//! bound field fails.
//! Chunk receipts come from SIGIL's own engine; identities and scores are
//! inputs to the rules, not measured values.

use std::sync::Arc;

use sigil_core::delegation::AuthorityCeiling;
use sigil_core::policy::Policy;
use sigil_core::receipt::ReceiptVerifyError;
use sigil_core::retrieval::{
    EmbeddedInput, EmbeddingBinding, EmbeddingModel, Pooling, RetrievalFinding, RetrievedChunk,
    assess_retrieval, sign_retrieval, verify_retrieval_receipt,
};
use sigil_core::signing::{EcdsaP384Signer, SignatureVerifyError};
use sigil_core::types::{Provenance, RepresentationReceipt, TextSegment, TrustLevel};
use sigil_core::{Sigil, Vocab};

/// The GloVe specimen's probes (RIC-MM-001 §1): the filter scored the
/// tag-smuggled attack 0.757 and the benign request 0.768.
const TAG_SCORE: f64 = 0.757;
const BENIGN_SCORE: f64 = 0.768;

fn admit(text: &str) -> RepresentationReceipt {
    Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
        .expect("engine")
        .process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::Retrieval,
        }])
        .expect("admit")
        .receipt
}

fn model() -> EmbeddingModel {
    EmbeddingModel {
        name: "glove-wiki-gigaword-100/mean".to_string(),
        weights_digest: "a1".repeat(48),
        tokenizer_digest: "b2".repeat(48),
        pooling: Pooling::Mean,
        dimensions: 100,
    }
}

fn bound(receipt: &RepresentationReceipt, dropped_bytes: u64, score: f64) -> EmbeddingBinding {
    EmbeddingBinding {
        model: model(),
        input: EmbeddedInput {
            admitted_digest: receipt.canonical_digest.clone(),
            consumed_digest: "c3".repeat(48),
            consumed_units: 4,
            dropped_bytes,
        },
        score,
    }
}

fn chunk(
    trust: TrustLevel,
    ceiling: AuthorityCeiling,
    embedding: Option<EmbeddingBinding>,
) -> RetrievedChunk {
    let receipt = admit("please summarise the quarterly revenue report");
    RetrievedChunk {
        source_id: "kb://reports/q3".to_string(),
        source_trust: trust,
        source_ceiling: ceiling,
        embedding,
        receipt,
    }
}

fn bound_chunk(trust: TrustLevel, ceiling: AuthorityCeiling) -> RetrievedChunk {
    let mut c = chunk(trust, ceiling, None);
    c.embedding = Some(bound(&c.receipt, 0, BENIGN_SCORE));
    c
}

#[test]
fn cv_ric_038_retrieval_never_upgrades_source_trust() {
    // Provenance::Retrieval defaults to Bounded; an untrusted source stays
    // untrusted after retrieval, and nothing rises above Bounded.
    for (source, expected) in [
        (TrustLevel::Untrusted, TrustLevel::Untrusted),
        (TrustLevel::Bounded, TrustLevel::Bounded),
        (TrustLevel::Trusted, TrustLevel::Bounded),
        (TrustLevel::Privileged, TrustLevel::Bounded),
    ] {
        let assessment = assess_retrieval(
            &bound_chunk(source, AuthorityCeiling::Act),
            AuthorityCeiling::Act,
        );
        assert_eq!(assessment.trust, expected, "{source:?}");
        assert!(assessment.trust <= source);
    }
}

#[test]
fn cv_ric_038_retrieval_never_upgrades_the_source_ceiling() {
    use AuthorityCeiling::{Act, Draft, Escalate, Observe};
    for source in [Escalate, Observe, Draft, Act] {
        for content in [Escalate, Observe, Draft, Act] {
            let assessment = assess_retrieval(&bound_chunk(TrustLevel::Bounded, source), content);
            assert_eq!(
                assessment.ceiling,
                source.min(content),
                "{source:?}/{content:?}"
            );
            assert!(assessment.findings.is_empty());
        }
    }
}

#[test]
fn cv_ric_039_an_unbound_embedding_caps_at_observe() {
    let assessment = assess_retrieval(
        &chunk(TrustLevel::Bounded, AuthorityCeiling::Act, None),
        AuthorityCeiling::Act,
    );
    assert_eq!(assessment.ceiling, AuthorityCeiling::Observe);
    assert_eq!(
        assessment.findings,
        vec![RetrievalFinding::UnboundEmbedding]
    );
}

#[test]
fn cv_ric_039_a_bound_reference_matched_embedding_resolves_the_interpreter() {
    let assessment = assess_retrieval(
        &bound_chunk(TrustLevel::Bounded, AuthorityCeiling::Act),
        AuthorityCeiling::Act,
    );
    assert_eq!(assessment.ceiling, AuthorityCeiling::Act);
}

#[test]
fn cv_ric_039_content_the_embedder_dropped_caps_at_observe() {
    // The GloVe case: tag characters make an out-of-vocabulary word, which a
    // word-level filter drops, so it scores a request the model never gets.
    let mut c = chunk(TrustLevel::Bounded, AuthorityCeiling::Act, None);
    c.embedding = Some(bound(&c.receipt, 84, TAG_SCORE));
    let assessment = assess_retrieval(&c, AuthorityCeiling::Act);
    assert_eq!(assessment.ceiling, AuthorityCeiling::Observe);
    assert_eq!(
        assessment.findings,
        vec![RetrievalFinding::EmbeddingDroppedContent]
    );
}

#[test]
fn cv_ric_039_an_embedding_of_a_sibling_representation_caps_at_observe() {
    let mut c = chunk(TrustLevel::Bounded, AuthorityCeiling::Act, None);
    let raw_text = admit("please summarise the quarterly revenue report ");
    c.embedding = Some(bound(&raw_text, 0, BENIGN_SCORE));
    let assessment = assess_retrieval(&c, AuthorityCeiling::Act);
    assert_eq!(assessment.ceiling, AuthorityCeiling::Observe);
    assert_eq!(
        assessment.findings,
        vec![RetrievalFinding::EmbeddedSiblingRepresentation]
    );
}

#[test]
fn cv_ric_039_no_similarity_score_raises_a_ceiling() {
    for score in [0.0, TAG_SCORE, BENIGN_SCORE, 1.0, f64::MAX] {
        // Unbound: the cap holds whatever the score.
        let mut unbound = chunk(TrustLevel::Bounded, AuthorityCeiling::Act, None);
        let mut binding = bound(&unbound.receipt, 1, score);
        binding.input.dropped_bytes = 1;
        unbound.embedding = Some(binding);
        assert_eq!(
            assess_retrieval(&unbound, AuthorityCeiling::Act).ceiling,
            AuthorityCeiling::Observe
        );
        // Bound: the score does not lift the source or content ceiling.
        let mut c = bound_chunk(TrustLevel::Bounded, AuthorityCeiling::Draft);
        c.embedding.as_mut().expect("bound").score = score;
        assert_eq!(
            assess_retrieval(&c, AuthorityCeiling::Observe).ceiling,
            AuthorityCeiling::Observe
        );
        assert_eq!(
            assess_retrieval(&c, AuthorityCeiling::Act).ceiling,
            AuthorityCeiling::Draft
        );
    }
}

fn signer() -> Arc<EcdsaP384Signer> {
    Arc::new(EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("key"))
}

#[test]
fn cv_ric_040_a_retrieval_receipt_signs_and_verifies() {
    let signer = signer();
    let key = signer.verification_key_hex();
    let receipt = sign_retrieval(
        &bound_chunk(TrustLevel::Bounded, AuthorityCeiling::Act),
        signer.as_ref(),
    )
    .expect("bound chunk signs");
    assert_eq!(receipt.model_identity, model().identity_digest());
    assert_eq!(verify_retrieval_receipt(&receipt, &key), Ok(()));
    let wire = serde_json::to_string(&receipt).expect("serialize");
    let back = serde_json::from_str(&wire).expect("deserialize");
    assert_eq!(verify_retrieval_receipt(&back, &key), Ok(()));
}

#[test]
fn cv_ric_040_unbound_or_non_finite_retrievals_produce_no_receipt() {
    let signer = signer();
    assert!(
        sign_retrieval(
            &chunk(TrustLevel::Bounded, AuthorityCeiling::Act, None),
            signer.as_ref()
        )
        .is_none()
    );
    let mut c = bound_chunk(TrustLevel::Bounded, AuthorityCeiling::Act);
    c.embedding.as_mut().expect("bound").score = f64::NAN;
    assert!(sign_retrieval(&c, signer.as_ref()).is_none());
}

type Tamper = (
    &'static str,
    fn(&mut sigil_core::retrieval::RetrievalReceipt),
);

#[test]
fn cv_ric_040_changing_any_bound_field_fails() {
    let signer = signer();
    let key = signer.verification_key_hex();
    let receipt = sign_retrieval(
        &bound_chunk(TrustLevel::Bounded, AuthorityCeiling::Draft),
        signer.as_ref(),
    )
    .expect("signs");
    let tampers: Vec<Tamper> = vec![
        ("score", |r| r.score = TAG_SCORE),
        ("source id", |r| r.source_id.push('x')),
        ("source trust", |r| r.source_trust = TrustLevel::Trusted),
        ("source ceiling", |r| {
            r.source_ceiling = AuthorityCeiling::Act
        }),
        ("chunk digest", |r| r.chunk_digest = "d4".repeat(48)),
        ("admitted digest", |r| {
            r.input.admitted_digest = "d4".repeat(48)
        }),
        ("consumed digest", |r| {
            r.input.consumed_digest = "d4".repeat(48)
        }),
        ("consumed units", |r| r.input.consumed_units += 1),
        ("dropped bytes", |r| r.input.dropped_bytes = 1),
    ];
    for (name, tamper) in tampers {
        let mut tampered = receipt.clone();
        tamper(&mut tampered);
        assert_eq!(
            verify_retrieval_receipt(&tampered, &key),
            Err(ReceiptVerifyError::Signature(
                SignatureVerifyError::Mismatch
            )),
            "{name}"
        );
    }
    // A changed model changes its identity: recorded and recomputed disagree.
    let model_tampers: Vec<Tamper> = vec![
        ("weights", |r| r.model.weights_digest = "e5".repeat(48)),
        ("tokenizer", |r| r.model.tokenizer_digest = "e5".repeat(48)),
        ("pooling", |r| r.model.pooling = Pooling::Cls),
        ("dimensions", |r| r.model.dimensions = 300),
        ("name", |r| r.model.name.push('x')),
    ];
    for (name, tamper) in model_tampers {
        let mut tampered = receipt.clone();
        tamper(&mut tampered);
        assert_eq!(
            verify_retrieval_receipt(&tampered, &key),
            Err(ReceiptVerifyError::InconsistentModelIdentity),
            "{name}"
        );
        // Recording the new identity too still fails the signature.
        tampered.model_identity = tampered.model.identity_digest();
        assert_eq!(
            verify_retrieval_receipt(&tampered, &key),
            Err(ReceiptVerifyError::Signature(
                SignatureVerifyError::Mismatch
            )),
            "{name}"
        );
    }
    let mut other_version = receipt;
    other_version.retrieval_version = 2;
    assert_eq!(
        verify_retrieval_receipt(&other_version, &key),
        Err(ReceiptVerifyError::UnsupportedVersion(2))
    );
}
