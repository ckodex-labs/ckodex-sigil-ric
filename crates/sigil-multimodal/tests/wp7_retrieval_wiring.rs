//! RIC-MM-001 WP7 kernel wiring: the multimodal engine applies the
//! retrieval boundary (RIC-SPEC §4.3) to every retrieval-provenance input.
//!
//! CV-RIC-039: a retrieved chunk without an in-process assessment, or with
//! one made for other text, is capped at observe; the wire cannot assert it.
//! CV-RIC-038: a bound chunk keeps no more than its source's ceiling, and its
//! source's trust is what fusion sees.

use sigil_core::delegation::AuthorityCeiling;
use sigil_core::policy::Policy;
use sigil_core::retrieval::{
    EmbeddedInput, EmbeddingBinding, EmbeddingModel, Pooling, RetrievedChunk,
};
use sigil_core::types::{Provenance, TextSegment, TrustLevel};
use sigil_core::{Sigil, Vocab};
use sigil_multimodal::{FusionRiskKind, ModalInput, MultimodalAssessment, MultimodalEngine};

const CHUNK: &str = "Q3 revenue grew 12% in the northern region.";

fn analyze(inputs: &[ModalInput]) -> MultimodalAssessment {
    MultimodalEngine::new(Policy::default(), Vocab::tiktoken("cl100k_base"))
        .expect("engine")
        .analyze(inputs)
        .expect("analysis")
}

/// A chunk bound for `text`, admitted by SIGIL's engine as the multimodal
/// engine admits it.
fn bound_chunk(text: &str, trust: TrustLevel, ceiling: AuthorityCeiling) -> RetrievedChunk {
    let receipt = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
        .expect("engine")
        .process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::Retrieval,
        }])
        .expect("admit")
        .receipt;
    RetrievedChunk {
        source_id: "kb://reports/q3".to_string(),
        source_trust: trust,
        source_ceiling: ceiling,
        embedding: Some(EmbeddingBinding {
            model: EmbeddingModel {
                name: "bge-small".to_string(),
                weights_digest: "a1".repeat(48),
                tokenizer_digest: "b2".repeat(48),
                pooling: Pooling::Cls,
                dimensions: 384,
            },
            input: EmbeddedInput::from_token_ids(&receipt.canonical_digest, &[1, 2, 3]),
            score: 0.91,
        }),
        receipt,
    }
}

#[test]
fn cv_ric_039_a_retrieved_input_off_the_wire_is_capped() {
    let wire = r#"{"modality":"text","content":"Q3 revenue grew 12% in the northern region.",
        "provenance":"retrieval","retrieval":{"chunk_digest":"x"}}"#;
    let input: ModalInput = serde_json::from_str(wire).expect("deserialize");
    assert!(input.retrieval.is_none(), "never read from the wire");
    assert_eq!(
        analyze(&[input]).authority_ceiling,
        AuthorityCeiling::Observe
    );
}

#[test]
fn cv_ric_039_a_bound_chunk_keeps_its_ceiling() {
    let chunk = bound_chunk(CHUNK, TrustLevel::Bounded, AuthorityCeiling::Act);
    let input = ModalInput::retrieved(CHUNK.to_string(), &chunk);
    assert_eq!(analyze(&[input]).authority_ceiling, AuthorityCeiling::Act);
}

#[test]
fn cv_ric_039_an_assessment_for_other_text_is_capped() {
    let chunk = bound_chunk(CHUNK, TrustLevel::Bounded, AuthorityCeiling::Act);
    let swapped = ModalInput::retrieved(
        "Q3 revenue fell 12% in the northern region.".to_string(),
        &chunk,
    );
    assert_eq!(
        analyze(&[swapped]).authority_ceiling,
        AuthorityCeiling::Observe
    );
}

#[test]
fn cv_ric_038_the_source_ceiling_bounds_the_retrieved_chunk() {
    let chunk = bound_chunk(CHUNK, TrustLevel::Bounded, AuthorityCeiling::Draft);
    let input = ModalInput::retrieved(CHUNK.to_string(), &chunk);
    assert_eq!(analyze(&[input]).authority_ceiling, AuthorityCeiling::Draft);
}

fn cross_trust(assessment: &MultimodalAssessment) -> bool {
    assessment
        .fusion
        .events
        .iter()
        .any(|e| e.kind == FusionRiskKind::CrossTrustFusion)
}

#[test]
fn cv_ric_038_fusion_sees_the_source_trust_not_the_retrieval_default() {
    let user = ModalInput {
        content: "Summarise the chunk.".to_string(),
        provenance: Provenance::User,
        ..Default::default()
    };
    // Retrieval defaults to Bounded, so a bounded source differs from the
    // untrusted user turn...
    let bounded = bound_chunk(CHUNK, TrustLevel::Bounded, AuthorityCeiling::Act);
    let mixed = analyze(&[
        user.clone(),
        ModalInput::retrieved(CHUNK.to_string(), &bounded),
    ]);
    assert!(cross_trust(&mixed));
    // ...but a chunk indexed from an untrusted source is untrusted: no
    // trust is gained by retrieving it.
    let untrusted = bound_chunk(CHUNK, TrustLevel::Untrusted, AuthorityCeiling::Act);
    let same = analyze(&[user, ModalInput::retrieved(CHUNK.to_string(), &untrusted)]);
    assert!(!cross_trust(&same));
}
