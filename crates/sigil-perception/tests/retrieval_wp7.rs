//! RIC-MM-001 WP7 with a real tokenizer: a subword embedder whose tokenizer
//! is the pinned Qwen2 byte-level BPE (CV-RIC-036 shows it equals Hugging
//! Face's) consumes every byte of the GloVe specimen's tag-smuggled probe,
//! so its embedded input binds the admitted representation and the
//! retrieval interpreter resolves (CV-RIC-039).

use std::path::Path;

use serde_json::Value;
use sigil_core::delegation::AuthorityCeiling;
use sigil_core::policy::Policy;
use sigil_core::retrieval::{
    EmbeddedInput, EmbeddingBinding, EmbeddingModel, Pooling, RetrievedChunk, assess_retrieval,
};
use sigil_core::types::{Provenance, TextSegment, TrustLevel};
use sigil_core::{Sigil, Vocab};
use sigil_perception::vlm::{QWEN2_VL_2B, Qwen2VlInterpreter};

/// The pinned Qwen2-VL interpreter. Fetched, not vendored:
/// scripts/reference/fetch_qwen2vl_assets.sh.
fn qwen2vl_interpreter() -> Qwen2VlInterpreter {
    let assets = std::env::var_os("SIGIL_QWEN2VL_ASSETS").map_or_else(
        || Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.ref-models/qwen2-vl-2b"),
        std::path::PathBuf::from,
    );
    Qwen2VlInterpreter::load(&assets, &QWEN2_VL_2B).unwrap_or_else(|e| {
        panic!(
            "Qwen2-VL assets at {}: {e} (run scripts/reference/fetch_qwen2vl_assets.sh)",
            assets.display()
        )
    })
}

/// `text` admitted by SIGIL's engine as a retrieved chunk, embedded by a
/// model whose tokenizer produced `ids`.
fn bound_chunk(text: &str, ids: &[u32]) -> RetrievedChunk {
    let receipt = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
        .expect("engine")
        .process_text_segments(&[TextSegment {
            text,
            provenance: Provenance::Retrieval,
        }])
        .expect("admit")
        .receipt;
    let tokenizer_digest = QWEN2_VL_2B.files[0].1.to_string();
    RetrievedChunk {
        source_id: "kb://reports/q3".to_string(),
        source_trust: TrustLevel::Bounded,
        source_ceiling: AuthorityCeiling::Act,
        embedding: Some(EmbeddingBinding {
            model: EmbeddingModel {
                name: "qwen2-tokenized embedder".to_string(),
                // No embedding weights are vendored: the rule under test is
                // the input binding, which the real tokenizer decides.
                weights_digest: "unmeasured".to_string(),
                tokenizer_digest,
                pooling: Pooling::Mean,
                dimensions: 1536,
            },
            input: EmbeddedInput::from_token_ids(&receipt.canonical_digest, ids),
            score: 0.5,
        }),
        receipt,
    }
}

#[test]
fn cv_ric_039_a_byte_level_embedder_binds_the_whole_tag_smuggled_chunk() {
    let reference: Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/multimodal/qwen2vl_ids.json"
    ))
    .expect("reference");
    let probe = &reference["texts"][0];
    let text = probe["text"].as_str().expect("text");
    assert!(
        text.chars()
            .any(|c| ('\u{E0000}'..='\u{E007F}').contains(&c)),
        "the tag probe"
    );

    let interpreter = qwen2vl_interpreter();
    let ids = interpreter.tokenizer().encode(text).expect("encode");
    let expected: Vec<u64> = probe["ids"]
        .as_array()
        .expect("ids")
        .iter()
        .map(|v| v.as_u64().expect("id"))
        .collect();
    assert_eq!(
        ids.iter().map(|id| u64::from(*id)).collect::<Vec<_>>(),
        expected
    );

    let chunk = bound_chunk(text, &ids);
    let assessment = assess_retrieval(&chunk, AuthorityCeiling::Act);
    assert!(assessment.findings.is_empty(), "{:?}", assessment.findings);
    assert_eq!(assessment.ceiling, AuthorityCeiling::Act);
    assert_eq!(
        chunk.embedding.expect("bound").input.consumed_units,
        ids.len() as u64
    );
}
