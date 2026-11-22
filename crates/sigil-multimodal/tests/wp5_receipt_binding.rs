//! RIC-MM-001 WP5 kernel half: every receipt the multimodal engine signs for
//! a perceived artifact binds the report's consumed block, the same object
//! the RIC-R-8 cap reads. Text inputs stay unbound.

use std::sync::Arc;

use sigil_core::Vocab;
use sigil_core::policy::Policy;
use sigil_core::receipt::verify_receipt;
use sigil_core::signing::EcdsaP384Signer;
use sigil_core::types::Provenance;
use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_multimodal::{
    AuthorityCeiling, ChannelKind, ConsumedParity, ConsumedView, ExtractedChannel,
    ExtractorIdentity, ModalInput, Modality, MultimodalEngine, PerceptionReport,
};

fn report(consumed: ConsumedView) -> PerceptionReport {
    let extractor = ExtractorIdentity::bound(
        "external-ocr/model-view".to_string(),
        "5.5.4".to_string(),
        "0e".repeat(48),
        vec!["stdin".to_string(), "-".to_string()],
        Vec::new(),
    );
    let channel = ExtractedChannel {
        channel_kind: ChannelKind::OcrText,
        content: "Q3 revenue by region".to_string(),
        extractor,
        confidence: None,
        truncated: false,
    };
    PerceptionReport {
        source_id: "chart".to_string(),
        artifact_digest: "ab".repeat(48),
        media_type: "image/png".to_string(),
        channels: vec![channel],
        consumed: Some(consumed),
        ..Default::default()
    }
}

#[test]
fn cv_ric_033_the_kernel_signs_the_consumed_block_it_judged() {
    let consumed = ConsumedView {
        profile: "thumbnail/nearest-80".to_string(),
        profile_digest: "11".repeat(48),
        digest: "22".repeat(48),
        parity: ConsumedParity::ReferenceMatched,
        extractor: Some("e3".to_string()),
        placeholders: None,
        placeholder_stream_digest: None,
    };
    let signer = Arc::new(EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("key"));
    let key = signer.verification_key_hex();
    let engine = MultimodalEngine::new(Policy::default(), Vocab::tiktoken("cl100k_base"))
        .expect("engine")
        .with_receipt_signer(signer);

    let mut inputs = channels_to_modal_inputs(&report(consumed.clone()), Modality::Vision);
    assert_eq!(inputs[0].channel, Some(ChannelKind::OcrText));
    inputs.push(ModalInput {
        modality: Modality::Text,
        content: "summarize the chart".to_string(),
        provenance: Provenance::User,
        ..Default::default()
    });
    let assessment = engine.analyze(&inputs).expect("analysis");
    assert_eq!(assessment.authority_ceiling, AuthorityCeiling::Act);

    let vision = assessment
        .vision
        .expect("vision")
        .sigil_output
        .expect("output");
    assert_eq!(vision.receipt.consumed.as_ref(), Some(&consumed));
    assert!(verify_receipt(&vision.receipt, &key).is_ok());

    let text = assessment.text.expect("text");
    assert_eq!(text.receipt.consumed, None, "text has no consumed media");
    assert!(verify_receipt(&text.receipt, &key).is_ok());
}
