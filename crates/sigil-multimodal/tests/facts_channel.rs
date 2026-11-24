//! RIC-MM-001 F1 / D5: the audio spectral report is SIGIL's own measurement.
//! As a facts channel it is judged only by the spectral rules; lexed as
//! language, its JSON (a hex digest, numeric keys) flagged every benign
//! recording as token smuggling.

use sigil_core::Vocab;
use sigil_core::policy::Policy;
use sigil_core::types::{Provenance, Verdict};
use sigil_multimodal::{ChannelKind, ModalInput, Modality, MultimodalEngine};

/// The spectral report sigil-perception produced for real speech
/// (LibriSpeech, from the sherpa-onnx test set).
fn benign_report() -> String {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/fixtures/multimodal/benign_speech_spectral.json"
    ))
    .expect("fixture");
    fixture["reports"]["0.wav"].to_string()
}

fn audio(kind: ChannelKind, content: String) -> ModalInput {
    ModalInput {
        modality: Modality::Audio,
        content,
        provenance: Provenance::McpTool,
        source_id: Some("speech.wav:spectral".to_string()),
        derived_from: Some("speech.wav".to_string()),
        channel: Some(kind),
        consumed: None,
        retrieval: None,
    }
}

fn verdict(input: ModalInput) -> Verdict {
    MultimodalEngine::new(Policy::default(), Vocab::tiktoken("cl100k_base"))
        .expect("engine")
        .analyze(&[input])
        .expect("analysis")
        .verdict
}

#[test]
fn a_benign_spectral_report_is_judged_as_facts_not_language() {
    assert_eq!(
        verdict(audio(ChannelKind::Facts, benign_report())),
        Verdict::Allow
    );
    // The same bytes in a language channel are lexed, and flag: the gate is
    // the channel kind an in-process adapter chose, nothing in the content.
    assert_ne!(
        verdict(audio(ChannelKind::Metadata, benign_report())),
        Verdict::Allow
    );
}

#[test]
fn a_facts_channel_still_carries_its_spectral_findings() {
    let hidden = serde_json::json!({ "inaudible_band": {
        "low_hz": 20000.0, "high_hz": 48000.0, "energy_fraction": 0.73,
        "peak_hz": 32250.0, "flatness": 1e-6 } });
    assert_ne!(
        verdict(audio(ChannelKind::Facts, hidden.to_string())),
        Verdict::Allow
    );
}

#[test]
fn a_facts_channel_cannot_be_claimed_over_the_wire() {
    let wire = r#"{"modality":"audio","content":"x","channel":"facts"}"#;
    let input: ModalInput = serde_json::from_str(wire).expect("deserialize");
    assert_eq!(input.channel, None);
}
