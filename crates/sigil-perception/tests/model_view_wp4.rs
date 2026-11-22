//! RIC-MM-001 WP4 end to end on the specimens (CV-RIC-029, CV-RIC-030,
//! CV-RIC-031 through the adapters).
//!
//! CV-RIC-029 runs real Tesseract on the source and on the model's view. It
//! fails, rather than skips, when Tesseract is missing: a vector that passes
//! without running proves nothing.

use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_multimodal::{
    ArtifactRef, AuthorityCeiling, ChannelKind, ConsumedParity, MultimodalEngine,
    MultimodalFindingKind, PerceptionReport,
};
use sigil_perception::audio::AudioAdapter;
use sigil_perception::preprocess::builtin;
use sigil_perception::{ExternalOcr, ImageAdapter, PerceptionAdapter};
use std::path::{Path, PathBuf};

const TESSERACT: &[&str] = &[
    "/opt/homebrew/bin/tesseract",
    "/usr/local/bin/tesseract",
    "/usr/bin/tesseract",
];

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/multimodal")
        .join(name)
}

fn specimens() -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(fixture("specimens.json")).expect("read"))
        .expect("json")
}

fn tesseract() -> ExternalOcr {
    let binary = TESSERACT
        .iter()
        .map(PathBuf::from)
        .find(|path| path.exists())
        .expect("CV-RIC-029 runs real OCR: install tesseract (brew install tesseract)");
    let args = ["stdin", "-", "--psm", "6"].map(str::to_string).to_vec();
    ExternalOcr::pin(binary, args, "tesseract".to_string()).expect("pin")
}

fn perceive_image(profile: &str) -> PerceptionReport {
    let bytes = std::fs::read(fixture("attack_source.png")).expect("specimen");
    ImageAdapter {
        interpreter: None,
        ocr: Some(tesseract()),
        profile: Some(builtin(profile).expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "attack_source".to_string(),
        bytes: &bytes,
        media_type: Some("image/png".to_string()),
    })
    .expect("perceive")
}

fn analyze(
    report: &PerceptionReport,
    modality: sigil_multimodal::Modality,
) -> sigil_multimodal::MultimodalAssessment {
    MultimodalEngine::new(
        sigil_core::policy::Policy::default(),
        sigil_core::Vocab::tiktoken("cl100k_base"),
    )
    .expect("engine")
    .analyze(&channels_to_modal_inputs(report, modality))
    .expect("analysis")
}

fn divergence(report: &PerceptionReport) -> Option<&str> {
    report
        .channels
        .iter()
        .find(|c| c.channel_kind == ChannelKind::Divergence)
        .map(|c| c.content.as_str())
}

#[test]
fn cv_ric_029_nearest_80_view_diverges_and_caps_authority() {
    let report = perceive_image("thumbnail/nearest-80");
    let consumed = report.consumed.as_ref().expect("consumed view");
    assert_eq!(
        consumed.digest,
        specimens()["image"]["views"]["nearest_80_rgb_sha384"]
    );
    assert_eq!(consumed.parity, ConsumedParity::ReferenceMatched);
    let only_in_view = divergence(&report)
        .expect("divergence channel")
        .to_uppercase();
    assert!(
        only_in_view.contains("IGNORE") && only_in_view.contains("RULES"),
        "the payload is text only the model's view carries: {only_in_view:?}"
    );
    let assessment = analyze(&report, sigil_multimodal::Modality::Vision);
    let finding = assessment
        .vision
        .as_ref()
        .expect("vision")
        .findings
        .iter()
        .find(|f| f.kind == MultimodalFindingKind::RepresentationDivergence)
        .expect("divergence finding");
    assert!(finding.severity >= sigil_core::types::Severity::High);
    assert!(assessment.authority_ceiling <= AuthorityCeiling::Observe);
}

#[test]
fn cv_ric_029_qwen2vl_view_does_not_diverge_and_binds_the_reference() {
    let report = perceive_image("qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow");
    let consumed = report.consumed.as_ref().expect("consumed view");
    let reference = specimens();
    assert_eq!(
        consumed.digest,
        reference["image"]["views"]["qwen2vl_644_bicubic_rgb_sha384"]
    );
    assert_eq!(
        Some(serde_json::json!(
            consumed.placeholders.expect("placeholders")
        )),
        Some(reference["image"]["qwen2vl"]["placeholders"].clone())
    );
    assert_eq!(divergence(&report), None);
    let view_ocr = report
        .channels
        .iter()
        .find(|c| c.extractor.name == "external-ocr/model-view")
        .expect("view OCR channel");
    assert!(
        view_ocr
            .extractor
            .args
            .iter()
            .any(|a| a == &format!("view:profile={}", consumed.profile_digest)),
        "the view OCR identity binds the profile"
    );
    let assessment = analyze(&report, sigil_multimodal::Modality::Vision);
    assert_eq!(assessment.authority_ceiling, AuthorityCeiling::Act);
}

#[test]
fn cv_ric_032_a_view_nothing_read_does_not_lift_the_cap() {
    // A benign image under a reference-matched profile with no OCR: the
    // view is bound, but nothing scanned it, so it resolves nothing.
    let mut png = std::io::Cursor::new(Vec::new());
    image::RgbImage::from_pixel(64, 64, image::Rgb([200, 210, 220]))
        .write_to(&mut png, image::ImageFormat::Png)
        .expect("png");
    let report = ImageAdapter {
        interpreter: None,
        ocr: None,
        profile: Some(builtin("thumbnail/nearest-80").expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "plain".to_string(),
        bytes: png.get_ref(),
        media_type: Some("image/png".to_string()),
    })
    .expect("perceive");
    let consumed = report.consumed.as_ref().expect("consumed view");
    assert_eq!(consumed.parity, ConsumedParity::ReferenceMatched);
    assert_eq!(consumed.extractor, None);
    let assessment = analyze(&report, sigil_multimodal::Modality::Vision);
    assert_eq!(assessment.authority_ceiling, AuthorityCeiling::Observe);
}

#[test]
fn cv_ric_031_decodes_no_vector_covers_are_approximate() {
    // Grey PNG: Pillow's convert("RGB") and this decoder may agree, but no
    // parity vector shows it, so the view claims nothing.
    let mut png = std::io::Cursor::new(Vec::new());
    image::GrayImage::from_pixel(64, 64, image::Luma([90]))
        .write_to(&mut png, image::ImageFormat::Png)
        .expect("png");
    let report = ImageAdapter {
        interpreter: None,
        ocr: None,
        profile: Some(builtin("thumbnail/nearest-80").expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "grey".to_string(),
        bytes: png.get_ref(),
        media_type: Some("image/png".to_string()),
    })
    .expect("perceive");
    assert_eq!(
        report.consumed.expect("consumed").parity,
        ConsumedParity::Approximate
    );
}

#[test]
fn a_wav_declaring_a_zero_sample_rate_fails_closed() {
    // hound accepts rate 0 when the byte rate is 0 too; decimation by a
    // zero step would panic.
    let mut wav = b"RIFF".to_vec();
    wav.extend(40u32.to_le_bytes());
    wav.extend(b"WAVEfmt ");
    wav.extend(16u32.to_le_bytes());
    wav.extend(1u16.to_le_bytes()); // PCM
    wav.extend(1u16.to_le_bytes()); // mono
    wav.extend(0u32.to_le_bytes()); // sample rate
    wav.extend(0u32.to_le_bytes()); // byte rate
    wav.extend(2u16.to_le_bytes()); // block align
    wav.extend(16u16.to_le_bytes()); // bits
    wav.extend(b"data");
    wav.extend(4u32.to_le_bytes());
    wav.extend([0, 0, 1, 0]);
    let result = AudioAdapter {
        resampler: None,
        transcript: None,
        profile: Some(builtin("audio/16k-decimate").expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "zero-rate".to_string(),
        bytes: &wav,
        media_type: Some("audio/wav".to_string()),
    });
    assert!(result.is_err(), "an error, not a panic and not a view");
}

#[test]
fn cv_ric_030_decimate_view_binds_the_reference_waveform() {
    // The divergence half of CV-RIC-030 needs a real ASR, which this
    // repository does not ship: here the consumed waveform is bound and
    // matches the numpy reference, and the audio judgment caps authority.
    let bytes = std::fs::read(fixture("attack_96k.wav")).expect("specimen");
    let report = AudioAdapter {
        resampler: None,
        transcript: None,
        profile: Some(builtin("audio/16k-decimate").expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "attack_96k".to_string(),
        bytes: &bytes,
        media_type: Some("audio/wav".to_string()),
    })
    .expect("perceive");
    let consumed = report.consumed.as_ref().expect("consumed view");
    assert_eq!(
        consumed.digest,
        specimens()["audio"]["waveform_16k_sha384"]["decimate_x6"]
    );
    let assessment = analyze(&report, sigil_multimodal::Modality::Audio);
    assert!(assessment.authority_ceiling <= AuthorityCeiling::Observe);
}

#[test]
fn a_profile_of_the_wrong_modality_fails_closed() {
    let bytes = std::fs::read(fixture("attack_source.png")).expect("specimen");
    let result = ImageAdapter {
        interpreter: None,
        ocr: None,
        profile: Some(builtin("audio/16k-decimate").expect("profile")),
    }
    .perceive(&ArtifactRef {
        source_id: "attack_source".to_string(),
        bytes: &bytes,
        media_type: Some("image/png".to_string()),
    });
    assert!(result.is_err(), "no view, no report");
}
