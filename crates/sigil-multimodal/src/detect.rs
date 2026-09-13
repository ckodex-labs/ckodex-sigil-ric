use crate::types::*;
use sigil_core::types::{InputAssessment, Severity};

pub fn detect_vision(content: &str, assessment: &InputAssessment) -> Vec<MultimodalFinding> {
    detect_keywords(
        content,
        &[
            (
                "text in image",
                MultimodalFindingKind::TextInImage,
                Severity::High,
            ),
            (
                "adversarial patch",
                MultimodalFindingKind::AdversarialPatch,
                Severity::Critical,
            ),
            (
                "stego",
                MultimodalFindingKind::Steganography,
                Severity::High,
            ),
            ("ocr", MultimodalFindingKind::TextInImage, Severity::Medium),
        ],
        assessment,
    )
}

pub(crate) fn detect_audio(content: &str, assessment: &InputAssessment) -> Vec<MultimodalFinding> {
    let mut findings = detect_keywords(
        content,
        &[
            (
                "ultrasonic",
                MultimodalFindingKind::UltrasonicCommand,
                Severity::Critical,
            ),
            (
                "hidden speech",
                MultimodalFindingKind::HiddenSpeech,
                Severity::High,
            ),
            (
                "command",
                MultimodalFindingKind::HiddenSpeech,
                Severity::Medium,
            ),
            (
                "transcript",
                MultimodalFindingKind::HiddenSpeech,
                Severity::Low,
            ),
        ],
        assessment,
    );

    // Parse spectral analysis JSON emitted by sigil-perception::spectral.
    // The spectral report contains `subliminal_findings` and
    // `steganography_findings` arrays. When non-empty, emit findings with
    // the correct MultimodalFindingKind.
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(content) {
        if let Some(subliminal) = value.get("subliminal_findings").and_then(|v| v.as_array()) {
            if !subliminal.is_empty() {
                findings.push(MultimodalFinding {
                    kind: MultimodalFindingKind::SubliminalAudio,
                    severity: Severity::High.max(assessment.max_severity),
                    detail: format!(
                        "sub-audible spectral energy detected ({} band(s))",
                        subliminal.len()
                    ),
                });
            }
        }
        if let Some(stego) = value
            .get("steganography_findings")
            .and_then(|v| v.as_array())
        {
            if !stego.is_empty() {
                findings.push(MultimodalFinding {
                    kind: MultimodalFindingKind::AudioSteganography,
                    severity: Severity::High.max(assessment.max_severity),
                    detail: format!(
                        "high-frequency spectral anomaly detected ({} band(s))",
                        stego.len()
                    ),
                });
            }
        }
    }

    findings
}

pub(crate) fn detect_video(content: &str, assessment: &InputAssessment) -> Vec<MultimodalFinding> {
    detect_keywords(
        content,
        &[
            (
                "single frame",
                MultimodalFindingKind::TemporalInjection,
                Severity::Critical,
            ),
            (
                "frame 1",
                MultimodalFindingKind::TemporalInjection,
                Severity::High,
            ),
            (
                "subtitle injection",
                MultimodalFindingKind::TemporalInjection,
                Severity::High,
            ),
        ],
        assessment,
    )
}

pub(crate) fn detect_code(content: &str, assessment: &InputAssessment) -> Vec<MultimodalFinding> {
    detect_keywords(
        content,
        &[
            (
                "polyglot",
                MultimodalFindingKind::PolyglotPayload,
                Severity::High,
            ),
            (
                "comment injection",
                MultimodalFindingKind::CommentInjection,
                Severity::High,
            ),
            (
                "encoding exploit",
                MultimodalFindingKind::EncodingExploit,
                Severity::Critical,
            ),
            (
                "ignore previous",
                MultimodalFindingKind::CommentInjection,
                Severity::Critical,
            ),
        ],
        assessment,
    )
}

pub(crate) fn detect_document(
    content: &str,
    assessment: &InputAssessment,
) -> Vec<MultimodalFinding> {
    detect_keywords(
        content,
        &[
            (
                "hidden layer",
                MultimodalFindingKind::DocumentLayerInjection,
                Severity::High,
            ),
            (
                "white on white",
                MultimodalFindingKind::DocumentLayerInjection,
                Severity::Medium,
            ),
            (
                "ocr",
                MultimodalFindingKind::DocumentLayerInjection,
                Severity::Low,
            ),
            (
                "cross modal",
                MultimodalFindingKind::CrossModalSmuggling,
                Severity::High,
            ),
        ],
        assessment,
    )
}

pub(crate) fn detect_keywords(
    content: &str,
    patterns: &[(&str, MultimodalFindingKind, Severity)],
    assessment: &InputAssessment,
) -> Vec<MultimodalFinding> {
    let lower = content.to_ascii_lowercase();
    let mut findings = Vec::new();
    for (needle, kind, severity) in patterns {
        if lower.contains(needle) {
            findings.push(MultimodalFinding {
                kind: *kind,
                severity: (*severity).max(assessment.max_severity),
                detail: format!("detected {needle}"),
            });
        }
    }
    if lower.contains("text") && lower.contains("image") && !findings.is_empty() {
        findings.push(MultimodalFinding {
            kind: MultimodalFindingKind::CrossModalSmuggling,
            severity: Severity::Medium,
            detail: "cross-modal payload appears coherent across modalities".to_string(),
        });
    }
    findings
}
