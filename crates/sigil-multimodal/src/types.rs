use serde::{Deserialize, Serialize};
use sigil_core::types::{Provenance, Severity, SigilOutput, Verdict};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    #[default]
    Text,
    Vision,
    Audio,
    Video,
    Code,
    Document,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ModalInput {
    pub modality: Modality,
    pub content: String,
    #[serde(default)]
    pub provenance: Provenance,
    #[serde(default)]
    pub source_id: Option<String>,
    /// Derivation lineage: set when this channel was extracted from another
    /// artifact (e.g. OCR text read out of an image). Derived channels never
    /// inherit first-party authority (RIC-R-7).
    #[serde(default)]
    pub derived_from: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultimodalFinding {
    pub kind: MultimodalFindingKind,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MultimodalFindingKind {
    TextInImage,
    AdversarialPatch,
    Steganography,
    UltrasonicCommand,
    HiddenSpeech,
    TemporalInjection,
    PolyglotPayload,
    CommentInjection,
    EncodingExploit,
    DocumentLayerInjection,
    CrossModalSmuggling,
    /// Sub-audible frequency content (below ~20 Hz) detected by the
    /// spectral analyzer — may carry hidden ASR-transcribable commands.
    SubliminalAudio,
    /// Anomalous high-frequency energy near Nyquist — may indicate
    /// audio steganography or covert-channel embedding.
    AudioSteganography,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FusionRiskKind {
    /// Channels at different trust levels fused into one model context.
    CrossTrustFusion,
    /// Authority-bearing content (System) fused with data-role content.
    CrossRoleFusion,
    /// Instruction-like content in an untrusted channel fused with any
    /// higher-trust channel: the instruction may not exist in either
    /// artifact alone but forms through composition.
    CrossSourceInstructionFormation,
    /// A derived channel (OCR/ASR/transcript) claiming first-party
    /// authority (User/System provenance) it cannot possess.
    DerivedAuthorityEscalation,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FusionEvent {
    pub kind: FusionRiskKind,
    pub severity: Severity,
    pub sources: Vec<String>,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FusionAssessment {
    pub events: Vec<FusionEvent>,
    pub max_severity: Severity,
}

/// Upper bound on the authority any downstream consumer may exercise given
/// this assessment. Fusion uncertainty degrades authority; it never raises
/// it (RIC-R-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthorityCeiling {
    /// Clean input, no fusion events.
    Act,
    /// Clean input, but fusion events warrant caution.
    Draft,
    /// Flagged input — observe only.
    Observe,
    /// Denied input — human gate required.
    Escalate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ModalityAssessment {
    pub modality: Modality,
    pub sigil_output: Option<SigilOutput>,
    pub findings: Vec<MultimodalFinding>,
    pub verdict: Verdict,
    pub cross_modal_taint: Severity,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrossModalCorrelation {
    pub modalities: Vec<Modality>,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CrossModalAssessment {
    pub correlations: Vec<CrossModalCorrelation>,
    pub max_severity: Severity,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MultimodalAssessment {
    pub text: Option<SigilOutput>,
    pub vision: Option<ModalityAssessment>,
    pub audio: Option<ModalityAssessment>,
    pub code: Option<ModalityAssessment>,
    pub cross_modal: CrossModalAssessment,
    pub fusion: FusionAssessment,
    pub authority_ceiling: AuthorityCeiling,
    pub verdict: Verdict,
}
