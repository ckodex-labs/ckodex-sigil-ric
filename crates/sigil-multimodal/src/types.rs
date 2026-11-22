use crate::perception::ChannelKind;
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
    /// The perception channel this input was mapped from. Set in process by
    /// `channels_to_modal_inputs`; never read from the wire.
    #[serde(skip)]
    pub channel: Option<ChannelKind>,
    /// The representation SIGIL produced for the model from this input's
    /// artifact; `None` when no preprocessor profile was declared. Bound into
    /// the input's receipt, and read by the RIC-R-8 cap. Never read from the
    /// wire: a caller cannot assert a view SIGIL did not produce.
    #[serde(skip)]
    pub consumed: Option<ConsumedView>,
    /// The retrieval boundary's judgment, when this input is a retrieved
    /// chunk SIGIL assessed in process (RIC-SPEC §4.3). Never read from the
    /// wire: a retrieval-provenance input without it is capped at observe.
    #[serde(skip)]
    pub retrieval: Option<BoundRetrieval>,
}

/// A retrieved chunk's assessment, bound to the text it was made for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRetrieval {
    /// Canonical digest of the admitted chunk text the assessment is for.
    pub chunk_digest: String,
    pub assessment: sigil_core::retrieval::RetrievalAssessment,
}

impl ModalInput {
    /// A retrieved chunk as a text input: retrieval provenance, derived from
    /// its source, with the retrieval boundary's assessment attached.
    #[must_use]
    pub fn retrieved(content: String, chunk: &sigil_core::retrieval::RetrievedChunk) -> Self {
        let assessment = sigil_core::retrieval::assess_retrieval(
            chunk,
            sigil_core::delegation::AuthorityCeiling::Act,
        );
        Self {
            modality: Modality::Text,
            content,
            provenance: Provenance::Retrieval,
            source_id: Some(format!("{}:retrieved", chunk.source_id)),
            derived_from: Some(chunk.source_id.clone()),
            channel: None,
            consumed: None,
            retrieval: Some(BoundRetrieval {
                chunk_digest: chunk.receipt.canonical_digest.clone(),
                assessment,
            }),
        }
    }
}

pub use sigil_core::receipt::{ConsumedParity, ConsumedView};

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
    /// Structured content above the audible band holding a material share
    /// of the file's energy: a channel the listener cannot hear.
    InaudibleBandEnergy,
    /// Inaudible structured content that folds into a model's baseband when
    /// it resamples without an anti-alias filter: the file says different
    /// things depending on the resampler.
    ResamplerAliasing,
    /// Content one representation of an artifact carries and another does
    /// not (e.g. text only the model's resized view shows).
    RepresentationDivergence,
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
pub use sigil_core::AuthorityCeiling;

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
