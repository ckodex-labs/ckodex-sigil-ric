//! SIGIL-M multimodal extension.
//!
//! The multimodal layer reuses SIGIL-core for text-like extraction and applies
//! modality-specific heuristics for vision, audio, video, code, and documents.
//!
//! On top of per-modality detection, the fusion-boundary auditor inspects the
//! composition itself: which sources are being fused, at which trust levels,
//! and whether the fusion could form an instruction that did not exist in any
//! single artifact (unsafe-fusion detection, docs/RIC-CONTRACT.md RIC-R-6).

mod extractor_identity;
pub mod perception;

mod detect;
mod engine;
mod fusion;
mod types;
mod verdict;

pub use engine::MultimodalEngine;
pub use perception::{
    ArtifactRef, ChannelKind, ConsumedView, EXTRACTOR_IDENTITY_V1, EXTRACTOR_IDENTITY_V2,
    ExtractedChannel, ExtractorIdentity, PerceptionAdapter, PerceptionError, PerceptionReport,
};
pub use types::{
    AuthorityCeiling, BoundRetrieval, ConsumedParity, CrossModalAssessment, CrossModalCorrelation,
    Delivery, FusionAssessment, FusionEvent, FusionRiskKind, ModalInput, Modality,
    ModalityAssessment, MultimodalAssessment, MultimodalFinding, MultimodalFindingKind,
};

#[cfg(test)]
mod tests;
