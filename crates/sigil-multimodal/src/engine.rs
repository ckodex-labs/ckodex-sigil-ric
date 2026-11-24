use crate::detect::*;
use crate::fusion::*;
use crate::types::*;
use crate::verdict::*;
use sigil_core::engine::Sigil;
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_core::types::{InputAssessment, Provenance, Severity, SigilOutput, TextSegment};
use sigil_core::{TrustLevel, Vocab};

#[derive(Clone, Debug)]
pub struct MultimodalEngine {
    sigil: Sigil,
}

/// Per-channel record consumed by the fusion-boundary auditor.
pub(crate) struct FusionRecord {
    pub source: String,
    pub provenance: Provenance,
    pub trust: TrustLevel,
    pub derived: bool,
    pub instruction_signal: bool,
}

impl MultimodalEngine {
    pub fn new(policy: Policy, vocab: Vocab) -> sigil_core::Result<Self> {
        Ok(Self {
            sigil: Sigil::new(vocab, policy)?,
        })
    }

    /// Attach a receipt signer so every per-channel `SigilOutput` carries a
    /// signed receipt (docs/RIC-SPEC.md §5).
    pub fn with_receipt_signer(mut self, signer: std::sync::Arc<dyn ReceiptSigner>) -> Self {
        self.sigil = self.sigil.with_receipt_signer(signer);
        self
    }

    pub fn analyze(&self, inputs: &[ModalInput]) -> sigil_core::Result<MultimodalAssessment> {
        let mut acc = Accumulator::default();
        for (idx, input) in inputs.iter().enumerate() {
            self.absorb(&mut acc, idx, input)?;
        }
        Ok(acc.conclude(inputs))
    }

    /// Admits one input through the kernel and folds its judgment into `acc`.
    fn absorb(
        &self,
        acc: &mut Accumulator,
        idx: usize,
        input: &ModalInput,
    ) -> sigil_core::Result<()> {
        let output = self.sigil.process_text_segments_bound(
            &[TextSegment {
                text: &input.content,
                provenance: input.provenance,
            }],
            input.consumed.clone(),
        )?;
        let mut assessment = output.assessment.clone();
        if input.channel == Some(crate::perception::ChannelKind::Facts) {
            // SIGIL's own measurements are admitted and receipted, but judged
            // by the facts rules alone: lexing a spectral report as language
            // flagged every benign recording (RIC-MM-001 F1).
            assessment.max_severity = sigil_core::types::Severity::None;
        }
        acc.retrieval_caps
            .extend(retrieval_cap(input, &output.receipt.canonical_digest));
        if input.modality == Modality::Text {
            acc.text = Some(output.clone());
        }
        let mut findings = modality_findings(input, &assessment);
        if input.channel == Some(crate::perception::ChannelKind::Divergence) {
            findings.push(divergence_finding(&output));
        }
        let verdict = compose_modality_verdict(assessment.max_severity, &findings);
        let modality_assessment = ModalityAssessment {
            modality: input.modality,
            sigil_output: Some(output.clone()),
            findings,
            verdict,
            cross_modal_taint: assessment.max_severity,
        };

        acc.fusion_records.push(FusionRecord {
            source: input
                .source_id
                .clone()
                .unwrap_or_else(|| format!("{:?}[{}]", input.modality, idx)),
            provenance: input.provenance,
            trust: input_trust(input),
            derived: input.derived_from.is_some(),
            instruction_signal: has_instruction_signal(&output),
        });
        acc.modality_severities.push(assessment.max_severity);
        acc.place(input.modality, modality_assessment);
        acc.correlate(input.modality, assessment.max_severity);
        Ok(())
    }
}

/// The modality-specific findings for one admitted input. Text has none: it
/// is judged by the kernel alone.
fn modality_findings(input: &ModalInput, assessment: &InputAssessment) -> Vec<MultimodalFinding> {
    match input.modality {
        Modality::Text => Vec::new(),
        Modality::Vision => detect_vision(&input.content, assessment),
        Modality::Audio => detect_audio(&input.content, assessment),
        Modality::Video => detect_video(&input.content, assessment),
        Modality::Code => detect_code(&input.content, assessment),
        Modality::Document => detect_document(&input.content, assessment),
    }
}

/// What `analyze` gathers across inputs before it concludes.
#[derive(Default)]
struct Accumulator {
    text: Option<SigilOutput>,
    vision: Option<ModalityAssessment>,
    audio: Option<ModalityAssessment>,
    code: Option<ModalityAssessment>,
    correlations: Vec<CrossModalCorrelation>,
    modality_severities: Vec<Severity>,
    fusion_records: Vec<FusionRecord>,
    retrieval_caps: Vec<AuthorityCeiling>,
}

impl Accumulator {
    /// Folds a modality's assessment into its slot. Video, document and text
    /// are represented through the cross-modal set and the text channel.
    fn place(&mut self, modality: Modality, assessment: ModalityAssessment) {
        match modality {
            Modality::Vision => merge_modality(&mut self.vision, assessment),
            Modality::Audio => merge_modality(&mut self.audio, assessment),
            Modality::Code => merge_modality(&mut self.code, assessment),
            Modality::Text | Modality::Video | Modality::Document => {}
        }
    }

    /// Video and document content carries text-like payload; at medium
    /// severity or above the taint propagates to the text channel.
    fn correlate(&mut self, modality: Modality, severity: Severity) {
        if !matches!(modality, Modality::Video | Modality::Document) {
            return;
        }
        self.correlations.push(CrossModalCorrelation {
            modalities: vec![Modality::Text, modality],
            severity,
            detail: format!("{modality:?} content carries text-like payload"),
        });
        if severity >= Severity::Medium {
            self.correlations.push(CrossModalCorrelation {
                modalities: vec![Modality::Text, modality],
                severity,
                detail: "cross-modal taint propagated to text channel".to_string(),
            });
        }
    }

    /// Audits the fusion, folds the verdicts and bounds the authority.
    fn conclude(self, inputs: &[ModalInput]) -> MultimodalAssessment {
        let fusion = audit_fusion(&self.fusion_records);
        let cross_max = self
            .modality_severities
            .iter()
            .copied()
            .max()
            .unwrap_or(Severity::None)
            .max(fusion.max_severity);
        let cross_modal_verdict = compose_cross_modal_verdict(cross_max, &self.correlations);
        let final_verdict = fold_verdicts(
            self.text.as_ref(),
            self.vision.as_ref(),
            self.audio.as_ref(),
            self.code.as_ref(),
            &cross_modal_verdict,
        );
        let mut ceiling = authority_ceiling(&final_verdict, &fusion);
        if inputs.iter().any(interpreter_unresolved) {
            ceiling = ceiling.min(AuthorityCeiling::Observe);
        }
        for cap in self.retrieval_caps {
            ceiling = ceiling.min(cap);
        }

        MultimodalAssessment {
            text: self.text,
            vision: self.vision,
            audio: self.audio,
            code: self.code,
            cross_modal: CrossModalAssessment {
                correlations: self.correlations,
                max_severity: cross_max,
                verdict: cross_modal_verdict,
            },
            fusion,
            authority_ceiling: ceiling,
            verdict: final_verdict,
        }
    }
}
