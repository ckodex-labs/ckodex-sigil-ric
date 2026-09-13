use crate::detect::*;
use crate::fusion::*;
use crate::types::*;
use crate::verdict::*;
use sigil_core::engine::Sigil;
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_core::types::{Provenance, Severity, TextSegment};
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
        let mut text = None;
        let mut vision = None;
        let mut audio = None;
        let mut code = None;
        let mut correlations = Vec::new();
        let mut modality_severities = Vec::new();
        let mut fusion_records: Vec<FusionRecord> = Vec::new();

        for (idx, input) in inputs.iter().enumerate() {
            let output = self.sigil.process_text_segments(&[TextSegment {
                text: &input.content,
                provenance: input.provenance,
            }])?;
            let assessment = output.assessment.clone();
            let (findings, _cross_modal_taint) = match input.modality {
                Modality::Text => {
                    text = Some(output.clone());
                    (Vec::new(), assessment.max_severity)
                }
                Modality::Vision => {
                    let findings = detect_vision(&input.content, &assessment);
                    (findings, assessment.max_severity)
                }
                Modality::Audio => {
                    let findings = detect_audio(&input.content, &assessment);
                    (findings, assessment.max_severity)
                }
                Modality::Video => {
                    let findings = detect_video(&input.content, &assessment);
                    (findings, assessment.max_severity)
                }
                Modality::Code => {
                    let findings = detect_code(&input.content, &assessment);
                    (findings, assessment.max_severity)
                }
                Modality::Document => {
                    let findings = detect_document(&input.content, &assessment);
                    (findings, assessment.max_severity)
                }
            };

            let verdict = compose_modality_verdict(assessment.max_severity, &findings);
            let modality_assessment = ModalityAssessment {
                modality: input.modality,
                sigil_output: Some(output.clone()),
                findings,
                verdict: verdict.clone(),
                cross_modal_taint: assessment.max_severity,
            };

            fusion_records.push(FusionRecord {
                source: input
                    .source_id
                    .clone()
                    .unwrap_or_else(|| format!("{:?}[{}]", input.modality, idx)),
                provenance: input.provenance,
                trust: input.provenance.default_trust(),
                derived: input.derived_from.is_some(),
                instruction_signal: has_instruction_signal(&output),
            });

            modality_severities.push(assessment.max_severity);
            match input.modality {
                Modality::Vision => vision = Some(modality_assessment),
                Modality::Audio => audio = Some(modality_assessment),
                Modality::Code => code = Some(modality_assessment),
                Modality::Text | Modality::Video | Modality::Document => {
                    // These are represented through the cross-modal set and the text channel.
                    if matches!(input.modality, Modality::Video | Modality::Document) {
                        correlations.push(CrossModalCorrelation {
                            modalities: vec![Modality::Text, input.modality],
                            severity: assessment.max_severity,
                            detail: format!(
                                "{:?} content carries text-like payload",
                                input.modality
                            ),
                        });
                    }
                }
            }

            if matches!(input.modality, Modality::Video | Modality::Document)
                && assessment.max_severity >= Severity::Medium
            {
                correlations.push(CrossModalCorrelation {
                    modalities: vec![Modality::Text, input.modality],
                    severity: assessment.max_severity,
                    detail: "cross-modal taint propagated to text channel".to_string(),
                });
            }
        }

        let fusion = audit_fusion(&fusion_records);
        let cross_max = modality_severities
            .iter()
            .copied()
            .max()
            .unwrap_or(Severity::None)
            .max(fusion.max_severity);
        let cross_modal_verdict = compose_cross_modal_verdict(cross_max, &correlations);
        let final_verdict = fold_verdicts(
            text.as_ref(),
            vision.as_ref(),
            audio.as_ref(),
            code.as_ref(),
            &cross_modal_verdict,
        );
        let ceiling = authority_ceiling(&final_verdict, &fusion);

        Ok(MultimodalAssessment {
            text,
            vision,
            audio,
            code,
            cross_modal: CrossModalAssessment {
                correlations,
                max_severity: cross_max,
                verdict: cross_modal_verdict,
            },
            fusion,
            authority_ceiling: ceiling,
            verdict: final_verdict,
        })
    }
}
