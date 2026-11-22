use crate::types::*;
use sigil_core::types::{FlagReason, Severity, SigilOutput, Verdict};

pub fn has_instruction_signal(output: &SigilOutput) -> bool {
    match &output.assessment.verdict {
        Verdict::Flag { reasons } => reasons.iter().any(|reason| {
            matches!(
                reason,
                FlagReason::InjectionPattern
                    | FlagReason::Smuggling
                    | FlagReason::CrossModalSmuggling
            )
        }),
        Verdict::Deny { .. } => output.assessment.max_severity >= Severity::High,
        Verdict::Allow => false,
    }
}

pub(crate) fn authority_ceiling(verdict: &Verdict, fusion: &FusionAssessment) -> AuthorityCeiling {
    match verdict {
        Verdict::Deny { .. } => AuthorityCeiling::Escalate,
        Verdict::Flag { .. } => AuthorityCeiling::Observe,
        Verdict::Allow => {
            if fusion.events.is_empty() {
                AuthorityCeiling::Act
            } else {
                AuthorityCeiling::Draft
            }
        }
    }
}

/// RIC-R-8: a pixel or sound input whose consumed representation SIGIL did
/// not produce under a reference-matched profile leaves the model's
/// interpreter unresolved. Uncertainty degrades authority, never raises it.
pub(crate) fn interpreter_unresolved(input: &ModalInput) -> bool {
    matches!(
        input.modality,
        Modality::Vision | Modality::Audio | Modality::Video
    ) && input.consumed_parity != Some(ConsumedParity::ReferenceMatched)
}

fn verdict_rank(verdict: &Verdict) -> u8 {
    match verdict {
        Verdict::Allow => 0,
        Verdict::Flag { .. } => 1,
        Verdict::Deny { .. } => 2,
    }
}

/// Folds another channel's assessment into the modality's slot: the most
/// severe verdict and output lead, and every channel's findings are kept.
pub(crate) fn merge_modality(slot: &mut Option<ModalityAssessment>, next: ModalityAssessment) {
    let Some(current) = slot.take() else {
        *slot = Some(next);
        return;
    };
    let key = |a: &ModalityAssessment| (verdict_rank(&a.verdict), a.cross_modal_taint);
    let (mut lead, other) = if key(&next) > key(&current) {
        (next, current)
    } else {
        (current, next)
    };
    lead.findings.extend(other.findings);
    *slot = Some(lead);
}

pub(crate) fn compose_modality_verdict(
    severity: Severity,
    findings: &[MultimodalFinding],
) -> Verdict {
    if severity >= Severity::Critical {
        Verdict::Deny {
            reasons: vec![sigil_core::types::DenyReason::BehavioralCompromise],
        }
    } else if severity >= Severity::High || !findings.is_empty() {
        Verdict::Flag {
            reasons: vec![FlagReason::BehavioralDrift],
        }
    } else {
        Verdict::Allow
    }
}

pub(crate) fn compose_cross_modal_verdict(
    severity: Severity,
    correlations: &[CrossModalCorrelation],
) -> Verdict {
    if severity >= Severity::Critical {
        Verdict::Deny {
            reasons: vec![sigil_core::types::DenyReason::BehavioralCompromise],
        }
    } else if severity >= Severity::High || correlations.len() > 1 {
        Verdict::Flag {
            reasons: vec![FlagReason::SentinelDisagreement],
        }
    } else {
        Verdict::Allow
    }
}

pub(crate) fn fold_verdicts(
    text: Option<&SigilOutput>,
    vision: Option<&ModalityAssessment>,
    audio: Option<&ModalityAssessment>,
    code: Option<&ModalityAssessment>,
    cross_modal: &Verdict,
) -> Verdict {
    let mut severities = Vec::new();
    if let Some(text) = text {
        severities.push(text.assessment.max_severity);
    }
    for item in [vision, audio, code].into_iter().flatten() {
        severities.push(match item.verdict {
            Verdict::Deny { .. } => Severity::Critical,
            Verdict::Flag { .. } => Severity::Medium,
            Verdict::Allow => item.cross_modal_taint,
        });
    }
    if let Verdict::Deny { .. } = cross_modal {
        return cross_modal.clone();
    }
    let max = severities.into_iter().max().unwrap_or(Severity::None);
    match max {
        Severity::Critical => Verdict::Deny {
            reasons: vec![sigil_core::types::DenyReason::BehavioralCompromise],
        },
        Severity::High | Severity::Medium => Verdict::Flag {
            reasons: vec![FlagReason::CrossModalSmuggling],
        },
        _ => cross_modal.clone(),
    }
}
