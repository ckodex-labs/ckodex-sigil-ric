use crate::engine::FusionRecord;
use crate::types::*;
use sigil_core::types::{Provenance, Severity};
use sigil_core::TrustLevel;

pub fn audit_fusion(records: &[FusionRecord]) -> FusionAssessment {
    let mut events = Vec::new();

    if records.is_empty() {
        return FusionAssessment {
            events,
            max_severity: Severity::None,
        };
    }

    let min_trust = records.iter().map(|r| r.trust).min().unwrap_or_default();
    let max_trust = records.iter().map(|r| r.trust).max().unwrap_or_default();

    // R1: cross-trust fusion (requires at least two channels).
    if records.len() >= 2 && min_trust != max_trust {
        let severity = if (max_trust as u8) - (min_trust as u8) >= 2 {
            Severity::Medium
        } else {
            Severity::Low
        };
        events.push(FusionEvent {
            kind: FusionRiskKind::CrossTrustFusion,
            severity,
            sources: records.iter().map(|r| r.source.clone()).collect(),
            detail: "channels at different trust levels fused into one context".to_string(),
        });
    }

    // R2: cross-role fusion — authority-bearing content fused with data channels.
    let has_authority = records.iter().any(|r| r.provenance == Provenance::System);
    let has_data = records
        .iter()
        .any(|r| !matches!(r.provenance, Provenance::System | Provenance::Generated));
    if has_authority && has_data {
        events.push(FusionEvent {
            kind: FusionRiskKind::CrossRoleFusion,
            severity: Severity::Medium,
            sources: records.iter().map(|r| r.source.clone()).collect(),
            detail: "authority-bearing content fused with data channels".to_string(),
        });
    }

    // R3: instruction formation across sources — an untrusted channel carries
    // an instruction signal while a higher-trust channel is present.
    let untrusted_instruction = records
        .iter()
        .any(|r| r.instruction_signal && r.trust == TrustLevel::Untrusted);
    let trusted_present = records.iter().any(|r| r.trust > TrustLevel::Untrusted);
    if untrusted_instruction && trusted_present {
        let sources = records
            .iter()
            .filter(|r| r.trust == TrustLevel::Untrusted && r.instruction_signal)
            .map(|r| r.source.clone())
            .collect();
        events.push(FusionEvent {
            kind: FusionRiskKind::CrossSourceInstructionFormation,
            severity: Severity::Critical,
            sources,
            detail: "untrusted channel carries instruction-like content fused with trusted context"
                .to_string(),
        });
    }

    // R4: derived authority escalation.
    for record in records.iter().filter(|r| r.derived) {
        if matches!(record.provenance, Provenance::System | Provenance::User) {
            events.push(FusionEvent {
                kind: FusionRiskKind::DerivedAuthorityEscalation,
                severity: Severity::High,
                sources: vec![record.source.clone()],
                detail: format!(
                    "derived channel {} claims first-party authority {:?}",
                    record.source, record.provenance,
                ),
            });
        }
    }

    let max_severity = events
        .iter()
        .map(|event| event.severity)
        .max()
        .unwrap_or(Severity::None);
    FusionAssessment {
        events,
        max_severity,
    }
}
