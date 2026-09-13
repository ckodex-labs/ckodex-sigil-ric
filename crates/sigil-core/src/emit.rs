use crate::{
    evidence::build_evidence,
    merge::MergedToken,
    policy::{EvidenceMode, Mode, Policy},
    scan::ScanReport,
    types::{
        FlagReason, InputAssessment, RepresentationReceipt, ScanFinding, Severity, SigilOutput,
        TokenAnnotation, Verdict,
    },
};

pub fn emit_output(
    policy: &Policy,
    merged: Vec<MergedToken>,
    mut report: ScanReport,
    receipt: RepresentationReceipt,
) -> SigilOutput {
    let token_ids = merged
        .iter()
        .map(|token| token.token_id)
        .collect::<Vec<_>>();
    let annotations = merged
        .iter()
        .map(|token| annotation_for_token(token, &report.findings))
        .collect::<Vec<_>>();
    let verdict = decide_verdict(policy, &report);
    let assessment = InputAssessment {
        verdict: verdict.clone(),
        max_severity: report.max_severity,
        threat_count: report.threat_count,
        entropy_profile: report.entropy_profile,
        dlp_findings: report.dlp_findings.clone(),
        injection_score: report.injection_score,
    };
    let evidence = match assessment.verdict {
        Verdict::Allow if !matches!(policy.emit.evidence_mode, EvidenceMode::Always) => None,
        _ => Some(build_evidence(
            policy,
            assessment.verdict.clone(),
            std::mem::take(&mut report.findings),
            token_ids.len(),
        )),
    };

    SigilOutput {
        token_ids,
        annotations,
        assessment,
        evidence,
        receipt,
    }
}

fn annotation_for_token(token: &MergedToken, findings: &[ScanFinding]) -> TokenAnnotation {
    let mut threat = ScanFinding::none(token.byte_range);
    for finding in findings {
        if token.byte_range.overlaps(finding.byte_range) {
            if threat.severity.rank() < finding.severity.rank() {
                threat.severity = finding.severity;
            }
            for detector in &finding.detectors {
                if !threat.detectors.contains(detector) {
                    threat.detectors.push(detector.clone());
                }
            }
            threat.confidence = threat.confidence.max(finding.confidence);
            if threat.evidence.is_empty() {
                threat.evidence = finding.evidence.clone();
            }
        }
    }

    TokenAnnotation {
        provenance: token.provenance,
        trust_level: token.trust_level,
        threat,
        byte_range: token.byte_range,
        normalized: token.normalized,
        boundary: token.boundary,
    }
}

fn decide_verdict(policy: &Policy, report: &ScanReport) -> Verdict {
    let reasons = collect_reasons(report);
    let high = report.max_severity >= Severity::High;
    let medium = report.max_severity >= Severity::Medium
        || report.injection_score >= policy.scan.injection_threshold;

    match report.max_severity {
        Severity::Critical => Verdict::Deny {
            reasons: vec![crate::types::DenyReason::CriticalFinding],
        },
        Severity::High if matches!(policy.sigil.mode, Mode::Monitor) => Verdict::Flag { reasons },
        Severity::High => Verdict::Deny {
            reasons: vec![crate::types::DenyReason::PolicyViolation],
        },
        Severity::Medium if matches!(policy.sigil.mode, Mode::Strict) => Verdict::Deny {
            reasons: vec![crate::types::DenyReason::PolicyViolation],
        },
        Severity::Medium if medium => Verdict::Flag { reasons },
        Severity::Low if matches!(policy.sigil.mode, Mode::Strict) => Verdict::Flag { reasons },
        Severity::Low if matches!(policy.sigil.mode, Mode::Monitor) => Verdict::Flag { reasons },
        Severity::Low | Severity::None if high => Verdict::Flag { reasons },
        _ if report.threat_count > 0 => Verdict::Flag { reasons },
        _ => Verdict::Allow,
    }
}

fn collect_reasons(report: &ScanReport) -> Vec<FlagReason> {
    let mut reasons = Vec::new();
    if report.findings.iter().any(|finding| {
        finding.evidence.contains("instruction")
            || finding
                .detectors
                .iter()
                .any(|d| matches!(d, crate::types::DetectorId::InjectionGrammar))
    }) {
        reasons.push(FlagReason::InjectionPattern);
    }
    if !report.dlp_findings.is_empty() {
        reasons.push(FlagReason::DlpFinding);
    }
    if report.entropy_profile.anomaly_count > 0 {
        reasons.push(FlagReason::EntropyAnomaly);
    }
    if report.findings.iter().any(|finding| {
        finding
            .detectors
            .iter()
            .any(|d| matches!(d, crate::types::DetectorId::TokenSmuggling))
    }) {
        reasons.push(FlagReason::Smuggling);
    }
    if reasons.is_empty() && report.threat_count > 0 {
        reasons.push(FlagReason::UnicodeAbuse);
    }
    reasons
}
