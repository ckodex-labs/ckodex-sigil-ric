use sigil_core::{
    evidence::build_evidence,
    policy::Policy,
    types::{ByteRange, DetectorId, ScanFinding, Severity, Verdict},
};

fn finding(severity: Severity, label: &str) -> ScanFinding {
    ScanFinding {
        byte_range: ByteRange::new(0, label.len()),
        severity,
        detectors: vec![DetectorId::InjectionGrammar],
        confidence: 0.5,
        evidence: label.to_string(),
    }
}

#[test]
fn evidence_is_bounded_and_flags_truncation() {
    let mut policy = Policy::default();
    policy.emit.max_evidence_findings = 2;
    policy.emit.max_evidence_summary_chars = 128;

    let evidence = build_evidence(
        &policy,
        Verdict::Deny {
            reasons: vec![sigil_core::types::DenyReason::CriticalFinding],
        },
        vec![
            finding(Severity::Low, "low"),
            finding(Severity::High, "high"),
            finding(Severity::Critical, "critical"),
        ],
        42,
    );

    assert_eq!(evidence.findings.len(), 2);
    assert!(evidence.summary.contains("truncated=true"));
    assert!(evidence.summary.chars().count() <= policy.emit.max_evidence_summary_chars);
}

#[test]
fn zero_length_evidence_summary_stays_empty() {
    let mut policy = Policy::default();
    policy.emit.max_evidence_summary_chars = 0;

    let evidence = build_evidence(
        &policy,
        Verdict::Allow,
        vec![finding(Severity::Medium, "medium")],
        7,
    );

    assert!(evidence.summary.is_empty());
}
