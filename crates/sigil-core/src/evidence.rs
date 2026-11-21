use crate::{
    policy::{EvidenceFormat, Policy},
    types::{EvidenceBundle, ScanFinding, Verdict},
};
use sha2::{Digest, Sha384};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn build_evidence(
    policy: &Policy,
    verdict: Verdict,
    findings: Vec<ScanFinding>,
    token_count: usize,
) -> EvidenceBundle {
    let truncated = findings.len() > policy.emit.max_evidence_findings;
    let findings = truncate_findings(findings, policy.emit.max_evidence_findings);
    let summary = summarize(
        &findings,
        &verdict,
        policy.emit.max_evidence_summary_chars,
        truncated,
    );
    let timestamp_unix_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or_default();
    let id = stable_evidence_id(&summary, token_count, timestamp_unix_ms);

    EvidenceBundle {
        id,
        verdict,
        findings,
        token_count,
        format: match policy.emit.evidence_format {
            EvidenceFormat::Json => crate::types::EvidenceFormat::Json,
            EvidenceFormat::Cbor => crate::types::EvidenceFormat::Cbor,
            EvidenceFormat::Protobuf => crate::types::EvidenceFormat::Protobuf,
        },
        // LIVE-003: built is not persisted — a configured `EvidenceSink`
        // sets this to `true` only after the write is confirmed.
        persisted: false,
        summary,
        timestamp_unix_ms,
    }
}

/// Bounds the evidence list. When it must cut, the most severe findings are
/// kept (stable within a severity): a flood of low-severity findings, such as
/// one `UnicodeControl` per smuggled tag character, must not push the finding
/// that decided the verdict out of the record.
fn truncate_findings(mut findings: Vec<ScanFinding>, max_findings: usize) -> Vec<ScanFinding> {
    if findings.len() <= max_findings {
        return findings;
    }
    findings.sort_by_key(|finding| std::cmp::Reverse(finding.severity));
    findings.truncate(max_findings);
    findings
}

fn summarize(
    findings: &[ScanFinding],
    verdict: &Verdict,
    max_chars: usize,
    truncated: bool,
) -> String {
    let severities = findings
        .iter()
        .map(|finding| finding.severity.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut summary = format!("verdict={verdict:?}; findings=[{severities}]");
    if truncated {
        summary.push_str("; truncated=true");
    }
    truncate_summary(&summary, max_chars)
}

fn truncate_summary(summary: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }

    if summary.chars().count() <= max_chars {
        return summary.to_string();
    }

    if max_chars == 1 {
        return "…".to_string();
    }

    let mut truncated = summary
        .chars()
        .take(max_chars.saturating_sub(1))
        .collect::<String>();
    truncated.push('…');
    truncated
}

/// Evidence identity: SHA-384 over the summary, token count, and timestamp,
/// truncated to 64 bits for the display id. Cryptographic digests for the
/// admitted representation live on `RepresentationReceipt` (RIC-R-1..R-4);
/// this id is a correlation handle, not a security anchor (D-4 resolution).
fn stable_evidence_id(summary: &str, token_count: usize, timestamp_unix_ms: u64) -> String {
    let mut hasher = Sha384::new();
    hasher.update(summary.as_bytes());
    hasher.update(token_count.to_le_bytes());
    hasher.update(timestamp_unix_ms.to_le_bytes());
    let digest = hasher.finalize();
    let truncated = u64::from_be_bytes(digest[..8].try_into().expect("8-byte slice"));
    format!("sigil-{truncated:016x}")
}

#[cfg(test)]
mod tests {
    use super::truncate_findings;
    use crate::types::{ByteRange, DetectorId, ScanFinding, Severity};

    fn finding(severity: Severity, tag: &str) -> ScanFinding {
        ScanFinding {
            byte_range: ByteRange::new(0, 1),
            severity,
            detectors: vec![DetectorId::UnicodeControl],
            confidence: 0.9,
            evidence: tag.to_string(),
        }
    }

    #[test]
    fn truncation_keeps_the_most_severe_findings() {
        let mut findings: Vec<ScanFinding> = (0..40)
            .map(|i| finding(Severity::Medium, &format!("m{i}")))
            .collect();
        findings.push(finding(Severity::High, "decisive"));
        let kept = truncate_findings(findings, 8);
        assert_eq!(kept.len(), 8);
        assert_eq!(kept[0].evidence, "decisive");
        assert_eq!(kept[1].evidence, "m0", "stable within a severity");
    }

    #[test]
    fn evidence_within_the_bound_keeps_its_order() {
        let findings = vec![finding(Severity::Low, "a"), finding(Severity::High, "b")];
        let kept = truncate_findings(findings.clone(), 8);
        assert_eq!(kept, findings);
    }
}
