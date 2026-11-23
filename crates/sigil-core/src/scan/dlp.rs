use super::helpers::{load_custom_patterns, luhn_valid, redact_sample};
use super::types::TextMap;
use crate::policy::{EmailAction, Policy};
use crate::types::{ByteRange, DetectorId, DlpAction, DlpFinding, DlpKind, ScanFinding, Severity};
use regex::Regex;
use std::sync::LazyLock;

fn email_verdict(action: &EmailAction) -> Option<(Severity, DlpAction)> {
    match action {
        EmailAction::Off => None,
        EmailAction::Redact => Some((Severity::Low, DlpAction::Redact)),
        EmailAction::Flag => Some((Severity::Medium, DlpAction::Flag)),
        EmailAction::Deny => Some((Severity::High, DlpAction::Deny)),
    }
}

/// How one DLP match is reported: the same facts feed the typed `DlpFinding`
/// and the generic `ScanFinding`.
struct DlpRule {
    kind: DlpKind,
    detector: DetectorId,
    severity: Severity,
    action: DlpAction,
    confidence: f32,
    evidence: String,
}

/// Accumulates DLP matches in detection order.
#[derive(Default)]
struct DlpHits {
    dlp: Vec<DlpFinding>,
    findings: Vec<ScanFinding>,
}

impl DlpHits {
    fn record(&mut self, rule: &DlpRule, byte_range: ByteRange, raw: &str) {
        self.dlp.push(DlpFinding {
            kind: rule.kind.clone(),
            byte_range,
            severity: rule.severity,
            action: rule.action,
            confidence: rule.confidence,
            sample: redact_sample(raw),
        });
        self.findings.push(ScanFinding {
            byte_range,
            severity: rule.severity,
            detectors: vec![rule.detector.clone()],
            confidence: rule.confidence,
            evidence: rule.evidence.clone(),
        });
    }
}

/// Record every match of `re` in the text under `rule`.
fn scan_matches(map: &TextMap, re: &Regex, rule: &DlpRule, hits: &mut DlpHits) {
    for capture in re.find_iter(&map.text) {
        let byte_range = map.source_range_for(capture.start(), capture.end());
        hits.record(rule, byte_range, capture.as_str());
    }
}

/// Credit-card candidates are kept only when they pass the Luhn check.
fn scan_credit_cards(map: &TextMap, hits: &mut DlpHits) {
    static CC_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b(?:\d[ -]*?){13,19}\b").expect("cc regex"));
    let rule = DlpRule {
        kind: DlpKind::CreditCard,
        detector: DetectorId::DlpCreditCard,
        severity: Severity::Critical,
        action: DlpAction::Deny,
        confidence: 0.99,
        evidence: "credit card number".to_string(),
    };
    for capture in CC_RE.find_iter(&map.text) {
        let raw = capture.as_str();
        if luhn_valid(raw) {
            let byte_range = map.source_range_for(capture.start(), capture.end());
            hits.record(&rule, byte_range, raw);
        }
    }
}

fn scan_ssn(map: &TextMap, hits: &mut DlpHits) {
    static SSN_RE: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b\d{3}-?\d{2}-?\d{4}\b").expect("ssn regex"));
    let rule = DlpRule {
        kind: DlpKind::Ssn,
        detector: DetectorId::DlpSsn,
        severity: Severity::High,
        action: DlpAction::Deny,
        confidence: 0.95,
        evidence: "ssn pattern".to_string(),
    };
    scan_matches(map, &SSN_RE, &rule, hits);
}

fn scan_api_keys(map: &TextMap, hits: &mut DlpHits) {
    static KEY_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
            .expect("api key regex")
    });
    let rule = DlpRule {
        kind: DlpKind::ApiKey,
        detector: DetectorId::DlpApiKey,
        severity: Severity::High,
        action: DlpAction::Deny,
        confidence: 0.98,
        evidence: "api key pattern".to_string(),
    };
    scan_matches(map, &KEY_RE, &rule, hits);
}

fn scan_emails(map: &TextMap, severity: Severity, action: DlpAction, hits: &mut DlpHits) {
    static EMAIL_RE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").expect("email regex")
    });
    let rule = DlpRule {
        kind: DlpKind::Email,
        detector: DetectorId::DlpEmail,
        severity,
        action,
        confidence: 0.90,
        evidence: "email address".to_string(),
    };
    scan_matches(map, &EMAIL_RE, &rule, hits);
}

/// Operator-supplied patterns; a `.toml` entry names a pattern file.
fn scan_custom_patterns(map: &TextMap, patterns: &[String], hits: &mut DlpHits) {
    for pattern in patterns {
        let regex = if pattern.ends_with(".toml") {
            load_custom_patterns(pattern)
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            vec![pattern.clone()]
        };
        for raw_pattern in regex {
            if let Ok(re) = Regex::new(&raw_pattern) {
                let rule = DlpRule {
                    kind: DlpKind::Custom(raw_pattern.clone()),
                    detector: DetectorId::DlpCustom,
                    severity: Severity::Medium,
                    action: DlpAction::Flag,
                    confidence: 0.75,
                    evidence: raw_pattern,
                };
                scan_matches(map, &re, &rule, hits);
            }
        }
    }
}

pub(crate) fn detect_dlp(map: &TextMap, policy: &Policy) -> (Vec<DlpFinding>, Vec<ScanFinding>) {
    let mut hits = DlpHits::default();

    if policy.scan.dlp.credit_cards {
        scan_credit_cards(map, &mut hits);
    }
    if policy.scan.dlp.ssn {
        scan_ssn(map, &mut hits);
    }
    if policy.scan.dlp.api_keys {
        scan_api_keys(map, &mut hits);
    }
    if let Some((severity, action)) = email_verdict(&policy.scan.dlp.emails) {
        scan_emails(map, severity, action, &mut hits);
    }
    scan_custom_patterns(map, &policy.scan.dlp.custom_patterns, &mut hits);

    (hits.dlp, hits.findings)
}
