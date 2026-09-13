use super::helpers::{load_custom_patterns, luhn_valid, redact_sample};
use super::types::TextMap;
use crate::policy::{EmailAction, Policy};
use crate::types::{DetectorId, DlpAction, DlpFinding, DlpKind, ScanFinding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub(crate) fn detect_dlp(map: &TextMap, policy: &Policy) -> (Vec<DlpFinding>, Vec<ScanFinding>) {
    let mut dlp = Vec::new();
    let mut findings = Vec::new();

    if policy.scan.dlp.credit_cards {
        static CC_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\b(?:\d[ -]*?){13,19}\b").expect("cc regex"));
        for capture in CC_RE.find_iter(&map.text) {
            let raw = capture.as_str();
            if luhn_valid(raw) {
                let byte_range = map.source_range_for(capture.start(), capture.end());
                dlp.push(DlpFinding {
                    kind: DlpKind::CreditCard,
                    byte_range,
                    severity: Severity::Critical,
                    action: DlpAction::Deny,
                    confidence: 0.99,
                    sample: redact_sample(raw),
                });
                findings.push(ScanFinding {
                    byte_range,
                    severity: Severity::Critical,
                    detectors: vec![DetectorId::DlpCreditCard],
                    confidence: 0.99,
                    evidence: "credit card number".to_string(),
                });
            }
        }
    }

    if policy.scan.dlp.ssn {
        static SSN_RE: Lazy<Regex> =
            Lazy::new(|| Regex::new(r"\b\d{3}-?\d{2}-?\d{4}\b").expect("ssn regex"));
        for capture in SSN_RE.find_iter(&map.text) {
            let byte_range = map.source_range_for(capture.start(), capture.end());
            dlp.push(DlpFinding {
                kind: DlpKind::Ssn,
                byte_range,
                severity: Severity::High,
                action: DlpAction::Deny,
                confidence: 0.95,
                sample: redact_sample(capture.as_str()),
            });
            findings.push(ScanFinding {
                byte_range,
                severity: Severity::High,
                detectors: vec![DetectorId::DlpSsn],
                confidence: 0.95,
                evidence: "ssn pattern".to_string(),
            });
        }
    }

    if policy.scan.dlp.api_keys {
        static KEY_RE: Lazy<Regex> = Lazy::new(|| {
            Regex::new(r"\b(sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
                .expect("api key regex")
        });
        for capture in KEY_RE.find_iter(&map.text) {
            let byte_range = map.source_range_for(capture.start(), capture.end());
            dlp.push(DlpFinding {
                kind: DlpKind::ApiKey,
                byte_range,
                severity: Severity::High,
                action: DlpAction::Deny,
                confidence: 0.98,
                sample: redact_sample(capture.as_str()),
            });
            findings.push(ScanFinding {
                byte_range,
                severity: Severity::High,
                detectors: vec![DetectorId::DlpApiKey],
                confidence: 0.98,
                evidence: "api key pattern".to_string(),
            });
        }
    }

    match &policy.scan.dlp.emails {
        EmailAction::Off => {}
        action => {
            static EMAIL_RE: Lazy<Regex> = Lazy::new(|| {
                Regex::new(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b").expect("email regex")
            });
            for capture in EMAIL_RE.find_iter(&map.text) {
                let byte_range = map.source_range_for(capture.start(), capture.end());
                let severity = match action {
                    EmailAction::Redact => Severity::Low,
                    EmailAction::Flag => Severity::Medium,
                    EmailAction::Deny => Severity::High,
                    EmailAction::Off => Severity::None,
                };
                dlp.push(DlpFinding {
                    kind: DlpKind::Email,
                    byte_range,
                    severity,
                    action: match action {
                        EmailAction::Redact => DlpAction::Redact,
                        EmailAction::Flag => DlpAction::Flag,
                        EmailAction::Deny => DlpAction::Deny,
                        EmailAction::Off => DlpAction::Off,
                    },
                    confidence: 0.90,
                    sample: redact_sample(capture.as_str()),
                });
                findings.push(ScanFinding {
                    byte_range,
                    severity,
                    detectors: vec![DetectorId::DlpEmail],
                    confidence: 0.90,
                    evidence: "email address".to_string(),
                });
            }
        }
    }

    for pattern in &policy.scan.dlp.custom_patterns {
        let regex = if pattern.ends_with(".toml") {
            load_custom_patterns(pattern)
                .into_iter()
                .collect::<Vec<_>>()
        } else {
            vec![pattern.clone()]
        };
        for raw_pattern in regex {
            if let Ok(re) = Regex::new(&raw_pattern) {
                for capture in re.find_iter(&map.text) {
                    let byte_range = map.source_range_for(capture.start(), capture.end());
                    dlp.push(DlpFinding {
                        kind: DlpKind::Custom(raw_pattern.clone()),
                        byte_range,
                        severity: Severity::Medium,
                        action: DlpAction::Flag,
                        confidence: 0.75,
                        sample: redact_sample(capture.as_str()),
                    });
                    findings.push(ScanFinding {
                        byte_range,
                        severity: Severity::Medium,
                        detectors: vec![DetectorId::DlpCustom],
                        confidence: 0.75,
                        evidence: raw_pattern.clone(),
                    });
                }
            }
        }
    }

    (dlp, findings)
}
