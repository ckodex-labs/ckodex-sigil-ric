use super::helpers::{is_smuggling_char, looks_like_base64, shannon_entropy};
use super::types::TextMap;
use crate::policy::{Mode, Policy};
use crate::types::{ByteRange, DetectorId, EntropyProfile, ScanFinding, Severity};
use once_cell::sync::Lazy;
use regex::Regex;

pub(crate) fn detect_injection(map: &TextMap, policy: &Policy) -> Vec<ScanFinding> {
    static PATTERNS: &[(&str, Severity, DetectorId)] = &[
        (
            "ignore previous",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        (
            "disregard previous",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        (
            "ignore all prior",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        ("ignore prior", Severity::High, DetectorId::InjectionGrammar),
        (
            "ignore the above",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        (
            "disregard all",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        (
            "forget all previous",
            Severity::High,
            DetectorId::InjectionGrammar,
        ),
        ("forget prior", Severity::High, DetectorId::InjectionGrammar),
        (
            "previous instructions",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "prior instructions",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "from now on",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "do anything now",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "new persona",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "pretend to be",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "pretend you are",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "new instructions",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        ("system:", Severity::High, DetectorId::InjectionGrammar),
        ("[inst]", Severity::High, DetectorId::InjectionGrammar),
        ("<|im_start|>", Severity::High, DetectorId::InjectionGrammar),
        (
            "### instruction",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "developer message",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        (
            "you are now",
            Severity::Medium,
            DetectorId::InjectionGrammar,
        ),
        ("act as", Severity::Medium, DetectorId::InjectionGrammar),
        ("override", Severity::Medium, DetectorId::InjectionGrammar),
    ];

    let mut findings = Vec::new();
    let lower = map.text.to_lowercase();
    for (needle, severity, detector) in PATTERNS {
        for (start, _) in lower.match_indices(needle) {
            let end = start + needle.len();
            findings.push(ScanFinding {
                byte_range: map.source_range_for(start, end),
                severity: *severity,
                detectors: vec![detector.clone()],
                confidence: 0.88,
                evidence: map.snippet_for(start, end),
            });
        }
    }

    // Unicode abuse is treated as part of the injection surface.
    findings.extend(detect_unicode_abuse(map, policy));
    findings
}

pub(crate) fn detect_unicode_abuse(map: &TextMap, policy: &Policy) -> Vec<ScanFinding> {
    let mut findings = Vec::new();

    for (idx, ch) in map.text.char_indices() {
        if crate::intake::is_invisible_char(ch) {
            let severity = match policy.intake.invisible_chars {
                crate::policy::InvisibleCharPolicy::Allow => Severity::Low,
                crate::policy::InvisibleCharPolicy::Strip => Severity::Low,
                crate::policy::InvisibleCharPolicy::Flag => Severity::Medium,
                crate::policy::InvisibleCharPolicy::Deny => Severity::Critical,
            };
            findings.push(ScanFinding {
                byte_range: map.source_range_for(idx, idx + ch.len_utf8()),
                severity,
                detectors: vec![DetectorId::UnicodeControl],
                confidence: 0.92,
                evidence: format!("unicode control U+{:04X}", u32::from(ch)),
            });
        }
    }

    let confusable_chars = [
        'а', 'е', 'о', 'р', 'с', 'у', 'х', 'і', 'ј', 'м', 'т', 'н', 'к', 'в', 'Α', 'Β', 'Ε', 'Ζ',
        'Η', 'Ι', 'Κ', 'Μ', 'Ν', 'Ο', 'Ρ', 'Τ', 'Υ', 'Χ',
    ];

    if map.text.chars().any(|ch| confusable_chars.contains(&ch))
        && map.text.chars().any(|ch| ch.is_ascii_alphabetic())
    {
        let severity = match policy.intake.homoglyph_action {
            crate::policy::HomoglyphAction::Normalize => Severity::Low,
            crate::policy::HomoglyphAction::Flag => Severity::Medium,
            crate::policy::HomoglyphAction::Deny => Severity::Critical,
        };
        findings.push(ScanFinding {
            byte_range: ByteRange::new(0, map.text.len()),
            severity,
            detectors: vec![DetectorId::Confusable],
            confidence: 0.86,
            evidence: "mixed-script confusable characters".to_string(),
        });
    }

    findings
}

pub(crate) fn detect_entropy(map: &TextMap, policy: &Policy) -> (EntropyProfile, Vec<ScanFinding>) {
    let bytes = map.text.as_bytes();
    let window = policy.scan.entropy_window.max(1);
    let mut values = Vec::new();
    let mut findings = Vec::new();

    if bytes.is_empty() {
        return (EntropyProfile::default(), findings);
    }

    let baseline = shannon_entropy(bytes);
    if bytes.len() <= window {
        let entropy = baseline;
        values.push(entropy);
    } else {
        for start in 0..=bytes.len() - window {
            let entropy = shannon_entropy(&bytes[start..start + window]);
            values.push(entropy);
            if (entropy - baseline).abs() >= policy.scan.entropy_deviation {
                let byte_range = map.source_range_for(start, start + window);
                findings.push(ScanFinding {
                    byte_range,
                    severity: if entropy > baseline {
                        Severity::High
                    } else {
                        Severity::Medium
                    },
                    detectors: vec![DetectorId::EntropySpike],
                    confidence: 0.72,
                    evidence: format!("entropy spike {:.2} vs {:.2}", entropy, baseline),
                });
            }
        }
    }

    let average_entropy = if values.is_empty() {
        baseline
    } else {
        values.iter().sum::<f32>() / values.len() as f32
    };
    let peak_entropy = values.iter().copied().fold(baseline, f32::max);
    (
        EntropyProfile {
            window_size: window,
            baseline_entropy: baseline,
            average_entropy,
            peak_entropy,
            anomaly_count: findings.len(),
        },
        findings,
    )
}

pub(crate) fn detect_smuggling(map: &TextMap, _policy: &Policy) -> Vec<ScanFinding> {
    let mut findings = Vec::new();
    let chars: Vec<(usize, char)> = map.text.char_indices().collect();

    for window in chars.windows(3) {
        let (a_i, a) = window[0];
        let (_, b) = window[1];
        let (c_i, c) = window[2];
        if a.is_ascii_alphanumeric() && is_smuggling_char(b) && c.is_ascii_alphanumeric() {
            findings.push(ScanFinding {
                byte_range: map.source_range_for(a_i, c_i + c.len_utf8()),
                severity: Severity::High,
                detectors: vec![DetectorId::TokenSmuggling],
                confidence: 0.84,
                evidence: "alphanumeric sequence bridged by invisible/control character"
                    .to_string(),
            });
        }
    }

    if looks_like_base64(&map.text) {
        findings.push(ScanFinding {
            byte_range: ByteRange::new(0, map.text.len()),
            severity: Severity::Medium,
            detectors: vec![DetectorId::TokenSmuggling],
            confidence: 0.68,
            evidence: "base64-like payload".to_string(),
        });
    }

    findings
}

pub(crate) fn detect_tokenizer_firewall(map: &TextMap, policy: &Policy) -> Vec<ScanFinding> {
    static RESERVED_PATTERN: Lazy<Regex> = Lazy::new(|| {
        Regex::new(r"<\|(?:reserved_\d+|startoftext|endoftext|endofprompt|fim_prefix|fim_middle|fim_suffix|return|constrain|channel|start|end|message|call)\|>")
            .expect("tokenizer firewall regex")
    });

    let mut findings = Vec::new();
    let severity = match policy.sigil.mode {
        Mode::Monitor => Severity::Medium,
        Mode::Enforce => Severity::High,
        Mode::Strict => Severity::Critical,
    };

    for capture in RESERVED_PATTERN.find_iter(&map.text) {
        let byte_range = map.source_range_for(capture.start(), capture.end());
        findings.push(ScanFinding {
            byte_range,
            severity,
            detectors: vec![DetectorId::TokenSmuggling],
            confidence: 0.96,
            evidence: format!("reserved tokenizer sentinel {}", capture.as_str()),
        });
    }

    findings
}
