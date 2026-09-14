use super::detectors::{
    detect_entropy, detect_injection, detect_smuggling, detect_tokenizer_firewall,
};
use super::dlp::detect_dlp;
use super::types::{annotate_graphemes, summarize_findings, ScanReport, TextMap};
use crate::policy::Policy;
use crate::types::{EntropyProfile, Severity, TaintedGrapheme};

pub fn run_scan(policy: &Policy, tainted: &mut [TaintedGrapheme]) -> ScanReport {
    run_scan_with_scorer(policy, tainted, None)
}

/// Scan with an optional injected [`SurprisalScorer`]. When the
/// perplexity detector is enabled, `scorer` overrides the built-in
/// `SelfSurprisalScorer` — this is the integration point for LM-grade
/// scorers (e.g. via `sigil-probe`) without kernel changes.
pub fn run_scan_with_scorer(
    policy: &Policy,
    tainted: &mut [TaintedGrapheme],
    scorer: Option<&dyn crate::perplexity::SurprisalScorer>,
) -> ScanReport {
    let map = TextMap::new(tainted);
    let mut findings = Vec::new();
    let mut dlp_findings = Vec::new();
    let mut entropy_profile = EntropyProfile::default();

    if policy.scan.injection_detection {
        findings.extend(detect_injection(&map, policy));
    }
    if policy.scan.tokenizer_firewall {
        findings.extend(detect_tokenizer_firewall(&map, policy));
    }
    if policy.scan.dlp_enabled {
        let (dlp, scan_findings) = detect_dlp(&map, policy);
        dlp_findings.extend(dlp);
        findings.extend(scan_findings);
    }
    if policy.scan.entropy_analysis {
        let (profile, entropy_findings) = detect_entropy(&map, policy);
        entropy_profile = profile;
        findings.extend(entropy_findings);
    }

    if policy.scan.smuggling_detection {
        findings.extend(detect_smuggling(&map, policy));
    }

    if policy.scan.rare_pattern_detection {
        findings.extend(crate::lfdd::detect_rare_patterns(
            &map.text,
            &crate::lfdd::RarePatternConfig::default(),
        ));
    }

    let mut perplexity = None;
    if policy.scan.perplexity.enabled {
        let builtin;
        let scorer: &dyn crate::perplexity::SurprisalScorer = match scorer {
            Some(s) => s,
            None => {
                builtin =
                    crate::perplexity::SelfSurprisalScorer::new(policy.scan.perplexity.model_order);
                &builtin
            }
        };
        let (pfindings, preport) = match scorer.score(&map.text) {
            Ok(units) => crate::perplexity::detect_perplexity_anomalies(
                &units,
                &policy.scan.perplexity,
                scorer.name(),
            ),
            Err(e) => (
                Vec::new(),
                crate::perplexity::PerplexityReport::failed(scorer.name(), e.to_string()),
            ),
        };
        findings.extend(pfindings);
        perplexity = Some(preport);
    }

    annotate_graphemes(tainted, &findings);
    let summary = summarize_findings(&findings);
    ScanReport {
        findings,
        dlp_findings,
        max_severity: summary.max_severity,
        threat_count: summary.threat_count,
        entropy_profile,
        injection_score: summary.injection_score,
        slow_rate: None,
        perplexity,
    }
}

/// Run the scan stage with a cross-input history for slow-rate detection.
/// In addition to the per-input detectors, this analyzes the history for
/// distributed prompt-injection patterns (rate anomalies + fragment
/// correlation) and attaches the result to the `ScanReport`.
pub fn run_scan_with_history(
    policy: &Policy,
    tainted: &mut [TaintedGrapheme],
    history: &[crate::lfdd::InputHistoryEntry],
    current_time: u64,
) -> ScanReport {
    let mut report = run_scan(policy, tainted);
    if policy.scan.slow_rate_detection {
        let slow = crate::lfdd::detect_slow_rate(
            history,
            current_time,
            &crate::lfdd::SlowRateConfig::default(),
        );
        if slow.severity > report.max_severity {
            report.max_severity = slow.severity;
        }
        if slow.severity != Severity::None {
            report.threat_count += 1;
        }
        report.slow_rate = Some(slow);
    }
    report
}
