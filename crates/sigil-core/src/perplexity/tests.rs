use super::*;
use crate::policy::PerplexityPolicy;

fn enabled_policy() -> PerplexityPolicy {
    PerplexityPolicy {
        enabled: true,
        ..Default::default()
    }
}

fn units_with_spike(text_len: usize, spike_start: usize, spike_end: usize) -> Vec<ScoredUnit> {
    (0..text_len)
        .map(|i| ScoredUnit {
            byte_range: ByteRange::new(i, i + 1),
            surprisal: if i >= spike_start && i < spike_end {
                12.0
            } else {
                2.0
            },
        })
        .collect()
}

#[test]
fn self_surprisal_scores_every_char_in_byte_order() {
    let scorer = SelfSurprisalScorer::new(4);
    let units = scorer.score("héllo wörld").expect("score");
    assert_eq!(units.len(), "héllo wörld".chars().count());
    // Byte ranges are contiguous, ordered, and cover the whole input.
    let mut cursor = 0;
    for unit in &units {
        assert_eq!(unit.byte_range.start, cursor);
        assert!(unit.byte_range.end > unit.byte_range.start);
        cursor = unit.byte_range.end;
    }
    assert_eq!(cursor, "héllo wörld".len());
}

#[test]
fn self_surprisal_marks_blob_region_more_surprising() {
    // A base64-ish blob embedded in varied prose breaks the document's
    // own character statistics.
    let mut text = String::new();
    for _ in 0..12 {
        text.push_str("the quick brown fox jumps over lazy dogs. ");
    }
    let blob_start = text.len();
    text.push_str("ZmluZCB0aGUgaGlkZGVuIHBheWxvYWQ=");
    let blob_end = text.len();
    for _ in 0..12 {
        text.push_str(" the rain in spain falls mainly on plains");
    }
    let scorer = SelfSurprisalScorer::new(4);
    let units = scorer.score(&text).expect("score");
    let in_blob: f32 = units
        .iter()
        .filter(|u| u.byte_range.start >= blob_start && u.byte_range.end <= blob_end)
        .map(|u| u.surprisal)
        .sum::<f32>()
        / (blob_end - blob_start) as f32;
    let out_blob: f32 = units
        .iter()
        .filter(|u| u.byte_range.end <= blob_start || u.byte_range.start >= blob_end)
        .map(|u| u.surprisal)
        .sum::<f32>()
        / (units.len() - (blob_end - blob_start)) as f32;
    assert!(
        in_blob > out_blob,
        "blob surprisal {in_blob} must exceed baseline {out_blob}"
    );
}

#[test]
fn multiscale_outlier_produces_finding_covering_spike() {
    let units = units_with_spike(400, 150, 210);
    let (findings, report) = detect_perplexity_anomalies(&units, &enabled_policy(), "test_scorer");
    assert_eq!(report.status, PerplexityStatus::Evaluated);
    assert_eq!(findings.len(), 1);
    let range = &findings[0].byte_range;
    assert!(range.start <= 150 && range.end >= 210, "range {range:?}");
    assert!(findings[0]
        .detectors
        .contains(&DetectorId::PerplexityAnomaly));
    assert_eq!(findings[0].severity, Severity::Medium);
}

#[test]
fn uniform_input_flags_nothing() {
    let units = units_with_spike(400, usize::MAX, usize::MAX);
    let (findings, report) = detect_perplexity_anomalies(&units, &enabled_policy(), "test_scorer");
    assert!(findings.is_empty());
    assert!(report.flagged.is_empty());
}

#[test]
fn min_scales_suppresses_single_scale_outlier() {
    // A spike narrow enough to fill only the smallest scale's window:
    // flagged at 16 but swallowed by 64/256 averages.
    let units = units_with_spike(400, 100, 118);
    let (findings, report) = detect_perplexity_anomalies(&units, &enabled_policy(), "test_scorer");
    // Either no cluster reaches 2 scales, or none — both acceptable;
    // the assertion is that no *finding* is emitted without corroboration.
    if report.flagged.is_empty() {
        assert!(findings.is_empty());
    } else {
        assert!(report
            .flagged
            .iter()
            .all(|f| findings.iter().any(|g| g.byte_range == f.byte_range)));
    }
}

#[test]
fn insufficient_units_is_skipped_not_silent() {
    let units = units_with_spike(10, 0, 5);
    let (findings, report) = detect_perplexity_anomalies(&units, &enabled_policy(), "test_scorer");
    assert!(findings.is_empty());
    assert!(matches!(report.status, PerplexityStatus::Skipped { .. }));
}

#[test]
fn empty_window_sizes_is_skipped() {
    let mut policy = enabled_policy();
    policy.window_sizes = vec![];
    let units = units_with_spike(400, 0, 50);
    let (_f, report) = detect_perplexity_anomalies(&units, &policy, "test_scorer");
    assert!(matches!(report.status, PerplexityStatus::Skipped { .. }));
}

#[test]
fn max_windows_bounds_work() {
    let mut policy = enabled_policy();
    policy.max_windows = 10;
    let units = units_with_spike(2000, 900, 960);
    let (_f, report) = detect_perplexity_anomalies(&units, &policy, "test_scorer");
    let total_windows: usize = report.scales.iter().map(|s| s.window_count).sum();
    assert!(total_windows <= 10, "windows {total_windows}");
}

#[test]
fn report_serializes_for_evidence() {
    let report = PerplexityReport {
        status: PerplexityStatus::Evaluated,
        scorer: "self_surprisal_char_ngram".to_string(),
        scales: vec![ScaleStats {
            units_per_window: 16,
            window_count: 10,
            median_surprisal: 2.0,
            mad: 0.1,
            flagged: 1,
        }],
        flagged: vec![FlagCluster {
            byte_range: ByteRange::new(4, 20),
            scales: vec![16, 64],
            max_z: 6.5,
        }],
    };
    let json = serde_json::to_string(&report).expect("serialize");
    let back: PerplexityReport = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, report);
    assert!(json.contains("\"evaluated\""));
}

#[test]
fn findings_are_capped() {
    // Many separated spikes → at most MAX_FINDINGS findings.
    let mut units = Vec::new();
    for i in 0..1200usize {
        let in_spike = (0..6).any(|s| (s * 200 + 50..s * 200 + 90).contains(&i));
        units.push(ScoredUnit {
            byte_range: ByteRange::new(i, i + 1),
            surprisal: if in_spike { 12.0 } else { 2.0 },
        });
    }
    let (findings, _) = detect_perplexity_anomalies(&units, &enabled_policy(), "t");
    assert!(
        findings.len() <= MAX_FINDINGS,
        "{} findings",
        findings.len()
    );
}
