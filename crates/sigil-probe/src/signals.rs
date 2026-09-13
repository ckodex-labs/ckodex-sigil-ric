use crate::types::*;
use std::collections::{BTreeMap, HashMap};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn health_score(
    signals: &[SignalAssessment],
    drift_score: f32,
    identity_confidence: f32,
) -> f32 {
    let signal_penalty = signals
        .iter()
        .map(|signal| signal.score * 0.10)
        .sum::<f32>();
    (1.0 - drift_score - signal_penalty + identity_confidence * 0.10).clamp(0.0, 1.0)
}

pub(crate) fn aggregate_drift(signals: &[SignalAssessment]) -> f32 {
    let max_signal = signals
        .iter()
        .map(|signal| signal.score)
        .fold(0.0, f32::max);
    let average = if signals.is_empty() {
        0.0
    } else {
        signals.iter().map(|signal| signal.score).sum::<f32>() / signals.len() as f32
    };
    (max_signal * 0.7 + average * 0.3).clamp(0.0, 1.0)
}

pub(crate) fn correlation_score(samples: &[ProbeSample]) -> f32 {
    if samples.is_empty() {
        return 1.0;
    }

    let mut total = 0.0;
    for sample in samples {
        let input_entropy = shannon_entropy(sample.input.as_bytes());
        let output_entropy = shannon_entropy(sample.output.as_bytes());
        let entropy_gap = (input_entropy - output_entropy).abs();
        let token_count = sample.output.split_whitespace().count().max(1) as f32;
        let latency_ratio = sample.latency_ms as f32 / token_count;
        total += (entropy_gap / 8.0).clamp(0.0, 1.0) * 0.5
            + (latency_ratio / 250.0).clamp(0.0, 1.0) * 0.5;
    }
    total / samples.len() as f32
}

pub(crate) fn output_distribution_shift(
    samples: &[ProbeSample],
    baseline: &BaselineProfile,
) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }

    let mut current = BTreeMap::new();
    for sample in samples {
        for token in sample.output.split_whitespace() {
            *current.entry(token.to_ascii_lowercase()).or_insert(0usize) += 1;
        }
    }

    let total_current: usize = current.values().sum();
    let total_baseline: usize = baseline.token_distribution.values().sum();
    if total_current == 0 || total_baseline == 0 {
        return 0.0;
    }

    let mut shift = 0.0;
    for (token, &count) in current.iter() {
        let p = count as f32 / total_current as f32;
        let q = baseline.token_distribution.get(token).copied().unwrap_or(0) as f32
            / total_baseline as f32;
        shift += (p - q).abs();
    }
    (shift / 2.0).clamp(0.0, 1.0)
}

pub(crate) fn refusal_rate(samples: &[ProbeSample]) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let refusals = samples
        .iter()
        .filter(|sample| is_refusal(&sample.output))
        .count();
    refusals as f32 / samples.len() as f32
}

pub(crate) fn latency_skew(samples: &[ProbeSample], baseline_ratio: f32) -> f32 {
    if samples.is_empty() {
        return 0.0;
    }
    let current = samples
        .iter()
        .map(|sample| {
            sample.latency_ms as f32 / sample.output.split_whitespace().count().max(1) as f32
        })
        .sum::<f32>()
        / samples.len() as f32;
    if baseline_ratio <= 0.0 {
        return 0.0;
    }
    ((current - baseline_ratio).abs() / baseline_ratio.max(1.0)).clamp(0.0, 1.0)
}

pub(crate) fn canary_failures(samples: &[ProbeSample], canaries: &[CanaryCase]) -> usize {
    canaries
        .iter()
        .filter(|canary| {
            samples.iter().all(|sample| {
                if sample.input != canary.input {
                    true
                } else {
                    !sample.output.contains(&canary.expected_fragment)
                }
            })
        })
        .count()
}

pub(crate) fn fingerprint_mismatches(
    samples: &[ProbeSample],
    probes: &[FingerprintProbe],
) -> usize {
    probes
        .iter()
        .filter(|probe| {
            samples.iter().all(|sample| {
                if sample.input != probe.input {
                    true
                } else {
                    !sample.output.contains(&probe.expected_fingerprint)
                }
            })
        })
        .count()
}

pub(crate) fn boundary_violations(samples: &[ProbeSample], probes: &[BoundaryProbe]) -> usize {
    probes
        .iter()
        .filter(|probe| {
            samples.iter().any(|sample| {
                sample.input == probe.input && sample.output.contains(&probe.forbidden_fragment)
            })
        })
        .count()
}

pub(crate) fn consistency_variants(samples: &[ProbeSample]) -> usize {
    let mut groups: HashMap<&str, Vec<&str>> = HashMap::new();
    for sample in samples {
        groups
            .entry(sample.input.as_str())
            .or_default()
            .push(sample.output.as_str());
    }

    groups
        .values()
        .filter(|outputs| {
            let mut unique = outputs.to_vec();
            unique.sort_unstable();
            unique.dedup();
            unique.len() > 1
        })
        .count()
}

pub(crate) fn is_refusal(output: &str) -> bool {
    let lowered = output.to_ascii_lowercase();
    lowered.contains("i can't")
        || lowered.contains("cannot comply")
        || lowered.contains("i cannot")
        || lowered.contains("refuse")
        || lowered.contains("not able")
}

pub(crate) fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f32;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}
