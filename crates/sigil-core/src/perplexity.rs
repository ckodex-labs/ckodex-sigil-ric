//! Multiscale perplexity-anomaly detection (D2).
//!
//! Detects injected segments whose predictive statistics break the
//! document's own baseline: sliding windows are scored at several scales
//! and windows whose mean surprisal is a robust outlier (median/MAD
//! z-score) — corroborated across scales — produce `ScanFinding`s.
//! Inspired by multiscale perplexity signatures (arXiv:2311.11509):
//! single-scale analysis misses camouflaged injections, so a window must
//! be anomalous at `min_scales` distinct scales to report.
//!
//! Boundary contract:
//! - A [`SurprisalScorer`] supplies per-unit surprisal (−ln p). Model or
//!   provider details live behind the trait — no model code in the kernel.
//! - Scores become *findings*; the kernel's policy maps findings to
//!   verdicts (`Medium` → `Flag`, `Deny` under `Mode::Strict`). A scorer
//!   never decides.
//! - [`SelfSurprisalScorer`] is the built-in deterministic scorer: an
//!   order-k character n-gram model fit to the input itself. It flags
//!   segments that break the document's own character statistics (encoded
//!   blobs, obfuscated payloads, script switches). It does **not** flag
//!   same-style English instructions — that requires an LM-grade scorer
//!   plugged through the same trait (e.g. via `sigil-probe`).
//! - Scorer failure is evidence-visible (`PerplexityStatus::Failed`), not
//!   silent and not a deny: an outage must not DoS the pipeline.

use crate::policy::PerplexityPolicy;
use crate::types::{ByteRange, DetectorId, ScanFinding, Severity};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// One scored unit of input, in byte order. The scorer defines the unit
/// (character, token, word); the analyzer only requires byte ranges.
#[derive(Clone, Debug, PartialEq)]
pub struct ScoredUnit {
    pub byte_range: ByteRange,
    /// −ln p of this unit under the scorer's model. Higher = more
    /// surprising.
    pub surprisal: f32,
}

/// Pluggable surprisal provider. Implementations may be deterministic
/// statistical models or adapters over external LMs; all produce the
/// same unit stream the kernel analyzes.
pub trait SurprisalScorer {
    /// Identifier recorded in evidence (`PerplexityReport::scorer`).
    fn name(&self) -> &'static str;
    /// Score `text` into per-unit surprisal values, in byte order.
    /// Must not panic on arbitrary input; report failures as `Err`.
    fn score(&self, text: &str) -> Result<Vec<ScoredUnit>, PerplexityError>;
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PerplexityError {
    pub message: String,
}

impl PerplexityError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for PerplexityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "surprisal scorer failed: {}", self.message)
    }
}

impl std::error::Error for PerplexityError {}

/// Built-in scorer: order-k character n-gram model fit to the input
/// itself, with add-one smoothing over the observed alphabet. The
/// document is its own baseline — segments whose character transitions
/// are rare *for this document* score high.
#[derive(Clone, Debug)]
pub struct SelfSurprisalScorer {
    /// Context length in characters (n-gram order − 1 context chars).
    pub order: usize,
}

impl SelfSurprisalScorer {
    pub fn new(order: usize) -> Self {
        Self {
            order: order.clamp(1, 16),
        }
    }
}

impl SurprisalScorer for SelfSurprisalScorer {
    fn name(&self) -> &'static str {
        "self_surprisal_char_ngram"
    }

    fn score(&self, text: &str) -> Result<Vec<ScoredUnit>, PerplexityError> {
        let chars: Vec<(usize, char)> = text.char_indices().collect();
        let n = chars.len();
        if n == 0 {
            return Ok(Vec::new());
        }
        let k = self.order;
        let mut unigram: HashMap<char, usize> = HashMap::new();
        let mut ctx_count: HashMap<Vec<char>, usize> = HashMap::new();
        let mut pair_count: HashMap<(Vec<char>, char), usize> = HashMap::new();
        for (i, &(_, ch)) in chars.iter().enumerate() {
            *unigram.entry(ch).or_default() += 1;
            if i >= k {
                let ctx: Vec<char> = chars[i - k..i].iter().map(|&(_, c)| c).collect();
                *ctx_count.entry(ctx.clone()).or_default() += 1;
                *pair_count.entry((ctx, ch)).or_default() += 1;
            }
        }
        let vocab = unigram.len() as f32;
        let mut units = Vec::with_capacity(n);
        for (i, &(byte_off, ch)) in chars.iter().enumerate() {
            let p = if i >= k {
                let ctx: Vec<char> = chars[i - k..i].iter().map(|&(_, c)| c).collect();
                let num = pair_count.get(&(ctx.clone(), ch)).copied().unwrap_or(0) as f32 + 1.0;
                let den = ctx_count.get(&ctx).copied().unwrap_or(0) as f32 + vocab;
                num / den
            } else {
                (unigram[&ch] as f32 + 1.0) / (n as f32 + vocab)
            };
            units.push(ScoredUnit {
                byte_range: ByteRange::new(byte_off, byte_off + ch.len_utf8()),
                surprisal: -p.ln(),
            });
        }
        Ok(units)
    }
}

/// One window flagged as a surprisal outlier at one scale.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlaggedWindow {
    pub byte_range: ByteRange,
    /// Units per window for the scale that flagged it.
    pub scale: usize,
    pub mean_surprisal: f32,
    /// Robust z-score: 0.6745·(x − median)/MAD.
    pub z: f32,
}

/// Per-scale distribution summary retained for evidence.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScaleStats {
    pub units_per_window: usize,
    pub window_count: usize,
    pub median_surprisal: f32,
    pub mad: f32,
    pub flagged: usize,
}

/// A cluster of overlapping flagged windows spanning multiple scales —
/// the unit that becomes a finding.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FlagCluster {
    /// Union byte range of the corroborating windows.
    pub byte_range: ByteRange,
    /// Distinct scales whose windows overlapped into this cluster.
    pub scales: Vec<usize>,
    /// Highest robust z-score among member windows.
    pub max_z: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PerplexityStatus {
    Evaluated,
    /// Detector was enabled but could not score meaningfully.
    Skipped {
        reason: String,
    },
    /// The scorer errored; recorded for evidence, not treated as signal.
    Failed {
        reason: String,
    },
}

/// Evidence record for the perplexity pass. Carries the scorer identity
/// and per-scale distribution stats so a flagged window can be audited
/// against the document's own baseline.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PerplexityReport {
    pub status: PerplexityStatus,
    pub scorer: String,
    pub scales: Vec<ScaleStats>,
    /// Overlapping-flag clusters that met `min_scales`, best first.
    pub flagged: Vec<FlagCluster>,
}

impl PerplexityReport {
    pub fn skipped(scorer: &str, reason: impl Into<String>) -> Self {
        Self {
            status: PerplexityStatus::Skipped {
                reason: reason.into(),
            },
            scorer: scorer.to_string(),
            scales: Vec::new(),
            flagged: Vec::new(),
        }
    }

    pub fn failed(scorer: &str, reason: impl Into<String>) -> Self {
        Self {
            status: PerplexityStatus::Failed {
                reason: reason.into(),
            },
            scorer: scorer.to_string(),
            scales: Vec::new(),
            flagged: Vec::new(),
        }
    }
}

fn median(values: &mut [f32]) -> f32 {
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    match values.len() {
        0 => 0.0,
        n if n % 2 == 1 => values[n / 2],
        n => (values[n / 2 - 1] + values[n / 2]) / 2.0,
    }
}

/// Maximum flagged clusters emitted as findings (bounded evidence).
const MAX_FINDINGS: usize = 8;

/// Analyze a scored unit stream at every configured scale. Windows whose
/// mean surprisal exceeds `median + z_threshold·MAD/0.6745` are flagged;
/// overlapping flags must span `min_scales` distinct scales to report.
pub fn detect_perplexity_anomalies(
    units: &[ScoredUnit],
    policy: &PerplexityPolicy,
    scorer_name: &str,
) -> (Vec<ScanFinding>, PerplexityReport) {
    if units.len() < policy.min_units {
        return (
            Vec::new(),
            PerplexityReport::skipped(scorer_name, "insufficient_scored_units"),
        );
    }
    let mut scales: Vec<usize> = policy.window_sizes.clone();
    scales.retain(|&w| w >= 2);
    scales.sort_unstable();
    scales.dedup();
    if scales.is_empty() {
        return (
            Vec::new(),
            PerplexityReport::skipped(scorer_name, "no_valid_window_sizes"),
        );
    }

    let mut stats = Vec::new();
    let mut flagged: Vec<FlaggedWindow> = Vec::new();
    let mut budget = policy.max_windows;
    for &w in &scales {
        if units.len() < w || budget == 0 {
            continue;
        }
        let step = (w / 2).max(1);
        let mut means = Vec::new();
        let mut start = 0;
        while start + w <= units.len() && budget > 0 {
            let mean: f32 = units[start..start + w]
                .iter()
                .map(|u| u.surprisal)
                .sum::<f32>()
                / w as f32;
            means.push((start, mean));
            start += step;
            budget -= 1;
        }
        let mut sorted: Vec<f32> = means.iter().map(|&(_, m)| m).collect();
        let med = median(&mut sorted);
        let mut devs: Vec<f32> = sorted.iter().map(|m| (m - med).abs()).collect();
        let mad = median(&mut devs);
        let mut scale_flagged = 0;
        for &(off, mean) in &means {
            let z = 0.6745 * (mean - med) / mad.max(f32::EPSILON);
            if z >= policy.z_threshold {
                flagged.push(FlaggedWindow {
                    byte_range: ByteRange::new(
                        units[off].byte_range.start,
                        units[off + w - 1].byte_range.end,
                    ),
                    scale: w,
                    mean_surprisal: mean,
                    z,
                });
                scale_flagged += 1;
            }
        }
        stats.push(ScaleStats {
            units_per_window: w,
            window_count: means.len(),
            median_surprisal: med,
            mad,
            flagged: scale_flagged,
        });
    }

    // Cluster overlapping flagged windows across scales; a cluster must
    // cover `min_scales` distinct scales to produce a finding.
    flagged.sort_by_key(|f| (f.byte_range.start, f.scale));
    let mut clusters: Vec<FlagCluster> = Vec::new();
    for fw in &flagged {
        match clusters.last_mut() {
            Some(c)
                if fw.byte_range.start <= c.byte_range.end
                    && fw.byte_range.end >= c.byte_range.start =>
            {
                if !c.scales.contains(&fw.scale) {
                    c.scales.push(fw.scale);
                }
                c.byte_range.end = c.byte_range.end.max(fw.byte_range.end);
                c.max_z = c.max_z.max(fw.z);
            }
            _ => clusters.push(FlagCluster {
                byte_range: fw.byte_range,
                scales: vec![fw.scale],
                max_z: fw.z,
            }),
        }
    }

    let min_scales = policy.min_scales.max(1);
    let mut corroborated: Vec<FlagCluster> = clusters
        .into_iter()
        .filter(|c| c.scales.len() >= min_scales)
        .collect();
    corroborated.sort_by(|a, b| {
        b.max_z
            .partial_cmp(&a.max_z)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    corroborated.truncate(MAX_FINDINGS);

    let findings = corroborated
        .iter()
        .map(|c| ScanFinding {
            byte_range: c.byte_range,
            severity: Severity::Medium,
            detectors: vec![DetectorId::PerplexityAnomaly],
            confidence: (c.max_z / (2.0 * policy.z_threshold)).min(1.0),
            evidence: format!(
                "surprisal outlier: z={:.1} corroborated at {} scales {:?}",
                c.max_z,
                c.scales.len(),
                c.scales
            ),
        })
        .collect();

    (
        findings,
        PerplexityReport {
            status: PerplexityStatus::Evaluated,
            scorer: scorer_name.to_string(),
            scales: stats,
            flagged: corroborated,
        },
    )
}

#[cfg(test)]
mod tests;
