//! Kernel judgment over the spectral report `sigil-perception` emits.
//!
//! The adapter reports physics (band energies, flatness, alias landing); this
//! module decides what is a finding and how severe. A hidden audio channel
//! needs both properties: enough energy where the listener cannot hear it,
//! and structure (speech or tones, not noise). Energy alone would flag white
//! noise beds; structure alone would flag a faint ultrasonic pilot tone.
//!
//! Structure is judged per slice of each region: the adapter reports every
//! slice (range, share of the file's energy, flatness) and this module sums
//! the energy of structured slices, so noise in other slices cannot dilute a
//! payload's slices.
//!
//! Known limit: noise added *inside* the payload's own slices raises their
//! flatness too. On the generated +32 kHz payload with band noise leaking
//! into its slices, detection holds at noise gain 8 and is lost from gain 12
//! (crates/sigil-perception/tests/spectral_wp2.rs). Whether an ASR still
//! decodes the payload at that SNR is not measured. A temporal-modulation
//! test (speech carries a 2-8 Hz syllabic envelope, a noise bed does not) is
//! the candidate remedy and is not implemented.

use crate::types::{MultimodalFinding, MultimodalFindingKind};
use serde_json::Value;
use sigil_core::types::Severity;

/// Smallest share of the file's spectral energy that counts as a hidden
/// channel. Measured on the generated set in
/// `crates/sigil-perception/tests/spectral_wp2.rs` (2026-11-21): the attack
/// family holds at least 34 % in the hidden region, generated speech and music
/// at most 1.9 %. A white-noise bed is not separated by energy (4.5 % at
/// −6 dB, more when louder); the flatness gate below handles it.
pub const HIDDEN_ENERGY_FRACTION_MIN: f64 = 0.05;

/// Structure (lowest material sub-band flatness, reported by the adapter) at
/// or above this is noise-like. Measured on the same set: attack hidden
/// regions at most 0.24, white-noise beds and generated music at least 0.95. Aggregated over many FFT windows, white noise approaches 1;
/// band-limited speech shifted into an otherwise quiet band sits orders of
/// magnitude lower.
pub const STRUCTURED_FLATNESS_MAX: f64 = 0.5;

pub(crate) fn spectral_findings(content: &str, severity_floor: Severity) -> Vec<MultimodalFinding> {
    let Ok(report) = serde_json::from_str::<Value>(content) else {
        return Vec::new();
    };
    let severity = Severity::High.max(severity_floor);
    let mut findings = Vec::new();
    let subliminal = report
        .get("subliminal_findings")
        .and_then(Value::as_array)
        .map_or(0, |bands| {
            bands.iter().filter(|band| material(band)).count()
        });
    if subliminal > 0 {
        let count = subliminal;
        findings.push(MultimodalFinding {
            kind: MultimodalFindingKind::SubliminalAudio,
            severity,
            detail: format!("sub-audible spectral energy detected ({count} band(s))"),
        });
    }
    let structured_stego = report
        .get("steganography_findings")
        .and_then(Value::as_array)
        .map_or(0, |bands| {
            bands
                .iter()
                .filter(|band| material(band) && structured_band(band))
                .count()
        });
    if structured_stego > 0 {
        let count = structured_stego;
        findings.push(MultimodalFinding {
            kind: MultimodalFindingKind::AudioSteganography,
            severity,
            detail: format!("high-frequency spectral anomaly detected ({count} band(s))"),
        });
    }
    findings.extend(inaudible_band(&report, severity));
    findings.extend(resampler_aliasing(&report, severity));
    findings
}

/// A reported band holds enough of the file's energy to carry a hidden
/// channel: the same floor as the inaudible band (`HIDDEN_ENERGY_FRACTION_MIN`).
/// Measured on real speech (LibriSpeech clips from the sherpa-onnx test set,
/// 2026-11-23, RIC-MM-001 O-3): the sub-20 Hz band held 0.06 % and the
/// 6-8 kHz peak 0.0007 %, which flagged every benign recording HIGH before the
/// floor; the attack specimens hold at least 34 %. A band without a fraction
/// counts: missing evidence never clears a band.
fn material(band: &Value) -> bool {
    band.get("fraction_of_total")
        .and_then(Value::as_f64)
        .is_none_or(|fraction| fraction >= HIDDEN_ENERGY_FRACTION_MIN)
}

/// A reported steganography band counts unless it is the aggregate
/// high-band anomaly, no slice of it is structured AND its own flatness marks
/// it as a noise floor. A band without flatness counts: missing evidence
/// never clears a band.
fn structured_band(band: &Value) -> bool {
    let aggregate = band.get("label").and_then(Value::as_str) == Some("high_frequency_anomaly");
    if !aggregate {
        return true;
    }
    structured_energy(band.get("subbands")).is_some_and(|energy| energy > 0.0)
        || number(band, "flatness").is_none_or(|flatness| flatness < STRUCTURED_FLATNESS_MAX)
}

fn number(value: &Value, key: &str) -> Option<f64> {
    value.get(key)?.as_f64()
}

/// A hidden-content fact counts when it shows enough structured energy, or
/// when it is present but unreadable: a missing or non-finite value (NaN
/// samples serialize as null) is not evidence of absence, so it fails closed.
fn hidden(fraction: Option<f64>, flatness: Option<f64>) -> bool {
    match (fraction, flatness) {
        (Some(fraction), Some(flatness)) if fraction.is_finite() && flatness.is_finite() => {
            fraction >= HIDDEN_ENERGY_FRACTION_MIN && flatness < STRUCTURED_FLATNESS_MAX
        }
        _ => true,
    }
}

/// Energy (as a share of the file) in slices whose flatness marks them as
/// structured. `None` when the report has no slices (older reports); a slice
/// with an unreadable value counts as structured (fail closed).
fn structured_energy(slices: Option<&Value>) -> Option<f64> {
    let slices = slices?.as_array().filter(|s| !s.is_empty())?;
    Some(
        slices
            .iter()
            .map(|slice| {
                let fraction = number(slice, "energy_fraction").filter(|f| f.is_finite());
                let flatness = number(slice, "flatness").filter(|f| f.is_finite());
                match (fraction, flatness) {
                    (Some(_), Some(flatness)) if flatness >= STRUCTURED_FLATNESS_MAX => 0.0,
                    (Some(fraction), Some(_)) => fraction,
                    _ => f64::INFINITY,
                }
            })
            .sum(),
    )
}

/// Hidden when the structured slices together reach the energy minimum, or
/// when the region-level summary says so. The two rules are combined, never
/// substituted: either one alone has inputs it misses.
fn hidden_region(slices: Option<&Value>, fraction: Option<f64>, flatness: Option<f64>) -> bool {
    structured_energy(slices).is_some_and(|energy| energy >= HIDDEN_ENERGY_FRACTION_MIN)
        || hidden(fraction, flatness)
}

fn inaudible_band(report: &Value, severity: Severity) -> Option<MultimodalFinding> {
    let band = report.get("inaudible_band")?;
    let fraction = number(band, "energy_fraction");
    let flatness = number(band, "flatness");
    if !hidden_region(band.get("subbands"), fraction, flatness) {
        return None;
    }
    Some(MultimodalFinding {
        kind: MultimodalFindingKind::InaudibleBandEnergy,
        severity,
        detail: format!(
            "{:.1} % of spectral energy above {:.0} Hz, peak {:.0} Hz, structured (flatness {:.2e})",
            fraction.unwrap_or_default() * 100.0,
            number(band, "low_hz").unwrap_or_default(),
            number(band, "peak_hz").unwrap_or_default(),
            flatness.unwrap_or_default(),
        ),
    })
}

fn resampler_aliasing(report: &Value, severity: Severity) -> Option<MultimodalFinding> {
    let folds: Vec<String> = report
        .get("alias_predictions")?
        .as_array()?
        .iter()
        .filter(|p| {
            hidden(
                number(p, "hidden_folding_fraction"),
                number(p, "hidden_flatness"),
            )
        })
        .map(|p| {
            format!(
                "{:.0} Hz: {:.1} % lands at {:.0}-{:.0} Hz",
                number(p, "target_rate_hz").unwrap_or_default(),
                number(p, "hidden_folding_fraction").unwrap_or_default() * 100.0,
                number(p, "alias_low_hz").unwrap_or_default(),
                number(p, "alias_high_hz").unwrap_or_default(),
            )
        })
        .collect();
    if folds.is_empty() {
        return None;
    }
    Some(MultimodalFinding {
        kind: MultimodalFindingKind::ResamplerAliasing,
        severity,
        detail: format!(
            "structured content the listener does not hear folds into baseband under unfiltered resampling ({})",
            folds.join("; ")
        ),
    })
}

#[cfg(test)]
mod tests;
