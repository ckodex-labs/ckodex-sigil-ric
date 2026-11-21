//! Kernel judgment over the spectral report `sigil-perception` emits.
//!
//! The adapter reports physics (band energies, flatness, alias landing); this
//! module decides what is a finding and how severe. A hidden audio channel
//! needs both properties: enough energy where the listener cannot hear it,
//! and structure (speech or tones, not noise). Energy alone would flag white
//! noise beds; structure alone would flag a faint ultrasonic pilot tone.

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
    if let Some(count) = non_empty_len(&report, "subliminal_findings") {
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
            bands.iter().filter(|band| structured_band(band)).count()
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

fn non_empty_len(report: &Value, key: &str) -> Option<usize> {
    report
        .get(key)?
        .as_array()
        .map(Vec::len)
        .filter(|len| *len > 0)
}

/// A reported steganography band counts unless it is the aggregate
/// high-band anomaly and its flatness marks it as a noise floor. A band with
/// no flatness (older reports) counts: missing evidence never clears a band.
fn structured_band(band: &Value) -> bool {
    let aggregate = band.get("label").and_then(Value::as_str) == Some("high_frequency_anomaly");
    !aggregate || number(band, "flatness").is_none_or(|flatness| flatness < STRUCTURED_FLATNESS_MAX)
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

fn inaudible_band(report: &Value, severity: Severity) -> Option<MultimodalFinding> {
    let band = report.get("inaudible_band")?;
    let fraction = number(band, "energy_fraction");
    let flatness = number(band, "flatness");
    if !hidden(fraction, flatness) {
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
