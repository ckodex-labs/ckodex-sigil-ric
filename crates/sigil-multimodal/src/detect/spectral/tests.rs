//! Each kernel rule over spectral facts, including the fail-closed defaults.

use super::{HIDDEN_ENERGY_FRACTION_MIN, STRUCTURED_FLATNESS_MAX, spectral_findings};
use crate::types::MultimodalFindingKind;
use serde_json::json;
use sigil_core::types::Severity;

fn kinds(report: serde_json::Value) -> Vec<MultimodalFindingKind> {
    spectral_findings(&report.to_string(), Severity::None)
        .into_iter()
        .map(|f| f.kind)
        .collect()
}

fn with_band(fraction: f64, flatness: f64) -> serde_json::Value {
    json!({ "inaudible_band": {
        "low_hz": 20000.0, "high_hz": 48000.0, "energy_fraction": fraction,
        "peak_hz": 32250.0, "flatness": flatness } })
}

fn with_alias(fraction: f64, flatness: f64) -> serde_json::Value {
    json!({ "alias_predictions": [{
        "target_rate_hz": 16000, "hidden_origin_hz": 16000.0, "folding_fraction": fraction,
        "hidden_folding_fraction": fraction, "hidden_flatness": flatness,
        "alias_low_hz": 62.5, "alias_high_hz": 1375.0 }] })
}

#[test]
fn structured_inaudible_energy_is_a_finding() {
    assert!(kinds(with_band(0.73, 1e-6)).contains(&MultimodalFindingKind::InaudibleBandEnergy));
}

#[test]
fn inaudible_noise_is_not_a_finding() {
    assert!(kinds(with_band(0.73, STRUCTURED_FLATNESS_MAX + 0.4)).is_empty());
}

#[test]
fn faint_inaudible_structure_is_not_a_finding() {
    assert!(kinds(with_band(HIDDEN_ENERGY_FRACTION_MIN / 2.0, 1e-6)).is_empty());
}

#[test]
fn threshold_is_inclusive_at_the_minimum_fraction() {
    assert!(!kinds(with_band(HIDDEN_ENERGY_FRACTION_MIN, 1e-6)).is_empty());
}

#[test]
fn structured_hidden_folding_is_a_resampler_aliasing_finding() {
    let findings = spectral_findings(&with_alias(0.73, 1e-6).to_string(), Severity::None);
    let aliasing = findings
        .iter()
        .find(|f| f.kind == MultimodalFindingKind::ResamplerAliasing)
        .expect("aliasing finding");
    assert!(aliasing.detail.contains("16000 Hz"), "{}", aliasing.detail);
}

#[test]
fn noise_that_folds_is_not_a_finding() {
    assert!(kinds(with_alias(0.73, 0.99)).is_empty());
}

#[test]
fn flat_aggregate_high_band_is_a_noise_floor() {
    let report = json!({ "steganography_findings": [{
        "label": "high_frequency_anomaly", "low_hz": 46000.0, "high_hz": 48000.0,
        "energy": 1.0, "fraction_of_total": 0.06, "flatness": 0.99 }] });
    assert!(kinds(report).is_empty());
}

#[test]
fn a_band_without_flatness_still_counts() {
    // Missing evidence never clears a band: older reports keep their finding.
    let report = json!({ "steganography_findings": [{
        "label": "high_frequency_anomaly", "low_hz": 46000.0, "high_hz": 48000.0,
        "energy": 1.0, "fraction_of_total": 0.06 }] });
    assert_eq!(
        kinds(report),
        vec![MultimodalFindingKind::AudioSteganography]
    );
}

#[test]
fn narrowband_peaks_are_never_cleared_by_flatness() {
    let report = json!({ "steganography_findings": [{
        "label": "narrowband_high_freq_peak", "low_hz": 46000.0, "high_hz": 48000.0,
        "energy": 1.0, "fraction_of_total": 0.01, "flatness": 0.99 }] });
    assert_eq!(
        kinds(report),
        vec![MultimodalFindingKind::AudioSteganography]
    );
}

#[test]
fn reports_without_wp2_facts_yield_no_wp2_findings() {
    assert!(kinds(json!({ "subliminal_findings": [], "steganography_findings": [] })).is_empty());
    assert!(kinds(json!("not a report")).is_empty());
}

fn sliced(slices: &[(f64, f64)]) -> serde_json::Value {
    let subbands: Vec<_> = slices
        .iter()
        .map(|(fraction, flatness)| {
            json!({ "low_hz": 0.0, "high_hz": 1.0,
            "energy_fraction": fraction, "flatness": flatness })
        })
        .collect();
    json!({ "inaudible_band": { "low_hz": 20000.0, "high_hz": 48000.0,
        "energy_fraction": 0.9, "peak_hz": 25000.0, "flatness": 0.99, "subbands": subbands } })
}

#[test]
fn structured_slices_count_even_when_noise_dominates_the_band() {
    // Region-level flatness says noise; three structured slices together hold
    // 9 % of the file, each under the 5 % minimum on its own.
    let report = sliced(&[
        (0.4, 0.99),
        (0.4, 0.98),
        (0.03, 0.1),
        (0.03, 0.05),
        (0.03, 0.2),
    ]);
    assert!(kinds(report).contains(&MultimodalFindingKind::InaudibleBandEnergy));
}

#[test]
fn noise_only_slices_are_not_a_finding() {
    assert!(kinds(sliced(&[(0.3, 0.99), (0.3, 0.97), (0.3, 0.95)])).is_empty());
}

#[test]
fn faint_structured_slices_are_not_a_finding() {
    assert!(kinds(sliced(&[(0.5, 0.99), (0.01, 0.1), (0.02, 0.1)])).is_empty());
}

#[test]
fn an_unreadable_slice_fails_closed() {
    let mut report = sliced(&[(0.5, 0.99)]);
    report["inaudible_band"]["subbands"][0]["flatness"] = serde_json::Value::Null;
    assert!(kinds(report).contains(&MultimodalFindingKind::InaudibleBandEnergy));
}

#[test]
fn a_structured_slice_keeps_the_aggregate_high_band_finding() {
    let report = json!({ "steganography_findings": [{
        "label": "high_frequency_anomaly", "low_hz": 46000.0, "high_hz": 48000.0,
        "energy": 1.0, "fraction_of_total": 0.06, "flatness": 0.99,
        "subbands": [{ "low_hz": 46000.0, "high_hz": 47000.0, "energy_fraction": 0.05, "flatness": 0.99 },
                     { "low_hz": 47000.0, "high_hz": 48000.0, "energy_fraction": 0.002, "flatness": 0.05 }] }] });
    assert_eq!(
        kinds(report),
        vec![MultimodalFindingKind::AudioSteganography]
    );
}

#[test]
fn unreadable_inaudible_facts_fail_closed() {
    // NaN in the samples poisons the spectrum and serializes as null.
    let report = json!({ "inaudible_band": {
        "low_hz": 20000.0, "high_hz": 48000.0, "energy_fraction": null,
        "peak_hz": 0.0, "flatness": null } });
    assert!(kinds(report).contains(&MultimodalFindingKind::InaudibleBandEnergy));
    let alias = json!({ "alias_predictions": [{ "target_rate_hz": 16000,
        "hidden_folding_fraction": null, "hidden_flatness": 0.1 }] });
    assert!(kinds(alias).contains(&MultimodalFindingKind::ResamplerAliasing));
}
