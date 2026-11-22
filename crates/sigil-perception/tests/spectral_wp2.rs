//! RIC-MM-001 WP2: the spectral adapter reports inaudible-band energy and
//! predicts resampler aliasing; the kernel turns them into findings.
//!
//! CV-RIC-024 — inaudible band: structured content above the audible range is
//! a finding (shifts {24, 32, 40, 48} kHz at 96 kHz, {16, 20} kHz at 48 kHz,
//! several phrase spectra, with and without benign overlap).
//! CV-RIC-025 — alias prediction: the same files predict folding into the
//! 16 kHz baseband, where Whisper-class ASR listens.
//! CV-RIC-026 — benign high-rate controls do not trigger. These controls are
//! generated (speech-like, music-like with cymbal bursts, white-noise beds),
//! not recordings: the real-recording control set is still open.
//!
//! All signals are synthesized here, in Rust. The hidden payload is built the
//! way the specimen was: a band-limited speech-like signal moved up by
//! single-sideband shifting, which for a sum of partials is adding the shift
//! to every partial's frequency.

use sigil_core::{Vocab, policy::Policy};
use sigil_multimodal::perception::channel_provenance;
use sigil_multimodal::{
    ChannelKind, ModalInput, Modality, MultimodalEngine, MultimodalFindingKind,
};
use sigil_perception::spectral::{SpectralConfig, SpectralReport, analyze_spectrum};
use std::f64::consts::TAU;

const SECONDS: f64 = 1.5;
/// Hidden payload bandwidth, as in the specimen.
const PAYLOAD_BANDWIDTH_HZ: f64 = 7_500.0;

/// Formant layouts standing in for different phrases (Hz).
const PHRASES: [[f64; 3]; 3] = [
    [500.0, 1_500.0, 2_500.0],
    [700.0, 1_100.0, 2_600.0],
    [300.0, 2_200.0, 3_000.0],
];

/// A speech-like signal: a gliding fundamental, harmonics shaped by three
/// formants, syllable-rate amplitude modulation, every partial shifted by
/// `shift_hz` and kept below `top_hz`.
fn speech_like(rate: u32, formants: [f64; 3], f0: f64, shift_hz: f64, top_hz: f64) -> Vec<f64> {
    let n = (f64::from(rate) * SECONDS) as usize;
    let dt = 1.0 / f64::from(rate);
    let harmonics = (PAYLOAD_BANDWIDTH_HZ / f0) as usize;
    let mut phases = vec![0.0_f64; harmonics + 1];
    let mut out = vec![0.0; n];
    for (i, slot) in out.iter_mut().enumerate() {
        let t = i as f64 * dt;
        let fundamental = f0 * (1.0 + 0.15 * (TAU * 0.7 * t).sin());
        let syllables = (0.5 + 0.5 * (TAU * 4.0 * t).sin()).powi(2);
        let mut sample = 0.0;
        for (k, phase) in phases.iter_mut().enumerate().skip(1) {
            let base = k as f64 * fundamental;
            let freq = base + shift_hz;
            if base > PAYLOAD_BANDWIDTH_HZ || freq >= top_hz {
                continue;
            }
            *phase += TAU * freq * dt;
            let envelope: f64 = formants
                .iter()
                .map(|f| (-((base - f) / 250.0).powi(2)).exp())
                .sum::<f64>()
                + 0.02;
            sample += envelope * phase.sin();
        }
        *slot = sample * syllables;
    }
    out
}

/// Deterministic white noise (xorshift64*), zero mean, unit-ish variance.
fn white_noise(len: usize, seed: u64) -> Vec<f64> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            let bits = state.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11;
            (bits as f64 / (1_u64 << 53) as f64) * 2.0 - 1.0
        })
        .collect()
}

/// One-pole low-pass, used to roll noise off like a cymbal above ~10 kHz.
fn low_pass(signal: &[f64], rate: u32, cutoff_hz: f64) -> Vec<f64> {
    let alpha = 1.0 - (-TAU * cutoff_hz / f64::from(rate)).exp();
    let mut state = 0.0;
    signal
        .iter()
        .map(|x| {
            state += alpha * (x - state);
            state
        })
        .collect()
}

/// Music-like control: three notes with 1/k harmonic roll-off up to 15 kHz,
/// plus decaying noise bursts low-passed twice at 10 kHz (cymbal-like).
fn music_like(rate: u32) -> Vec<f64> {
    let n = (f64::from(rate) * SECONDS) as usize;
    let noise = low_pass(
        &low_pass(&white_noise(n, 7), rate, 10_000.0),
        rate,
        10_000.0,
    );
    (0..n)
        .map(|i| {
            let t = i as f64 / f64::from(rate);
            let notes: f64 = [220.0, 277.18, 329.63]
                .iter()
                .map(|f0| {
                    (1..=((15_000.0 / f0) as usize))
                        .map(|k| (TAU * f0 * k as f64 * t).sin() / k as f64)
                        .sum::<f64>()
                })
                .sum();
            let burst = (-((t * 4.0).fract()) * 12.0).exp();
            0.3 * notes + 3.0 * burst * noise[i]
        })
        .collect()
}

fn mix(parts: &[(&[f64], f64)]) -> Vec<f32> {
    let len = parts.iter().map(|(s, _)| s.len()).min().unwrap_or(0);
    let mixed: Vec<f64> = (0..len)
        .map(|i| parts.iter().map(|(s, g)| s[i] * g).sum())
        .collect();
    let peak = mixed.iter().fold(0.0_f64, |m, x| m.max(x.abs())).max(1e-12);
    mixed.iter().map(|x| (x / peak * 0.9) as f32).collect()
}

fn report(samples: &[f32], rate: u32) -> SpectralReport {
    analyze_spectrum(samples, rate, &SpectralConfig::default(), "wp2").expect("spectrum")
}

fn kernel_kinds(report: &SpectralReport) -> Vec<MultimodalFindingKind> {
    let engine =
        MultimodalEngine::new(Policy::default(), Vocab::tiktoken("cl100k_base")).expect("engine");
    let assessment = engine
        .analyze(&[ModalInput {
            modality: Modality::Audio,
            content: serde_json::to_string(report).expect("json"),
            provenance: channel_provenance(ChannelKind::Metadata),
            source_id: Some("wp2:spectral".to_string()),
            derived_from: Some("wp2".to_string()),
            channel: None,
            consumed: None,
        }])
        .expect("analyze");
    assessment
        .audio
        .iter()
        .flat_map(|m| m.findings.iter().map(|f| f.kind))
        .collect()
}

/// Hidden payload placement for a shift at a rate: the band [shift,
/// shift + bandwidth], truncated at 0.97 × Nyquist. A shift at or above
/// Nyquist is placed as a lower sideband ending just below Nyquist.
fn hidden_payload(rate: u32, shift_hz: f64, phrase: usize) -> Vec<f64> {
    let nyquist = f64::from(rate) / 2.0;
    let top = nyquist * 0.97;
    let formants = PHRASES[phrase % PHRASES.len()];
    let f0 = 110.0 + 40.0 * phrase as f64;
    if shift_hz + 1_000.0 < top {
        speech_like(rate, formants, f0, shift_hz, top)
    } else {
        speech_like(rate, formants, f0, top - PAYLOAD_BANDWIDTH_HZ, top)
    }
}

struct Case {
    rate: u32,
    shift_hz: f64,
    phrase: usize,
    overlap_gain: f64,
}

fn attack_cases() -> Vec<Case> {
    let mut cases = Vec::new();
    for (rate, shifts) in [
        (96_000, vec![24_000.0, 32_000.0, 40_000.0, 48_000.0]),
        (48_000, vec![16_000.0, 20_000.0]),
    ] {
        for (i, shift_hz) in shifts.into_iter().enumerate() {
            for overlap_gain in [0.0, 1.0] {
                cases.push(Case {
                    rate,
                    shift_hz,
                    phrase: i,
                    overlap_gain,
                });
            }
        }
    }
    cases
}

fn attack(case: &Case) -> Vec<f32> {
    let benign = speech_like(
        case.rate,
        PHRASES[(case.phrase + 1) % PHRASES.len()],
        140.0,
        0.0,
        8_000.0,
    );
    let hidden = hidden_payload(case.rate, case.shift_hz, case.phrase);
    mix(&[(&hidden, 1.0), (&benign, case.overlap_gain)])
}

#[test]
fn cv_ric_024_inaudible_band_fact_and_finding_across_the_family() {
    for case in attack_cases().iter().filter(|c| c.rate == 96_000) {
        let report = report(&attack(case), case.rate);
        let band = report
            .inaudible_band
            .as_ref()
            .expect("96 kHz files report the band");
        assert!(
            band.energy_fraction > 0.2 && band.flatness < 0.25,
            "shift {} overlap {}: {band:?}",
            case.shift_hz,
            case.overlap_gain
        );
        assert!(
            kernel_kinds(&report).contains(&MultimodalFindingKind::InaudibleBandEnergy),
            "shift {} overlap {}",
            case.shift_hz,
            case.overlap_gain
        );
    }
}

#[test]
fn cv_ric_025_alias_prediction_into_the_16k_baseband_across_the_family() {
    for case in attack_cases() {
        let report = report(&attack(&case), case.rate);
        let at_16k = report
            .alias_predictions
            .iter()
            .find(|p| p.target_rate_hz == 16_000)
            .expect("16 kHz prediction");
        assert!(
            at_16k.hidden_folding_fraction > 0.2 && at_16k.alias_high_hz <= 8_000.0,
            "rate {} shift {} overlap {}: {at_16k:?}",
            case.rate,
            case.shift_hz,
            case.overlap_gain
        );
        assert!(
            kernel_kinds(&report).contains(&MultimodalFindingKind::ResamplerAliasing),
            "rate {} shift {} overlap {}",
            case.rate,
            case.shift_hz,
            case.overlap_gain
        );
    }
}

#[test]
fn cv_ric_026_generated_benign_high_rate_controls_do_not_trigger() {
    let hidden_kinds = [
        MultimodalFindingKind::InaudibleBandEnergy,
        MultimodalFindingKind::ResamplerAliasing,
        MultimodalFindingKind::AudioSteganography,
    ];
    for rate in [48_000_u32, 96_000] {
        let n = (f64::from(rate) * SECONDS) as usize;
        let speech = speech_like(rate, PHRASES[0], 120.0, 0.0, 8_000.0);
        let noise = white_noise(n, u64::from(rate));
        let controls: [(&str, Vec<f32>); 4] = [
            ("speech", mix(&[(&speech, 1.0)])),
            ("music with cymbal bursts", mix(&[(&music_like(rate), 1.0)])),
            (
                "speech over a white-noise bed",
                mix(&[(&speech, 1.0), (&noise, 0.5)]),
            ),
            // Loud enough that the energy gate alone would fire: only the
            // flatness gate keeps a noise bed from reading as a channel.
            (
                "speech over a loud white-noise bed",
                mix(&[(&speech, 1.0), (&noise, 3.0)]),
            ),
        ];
        for (name, samples) in controls {
            let report = report(&samples, rate);
            let kinds = kernel_kinds(&report);
            assert!(
                !kinds.iter().any(|k| hidden_kinds.contains(k)),
                "{name} at {rate} Hz triggered {kinds:?}: {:?} {:?}",
                report.inaudible_band,
                report.alias_predictions
            );
            assert!(
                !kinds.contains(&MultimodalFindingKind::SubliminalAudio),
                "{name} at {rate} Hz: sub-audible false positive"
            );
        }
    }
}

#[test]
fn masking_noise_over_the_hidden_band_does_not_clear_the_finding() {
    // Hidden speech at +32 kHz plus white noise high-passed above 20 kHz at
    // several levels: whole-band flatness rises with the noise, the
    // sub-band structure test must still see the payload.
    let rate = 96_000;
    let n = (f64::from(rate) * SECONDS) as usize;
    let hidden = hidden_payload(rate, 32_000.0, 0);
    let raw = white_noise(n, 11);
    let low = low_pass(&raw, rate, 20_000.0);
    let ultrasonic: Vec<f64> = raw.iter().zip(&low).map(|(x, l)| x - l).collect();
    for gain in [0.5, 1.0, 2.0] {
        let report = report(&mix(&[(&hidden, 1.0), (&ultrasonic, gain)]), rate);
        let kinds = kernel_kinds(&report);
        assert!(
            kinds.contains(&MultimodalFindingKind::InaudibleBandEnergy)
                && kinds.contains(&MultimodalFindingKind::ResamplerAliasing),
            "noise gain {gain}: {kinds:?} {:?}",
            report.inaudible_band
        );
    }
}

/// Noise confined (approximately: cascaded one-pole filters) to [low, high].
fn band_noise(len: usize, rate: u32, low_hz: f64, high_hz: f64, seed: u64) -> Vec<f64> {
    let raw = white_noise(len, seed);
    let cascade = |cutoff| (0..4).fold(raw.clone(), |s, _| low_pass(&s, rate, cutoff));
    let (upper, lower) = (cascade(high_hz), cascade(low_hz));
    upper.iter().zip(&lower).map(|(u, l)| u - l).collect()
}

#[test]
fn noise_beside_the_payload_at_moderate_level_does_not_hide_it() {
    // Payload at +32 kHz; noise filtered to 20-30.5 kHz (one-pole cascade, so
    // it leaks into the payload's slices). Regression at the level the
    // structure test still resolves. Known limit, measured 2026-11-21: from
    // gain 12 the leaked noise makes every slice flat and nothing fires; see
    // the module docs of sigil-multimodal detect/spectral.rs.
    let rate = 96_000;
    let n = (f64::from(rate) * SECONDS) as usize;
    let hidden = hidden_payload(rate, 32_000.0, 0);
    let noise = band_noise(n, rate, 20_000.0, 30_500.0, 21);
    for gain in [4.0, 8.0] {
        let report = report(&mix(&[(&hidden, 1.0), (&noise, gain)]), rate);
        let band = report.inaudible_band.as_ref().expect("band");
        let payload_share: f32 = band
            .subbands
            .iter()
            .filter(|s| s.low_hz >= 31_000.0)
            .map(|s| s.energy_fraction)
            .sum();
        assert!(
            payload_share > 0.05,
            "gain {gain}: payload share {payload_share}"
        );
        let kinds = kernel_kinds(&report);
        assert!(
            kinds.contains(&MultimodalFindingKind::InaudibleBandEnergy),
            "gain {gain}: {kinds:?} payload share {payload_share} {:?}",
            band.subbands
        );
    }
}

#[test]
fn audible_content_that_folds_is_reported_but_not_a_finding() {
    // Music folds into a 16 kHz baseband too (its harmonics reach 15 kHz),
    // but the listener hears that content: the fact is there, the finding is
    // not.
    let report = report(&mix(&[(&music_like(48_000), 1.0)]), 48_000);
    let at_16k = report
        .alias_predictions
        .iter()
        .find(|p| p.target_rate_hz == 16_000)
        .expect("16k");
    assert!(at_16k.folding_fraction > at_16k.hidden_folding_fraction);
    assert!(!kernel_kinds(&report).contains(&MultimodalFindingKind::ResamplerAliasing));
}

#[test]
fn rates_too_low_for_the_band_report_no_inaudible_fact() {
    let speech = speech_like(16_000, PHRASES[0], 120.0, 0.0, 7_900.0);
    let report = report(&mix(&[(&speech, 1.0)]), 16_000);
    assert!(report.inaudible_band.is_none());
    assert!(
        report.alias_predictions.is_empty(),
        "no target rate below 16 kHz"
    );
}
