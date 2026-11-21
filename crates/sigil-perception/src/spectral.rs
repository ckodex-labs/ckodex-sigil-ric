//! Low-frequency deception detection for audio artifacts.
//!
//! Two detection modes:
//!
//! 1. **Subliminal audio detection**: identifies spectral energy in
//!    sub-audible frequency bands (below ~20 Hz) that could carry hidden
//!    commands transcribable by ASR but inaudible to humans.
//!
//! 2. **Audio steganography detection**: identifies anomalous spectral
//!    patterns consistent with covert-channel embedding — specifically,
//!    unusually high energy in narrow high-frequency bands (near
//!    Nyquist) or energy in bands that should be silent given the
//!    dominant signal.
//!
//! Both detectors use real-valued FFT (`realfft` / `rustfft`, pure Rust).
//! The detectors produce `SpectralReport` records consumed by the
//! kernel — they do not set verdicts themselves (Option B: kernel
//! judges, adapters report facts).
//!
//! **Threat model**: CVE-2026-34760 (vLLM) demonstrated that unweighted
//! multi-channel downmixing allows hidden voice commands via physically
//! inaudible channels. Use `downmix_to_mono_weighted` (ITU-R BS.775-4)
//! instead of `downmix_to_mono` (simple average) for multi-channel audio
//! with >2 channels. SWhisper (USENIX Security 2026) demonstrated
//! near-ultrasonic jailbreaks against speech-driven LLMs, confirming
//! both sub-audible and ultrasonic bands are real attack vectors.
//!
//! In addition to band-energy checks, each window's per-bin spectrum is
//! examined for **narrowband peaks** inside the near-Nyquist band: a
//! single FFT bin holding a large share of a window's energy in a band
//! that is normally near-silent is a covert-tone signature even when the
//! aggregate band fraction stays under threshold (frequency-hopping
//! steganography, Yang & Huang 2018). When the peak lands on several
//! distinct bins across windows the finding is reported as
//! `frequency_hopping`. Per-bin magnitudes come from the windowed FFT
//! already computed, so no Goertzel pass is needed — the per-frequency
//! sensitivity is equivalent.
//!
//! **Remaining limitations**:
//! - Spectrogram-domain patterns below the narrowband-peak threshold
//!   (spread-spectrum, echo hiding) still evade detection; a
//!   spectrogram-based deep residual network (Spec-ResNet, 2019) would
//!   be needed for that class.
//! - This is a spectral anomaly detector, not a general-purpose audio
//!   steganalysis system.

mod downmix;

use realfft::RealFftPlanner;
use rustfft::num_complex::Complex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

pub use downmix::{
    downmix_to_mono, downmix_to_mono_f32, downmix_to_mono_weighted, downmix_to_mono_weighted_f32,
    normalization_factor, pcm_to_f32,
};

/// Frequency band of interest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FreqBand {
    pub label: String,
    pub low_hz: f32,
    pub high_hz: f32,
    pub energy: f32,
    pub fraction_of_total: f32,
}

/// Result of spectral analysis.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SpectralReport {
    /// SHA-384 over the raw artifact bytes.
    pub artifact_digest: String,
    pub sample_rate: u32,
    pub channels: u16,
    pub total_samples: usize,
    /// Number of FFT windows analyzed.
    pub windows_analyzed: usize,
    /// Total spectral energy across all bins and windows.
    pub total_energy: f32,
    /// Bands with anomalous energy (aggregated across windows).
    pub anomalous_bands: Vec<FreqBand>,
    /// Subliminal (sub-audible) findings.
    pub subliminal_findings: Vec<FreqBand>,
    /// Steganography (covert-channel) findings.
    pub steganography_findings: Vec<FreqBand>,
    /// Dominant frequency (Hz) — the strongest spectral peak.
    pub dominant_freq_hz: f32,
}

/// Configuration for spectral analysis.
#[derive(Clone, Debug)]
pub struct SpectralConfig {
    /// FFT window size (must be power of 2). Larger = better frequency
    /// resolution, slower computation.
    pub fft_size: usize,
    /// Overlap between consecutive windows (0.0 = no overlap, 0.5 = 50%).
    pub window_overlap: f32,
    /// Sub-audible threshold: frequencies below this are "subliminal".
    pub subliminal_cutoff_hz: f32,
    /// Fraction of total energy in a sub-audible band to flag as subliminal.
    pub subliminal_energy_fraction: f32,
    /// High-frequency band width (Hz from Nyquist) to scan for steganography.
    pub stego_high_band_hz: f32,
    /// Fraction of total energy in the high band to flag as steganography.
    pub stego_energy_fraction: f32,
    /// Fraction of a window's energy held by a single high-band bin that
    /// flags a narrowband peak — catches covert tones whose aggregate
    /// band share stays under `stego_energy_fraction`.
    pub stego_peak_fraction: f32,
    /// Distinct high-band peak bins across windows that upgrades a
    /// narrowband-peak finding to `frequency_hopping`.
    pub stego_hop_min_bins: usize,
}

impl Default for SpectralConfig {
    fn default() -> Self {
        Self {
            fft_size: 1024,
            window_overlap: 0.5,
            subliminal_cutoff_hz: 20.0,
            subliminal_energy_fraction: 0.01,
            stego_high_band_hz: 2000.0,
            stego_energy_fraction: 0.05,
            stego_peak_fraction: 0.02,
            stego_hop_min_bins: 3,
        }
    }
}

/// Analyze a mono PCM signal (f32 samples, -1.0..1.0) and produce a
/// spectral report. Multi-channel audio should be downmixed to mono
/// before calling this.
///
/// Analyzes the **full signal** in overlapping Hann-windowed FFT
/// windows and aggregates findings across all windows. A finding is
/// reported if it appears in any window.
///
/// `artifact_digest` should be the SHA-384 hex digest of the raw
/// artifact bytes (computed by the caller).
///
/// Returns `None` if the signal is too short for the configured FFT size.
pub fn analyze_spectrum(
    samples: &[f32],
    sample_rate: u32,
    config: &SpectralConfig,
    artifact_digest: &str,
) -> Option<SpectralReport> {
    if samples.len() < config.fft_size || config.fft_size < 4 {
        return None;
    }
    let stats = accumulate_windows(samples, sample_rate, config)?;
    Some(build_report(
        &stats,
        samples.len(),
        sample_rate,
        config,
        artifact_digest,
    ))
}

/// Per-run accumulators for the windowed FFT pass.
struct WindowStats {
    windows_analyzed: usize,
    total_energy: f32,
    dominant_freq_hz: f32,
    dominant_energy: f32,
    has_subliminal: bool,
    has_stego: bool,
    subliminal_energy_sum: f32,
    high_band_energy_sum: f32,
    high_band_start_hz: f32,
    nyquist: f32,
    narrowband_peak_energy_sum: f32,
    high_band_peak_bins: Vec<usize>,
}

/// Run the windowed Hann FFT pass over `samples`, folding each window's
/// band energies into `WindowStats`. Returns `None` when no window
/// produced usable energy.
fn accumulate_windows(
    samples: &[f32],
    sample_rate: u32,
    config: &SpectralConfig,
) -> Option<WindowStats> {
    let fft_size = config.fft_size;
    let hop = ((fft_size as f32 * (1.0 - config.window_overlap)) as usize).max(1);
    let bin_hz = sample_rate as f32 / fft_size as f32;
    let nyquist = sample_rate as f32 / 2.0;

    let window: Vec<f32> = (0..fft_size)
        .map(|i| 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / fft_size as f32).cos()))
        .collect();

    let mut planner = RealFftPlanner::<f32>::new();
    let r2c = planner.plan_fft_forward(fft_size);

    let subliminal_bins = (config.subliminal_cutoff_hz / bin_hz).ceil() as usize;
    let high_band_start_hz = (nyquist - config.stego_high_band_hz).max(0.0);
    let high_band_start_bin = (high_band_start_hz / bin_hz).ceil() as usize;

    let mut stats = WindowStats {
        windows_analyzed: 0,
        total_energy: 0.0,
        dominant_freq_hz: 0.0,
        dominant_energy: 0.0,
        has_subliminal: false,
        has_stego: false,
        subliminal_energy_sum: 0.0,
        high_band_energy_sum: 0.0,
        high_band_start_hz,
        nyquist,
        narrowband_peak_energy_sum: 0.0,
        high_band_peak_bins: Vec::new(),
    };

    let mut input: Vec<f32> = vec![0.0; fft_size];
    let mut spectrum: Vec<Complex<f32>> = r2c.make_output_vec();

    let mut offset = 0usize;
    while offset + fft_size <= samples.len() {
        for i in 0..fft_size {
            input[i] = samples[offset + i] * window[i];
        }

        if r2c.process(&mut input, &mut spectrum).is_err() {
            // Skip this window on FFT failure rather than aborting the
            // entire analysis. RealFft errors are rare (invalid FFT size
            // is caught at construction), but a mid-loop failure should
            // not silently discard accumulated state.
            offset += hop;
            continue;
        }

        let energies: Vec<f32> = spectrum.iter().map(|c| c.norm().powi(2)).collect();
        let window_energy: f32 = energies.iter().sum();
        if window_energy <= 0.0 {
            offset += hop;
            continue;
        }

        fold_window(
            &mut stats,
            &energies,
            window_energy,
            bin_hz,
            subliminal_bins,
            high_band_start_bin,
            config,
        );
        offset += hop;
    }

    if stats.windows_analyzed == 0 || stats.total_energy <= 0.0 {
        return None;
    }
    Some(stats)
}

/// Fold one window's band energies into the running accumulators.
fn fold_window(
    stats: &mut WindowStats,
    energies: &[f32],
    window_energy: f32,
    bin_hz: f32,
    subliminal_bins: usize,
    high_band_start_bin: usize,
    config: &SpectralConfig,
) {
    stats.total_energy += window_energy;
    stats.windows_analyzed += 1;

    let (peak_bin, &peak_energy) = energies
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
        .unwrap_or((0, &0.0));
    if peak_energy > stats.dominant_energy {
        stats.dominant_energy = peak_energy;
        stats.dominant_freq_hz = peak_bin as f32 * bin_hz;
    }

    let sub_energy: f32 = energies[..subliminal_bins.min(energies.len())].iter().sum();
    stats.subliminal_energy_sum += sub_energy;
    if sub_energy / window_energy > config.subliminal_energy_fraction {
        stats.has_subliminal = true;
    }

    let high_energy: f32 = energies[high_band_start_bin.min(energies.len())..]
        .iter()
        .sum();
    stats.high_band_energy_sum += high_energy;
    if high_energy / window_energy > config.stego_energy_fraction {
        stats.has_stego = true;
    }

    // Narrowband-peak pass: the strongest bin inside the high band. A
    // single-bin tone above `stego_peak_fraction` is a covert-carrier
    // signature even when the aggregate band share stays low.
    let band = &energies[high_band_start_bin.min(energies.len())..];
    if let Some((peak_offset, &peak_energy)) = band
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal))
    {
        if peak_energy / window_energy > config.stego_peak_fraction {
            stats.narrowband_peak_energy_sum += peak_energy;
            stats
                .high_band_peak_bins
                .push(high_band_start_bin + peak_offset);
        }
    }
}

/// Assemble the `SpectralReport` from the accumulated window stats.
fn build_report(
    stats: &WindowStats,
    total_samples: usize,
    sample_rate: u32,
    config: &SpectralConfig,
    artifact_digest: &str,
) -> SpectralReport {
    let mut subliminal_findings = Vec::new();
    if stats.has_subliminal {
        subliminal_findings.push(FreqBand {
            label: "sub_audible".to_string(),
            low_hz: 0.0,
            high_hz: config.subliminal_cutoff_hz,
            energy: stats.subliminal_energy_sum,
            fraction_of_total: stats.subliminal_energy_sum / stats.total_energy,
        });
    }

    let mut steganography_findings = Vec::new();
    if stats.has_stego {
        steganography_findings.push(FreqBand {
            label: "high_frequency_anomaly".to_string(),
            low_hz: stats.high_band_start_hz,
            high_hz: stats.nyquist,
            energy: stats.high_band_energy_sum,
            fraction_of_total: stats.high_band_energy_sum / stats.total_energy,
        });
    }
    if !stats.high_band_peak_bins.is_empty() {
        let distinct_bins = stats
            .high_band_peak_bins
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len();
        let label = if distinct_bins >= config.stego_hop_min_bins {
            "frequency_hopping"
        } else {
            "narrowband_high_freq_peak"
        };
        steganography_findings.push(FreqBand {
            label: label.to_string(),
            low_hz: stats.high_band_start_hz,
            high_hz: stats.nyquist,
            energy: stats.narrowband_peak_energy_sum,
            fraction_of_total: stats.narrowband_peak_energy_sum / stats.total_energy,
        });
    }

    let mut anomalous_bands = Vec::new();
    anomalous_bands.extend(subliminal_findings.clone());
    anomalous_bands.extend(steganography_findings.clone());

    SpectralReport {
        artifact_digest: artifact_digest.to_string(),
        sample_rate,
        channels: 1,
        total_samples,
        windows_analyzed: stats.windows_analyzed,
        total_energy: stats.total_energy,
        anomalous_bands,
        subliminal_findings,
        steganography_findings,
        dominant_freq_hz: stats.dominant_freq_hz,
    }
}

/// Compute SHA-384 digest of raw bytes, hex-encoded.
pub fn artifact_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha384::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
