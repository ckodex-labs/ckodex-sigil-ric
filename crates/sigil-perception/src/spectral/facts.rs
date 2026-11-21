//! Model-side resampling facts (RIC-MM-001 WP2).
//!
//! A model pipeline resamples audio to its own rate (Whisper: 16 kHz) before
//! it hears anything. Energy a human cannot hear (above ~20 kHz) is removed
//! by a filtered resampler but folds into the baseband under decimation
//! without a low-pass filter. These facts describe that physics from the
//! aggregated spectrum alone; they need no ASR and no resampler choice.
//! Severity is the kernel's call (`sigil-multimodal`), never this module's.

use serde::{Deserialize, Serialize};

/// Smallest bin energy, relative to the region's mean, admitted to the
/// flatness log-mean. Keeps exact-zero bins (digital silence) finite without
/// letting them dominate.
const FLATNESS_FLOOR: f64 = 1e-9;
/// A bin contributes to the reported alias landing range when it holds at
/// least this share of the strongest folding bin's energy; weaker bins are
/// noise floor, not content.
const ALIAS_RANGE_FLOOR: f64 = 0.01;

/// Energy above the audible band, for sample rates that can carry it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InaudibleBand {
    pub low_hz: f32,
    pub high_hz: f32,
    /// Share of the file's total spectral energy inside the band.
    pub energy_fraction: f32,
    /// Strongest frequency inside the band.
    pub peak_hz: f32,
    /// Spectral flatness (geometric / arithmetic mean of bin energies) over
    /// the band: ≈1 for white noise, far below for structured content such as
    /// shifted speech.
    pub flatness: f32,
}

/// What unfiltered decimation to `target_rate_hz` would fold into baseband.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AliasPrediction {
    pub target_rate_hz: u32,
    /// Share of total energy above the target's Nyquist (all of it folds).
    pub folding_fraction: f32,
    /// Lower edge of the region treated as hidden from the listener.
    pub hidden_origin_hz: f32,
    /// Share of total energy that folds and originates above
    /// `hidden_origin_hz`: content the listener does not hear but the model
    /// will, after unfiltered resampling.
    pub hidden_folding_fraction: f32,
    /// Spectral flatness of that hidden folding region.
    pub hidden_flatness: f32,
    /// Baseband range the hidden content lands in after folding (bins holding
    /// at least 1 % of the strongest folding bin's energy).
    pub alias_low_hz: f32,
    pub alias_high_hz: f32,
}

/// The run's aggregated power spectrum: per-bin energy summed over windows.
pub(super) struct Spectrum<'a> {
    pub bins: &'a [f64],
    pub bin_hz: f64,
    pub total: f64,
}

impl Spectrum<'_> {
    fn freq(&self, bin: usize) -> f64 {
        bin as f64 * self.bin_hz
    }

    /// Bins whose centre frequency lies strictly above `low_hz`.
    fn above(&self, low_hz: f64) -> impl Iterator<Item = (usize, f64)> + '_ {
        self.bins
            .iter()
            .enumerate()
            .filter(move |(bin, _)| self.freq(*bin) > low_hz)
            .map(|(bin, energy)| (bin, *energy))
    }
}

/// The inaudible-band fact, when the sample rate can represent the band.
pub(super) fn inaudible_band(
    spectrum: &Spectrum<'_>,
    sample_rate: u32,
    cutoff_hz: f32,
    min_sample_rate_hz: u32,
) -> Option<InaudibleBand> {
    let nyquist = f64::from(sample_rate) / 2.0;
    if sample_rate <= min_sample_rate_hz || nyquist <= f64::from(cutoff_hz) {
        return None;
    }
    let band: Vec<(usize, f64)> = spectrum.above(f64::from(cutoff_hz)).collect();
    let energy: f64 = band.iter().map(|(_, e)| e).sum();
    let peak_bin = band
        .iter()
        .max_by(|a, b| a.1.total_cmp(&b.1))
        .map_or(0, |(bin, _)| *bin);
    Some(InaudibleBand {
        low_hz: cutoff_hz,
        high_hz: nyquist as f32,
        energy_fraction: (energy / spectrum.total) as f32,
        peak_hz: spectrum.freq(peak_bin) as f32,
        flatness: flatness(band.iter().map(|(_, e)| *e)),
    })
}

/// One prediction per target rate below the source rate.
pub(super) fn alias_predictions(
    spectrum: &Spectrum<'_>,
    sample_rate: u32,
    origin_hz: f32,
    targets_hz: &[u32],
) -> Vec<AliasPrediction> {
    targets_hz
        .iter()
        .copied()
        .filter(|target| *target < sample_rate)
        .map(|target| predict(spectrum, target, f64::from(origin_hz)))
        .collect()
}

fn predict(spectrum: &Spectrum<'_>, target_hz: u32, origin_hz: f64) -> AliasPrediction {
    let target = f64::from(target_hz);
    let target_nyquist = target / 2.0;
    let folding: f64 = spectrum.above(target_nyquist).map(|(_, e)| e).sum();
    let hidden: Vec<(usize, f64)> = spectrum.above(target_nyquist.max(origin_hz)).collect();
    let hidden_energy: f64 = hidden.iter().map(|(_, e)| e).sum();
    let strongest = hidden.iter().map(|(_, e)| *e).fold(0.0, f64::max);
    let landing = hidden
        .iter()
        .filter(|(_, e)| strongest > 0.0 && *e >= strongest * ALIAS_RANGE_FLOOR)
        .map(|(bin, _)| fold(spectrum.freq(*bin), target));
    let (low, high) = landing.fold((f64::INFINITY, 0.0_f64), |(lo, hi), f| {
        (lo.min(f), hi.max(f))
    });
    AliasPrediction {
        target_rate_hz: target_hz,
        hidden_origin_hz: origin_hz as f32,
        folding_fraction: (folding / spectrum.total) as f32,
        hidden_folding_fraction: (hidden_energy / spectrum.total) as f32,
        hidden_flatness: flatness(hidden.iter().map(|(_, e)| *e)),
        alias_low_hz: if low.is_finite() { low as f32 } else { 0.0 },
        alias_high_hz: high as f32,
    }
}

/// Where a component at `freq` lands after sampling at `rate` with no
/// anti-alias filter: reduce modulo the rate, then mirror into [0, rate/2].
pub(super) fn fold(freq: f64, rate: f64) -> f64 {
    let reduced = freq.rem_euclid(rate);
    if reduced <= rate / 2.0 {
        reduced
    } else {
        rate - reduced
    }
}

/// Spectral flatness (Wiener entropy) of a set of bin energies; 0 for an
/// empty or all-zero set.
pub(super) fn flatness(energies: impl Iterator<Item = f64> + Clone) -> f32 {
    let count = energies.clone().count();
    let mean = energies.clone().sum::<f64>() / count.max(1) as f64;
    if count == 0 || mean <= 0.0 {
        return 0.0;
    }
    let floor = mean * FLATNESS_FLOOR;
    let log_mean = energies.map(|e| e.max(floor).ln()).sum::<f64>() / count as f64;
    (log_mean.exp() / mean) as f32
}

#[cfg(test)]
mod tests {
    use super::{flatness, fold};

    #[test]
    fn folding_follows_the_sampling_theorem() {
        // 32.25 kHz sampled at 16 kHz: 32.25 mod 16 = 0.25 kHz.
        assert!((fold(32_250.0, 16_000.0) - 250.0).abs() < 1e-9);
        // 15 kHz at 16 kHz mirrors to 1 kHz.
        assert!((fold(15_000.0, 16_000.0) - 1_000.0).abs() < 1e-9);
        // Below the target Nyquist nothing moves.
        assert!((fold(7_000.0, 16_000.0) - 7_000.0).abs() < 1e-9);
        // 39.5 kHz at 24 kHz: 15.5 kHz mirrors to 8.5 kHz.
        assert!((fold(39_500.0, 24_000.0) - 8_500.0).abs() < 1e-9);
    }

    #[test]
    fn flatness_separates_noise_from_peaks() {
        let flat = vec![1.0_f64; 64];
        assert!((flatness(flat.iter().copied()) - 1.0).abs() < 1e-6);
        let mut peaky = vec![1e-6_f64; 64];
        peaky[10] = 100.0;
        assert!(flatness(peaky.iter().copied()) < 0.1);
        assert_eq!(flatness(std::iter::empty()), 0.0);
    }
}
