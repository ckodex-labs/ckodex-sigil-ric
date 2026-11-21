//! Sub-audible (infrasound) energy at a resolution that can see it.
//!
//! The main FFT is sized for speech-band detail (1024 points): at 96 kHz a
//! bin spans 93.75 Hz, so a "0–20 Hz band" would be the DC bin alone, which
//! collects the DC offset and the leakage of ordinary voice fundamentals.
//! This pass uses its own FFT size so that a bin is at most a quarter of the
//! cutoff, excludes DC (an offset is not infrasound), and skips near-silent
//! windows whose ratios are meaningless.

use realfft::RealFftPlanner;

use super::SpectralConfig;

/// Bins per cutoff: four bins below 20 Hz give at most 5 Hz resolution.
const BINS_PER_CUTOFF: f32 = 4.0;

/// Outcome of the sub-audible pass.
pub(super) struct SubAudible {
    /// Some window above the energy floor exceeded the sub-audible fraction.
    pub flagged: bool,
    /// Sub-audible (DC excluded) energy summed over windows.
    pub energy: f32,
    /// Share of the pass's total energy that is sub-audible.
    pub fraction: f32,
}

/// Runs the pass, or returns `None` when the signal is too short to resolve
/// the cutoff (a 20 Hz component needs a window of several of its periods).
pub(super) fn analyze(
    samples: &[f32],
    sample_rate: u32,
    config: &SpectralConfig,
) -> Option<SubAudible> {
    let wanted =
        (BINS_PER_CUTOFF * sample_rate as f32 / config.subliminal_cutoff_hz).ceil() as usize;
    let fft_size = wanted
        .next_power_of_two()
        .min(prev_power_of_two(samples.len()));
    let bin_hz = sample_rate as f32 / fft_size as f32;
    let sub_bins = (config.subliminal_cutoff_hz / bin_hz).floor() as usize;
    if fft_size < 4 || sub_bins == 0 {
        return None;
    }
    let windows = window_energies(samples, fft_size, sub_bins, config.window_overlap)?;
    let total: f32 = windows.iter().map(|(e, _)| e).sum();
    let energy: f32 = windows.iter().map(|(_, s)| s).sum();
    // Median, not mean: one loud burst must not lift the floor over a real
    // infrasound window.
    let floor = median_energy(&windows) * config.subliminal_min_window_energy_ratio;
    let flagged = windows
        .iter()
        .any(|(e, s)| *e >= floor && *s / *e > config.subliminal_energy_fraction);
    Some(SubAudible {
        flagged,
        energy,
        fraction: if total > 0.0 { energy / total } else { 0.0 },
    })
}

/// (window energy, sub-audible energy in bins 1..=sub_bins) per window.
fn window_energies(
    samples: &[f32],
    fft_size: usize,
    sub_bins: usize,
    overlap: f32,
) -> Option<Vec<(f32, f32)>> {
    let hop = ((fft_size as f32 * (1.0 - overlap)) as usize).max(1);
    let hann: Vec<f32> = (0..fft_size)
        .map(|i| 0.5 * (1.0 - (2.0 * std::f32::consts::PI * i as f32 / fft_size as f32).cos()))
        .collect();
    let r2c = RealFftPlanner::<f32>::new().plan_fft_forward(fft_size);
    let mut input = vec![0.0; fft_size];
    let mut spectrum = r2c.make_output_vec();
    let mut out = Vec::new();
    let mut offset = 0;
    while offset + fft_size <= samples.len() {
        for (slot, (sample, weight)) in input.iter_mut().zip(samples[offset..].iter().zip(&hann)) {
            *slot = sample * weight;
        }
        offset += hop;
        if r2c.process(&mut input, &mut spectrum).is_err() {
            continue;
        }
        let energies: Vec<f32> = spectrum.iter().map(|c| c.norm_sqr()).collect();
        let window: f32 = energies.iter().sum();
        if window > 0.0 {
            let sub: f32 = energies[1..=sub_bins.min(energies.len() - 1)].iter().sum();
            out.push((window, sub));
        }
    }
    (!out.is_empty()).then_some(out)
}

fn median_energy(windows: &[(f32, f32)]) -> f32 {
    let mut energies: Vec<f32> = windows.iter().map(|(e, _)| *e).collect();
    energies.sort_by(f32::total_cmp);
    energies[energies.len() / 2]
}

fn prev_power_of_two(n: usize) -> usize {
    if n == 0 {
        0
    } else {
        1 << (usize::BITS - 1 - n.leading_zeros())
    }
}
