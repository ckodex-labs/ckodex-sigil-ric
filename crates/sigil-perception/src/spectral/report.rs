//! Assembly of the `SpectralReport` from the accumulated window stats.

use super::*;

/// Assemble the `SpectralReport` from the accumulated window stats.
pub(super) fn build_report(
    stats: &WindowStats,
    sub_audible: Option<&subaudible::SubAudible>,
    total_samples: usize,
    sample_rate: u32,
    config: &SpectralConfig,
    artifact_digest: &str,
) -> SpectralReport {
    let spectrum = facts::Spectrum {
        bins: &stats.bin_energy_sum,
        bin_hz: f64::from(stats.bin_hz),
        total: stats.bin_energy_sum.iter().sum(),
    };

    let subliminal_findings = subliminal_findings(sub_audible, config);
    let mut steganography_findings = Vec::new();
    steganography_findings.extend(high_frequency_anomaly(stats, &spectrum));
    steganography_findings.extend(narrowband_peak(stats, config));

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
        inaudible_band: facts::inaudible_band(
            &spectrum,
            sample_rate,
            config.inaudible_cutoff_hz,
            config.inaudible_min_sample_rate_hz,
        ),
        alias_predictions: facts::alias_predictions(
            &spectrum,
            sample_rate,
            config.alias_hidden_origin_hz,
            &config.alias_target_rates_hz,
        ),
    }
}

/// The sub-audible band, when the per-window check flagged it.
fn subliminal_findings(
    sub_audible: Option<&subaudible::SubAudible>,
    config: &SpectralConfig,
) -> Vec<FreqBand> {
    let mut findings = Vec::new();
    if let Some(sub_audible) = sub_audible.filter(|sub| sub.flagged) {
        findings.push(FreqBand {
            label: "sub_audible".to_string(),
            low_hz: 0.0,
            high_hz: config.subliminal_cutoff_hz,
            energy: sub_audible.energy,
            fraction_of_total: sub_audible.fraction,
            flatness: None,
            subbands: Vec::new(),
        });
    }
    findings
}

/// Aggregate high-band anomaly: energy near Nyquist above the stego fraction
/// in some window, reported with the band's flatness and subbands.
fn high_frequency_anomaly(stats: &WindowStats, spectrum: &facts::Spectrum<'_>) -> Option<FreqBand> {
    if !stats.has_stego {
        return None;
    }
    let high_band: Vec<(usize, f64)> = stats
        .bin_energy_sum
        .iter()
        .enumerate()
        .filter(|(bin, _)| *bin as f32 * stats.bin_hz >= stats.high_band_start_hz)
        .map(|(bin, energy)| (bin, *energy))
        .collect();
    Some(FreqBand {
        label: "high_frequency_anomaly".to_string(),
        low_hz: stats.high_band_start_hz,
        high_hz: stats.nyquist,
        energy: stats.high_band_energy_sum,
        fraction_of_total: stats.high_band_energy_sum / stats.total_energy,
        flatness: Some(facts::structure(
            &high_band.iter().map(|(_, e)| *e).collect::<Vec<_>>(),
        )),
        subbands: facts::subbands(spectrum, &high_band),
    })
}

/// Narrowband peaks in the high band: `frequency_hopping` when the peak
/// lands on enough distinct bins across windows.
fn narrowband_peak(stats: &WindowStats, config: &SpectralConfig) -> Option<FreqBand> {
    if stats.high_band_peak_bins.is_empty() {
        return None;
    }
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
    Some(FreqBand {
        label: label.to_string(),
        low_hz: stats.high_band_start_hz,
        high_hz: stats.nyquist,
        energy: stats.narrowband_peak_energy_sum,
        fraction_of_total: stats.narrowband_peak_energy_sum / stats.total_energy,
        flatness: None,
        subbands: Vec::new(),
    })
}
