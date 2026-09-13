use super::*;

fn sine_wave(freq_hz: f32, sample_rate: u32, duration_secs: f32) -> Vec<f32> {
    let n = (sample_rate as f32 * duration_secs) as usize;
    (0..n)
        .map(|i| (2.0 * std::f32::consts::PI * freq_hz * i as f32 / sample_rate as f32).sin())
        .collect()
}

#[test]
fn pure_tone_detected_at_correct_frequency() {
    let samples = sine_wave(440.0, 16000, 0.1);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "aa").expect("spectrum");
    assert!(
        (report.dominant_freq_hz - 440.0).abs() < 20.0,
        "dominant freq should be ~440 Hz, got {}",
        report.dominant_freq_hz
    );
}

#[test]
fn subliminal_low_frequency_energy_detected() {
    let mut samples = sine_wave(5.0, 16000, 0.5);
    for s in &mut samples {
        *s *= 10.0;
    }
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "bb").expect("spectrum");
    assert!(
        !report.subliminal_findings.is_empty(),
        "sub-audible signal should be detected: {:?}",
        report.subliminal_findings
    );
}

#[test]
fn high_frequency_steganography_detected() {
    let mut samples = sine_wave(7000.0, 16000, 0.1);
    for s in &mut samples {
        *s *= 5.0;
    }
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "cc").expect("spectrum");
    assert!(
        !report.steganography_findings.is_empty(),
        "high-frequency anomaly should be detected: {:?}",
        report.steganography_findings
    );
}

#[test]
fn normal_audio_no_false_positives() {
    let samples = sine_wave(440.0, 16000, 0.1);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "dd").expect("spectrum");
    assert!(
        report.subliminal_findings.is_empty(),
        "normal audio should not trigger subliminal: {:?}",
        report.subliminal_findings
    );
    assert!(
        report.steganography_findings.is_empty(),
        "normal audio should not trigger steganography: {:?}",
        report.steganography_findings
    );
}

#[test]
fn too_short_signal_returns_none() {
    let samples = vec![0.0; 10];
    let report = analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "ee");
    assert!(report.is_none(), "short signal should return None");
}

#[test]
fn silent_signal_returns_none() {
    let samples = vec![0.0; 1024];
    let report = analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "ff");
    assert!(report.is_none(), "silent signal should return None");
}

#[test]
fn artifact_digest_is_propagated() {
    let samples = sine_wave(440.0, 16000, 0.1);
    let digest = "0123456789abcdef".repeat(6);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), &digest).expect("spectrum");
    assert_eq!(report.artifact_digest, digest);
}

#[test]
fn multiple_windows_analyzed_for_long_signal() {
    // 2 seconds at 16000 Hz = 32000 samples. With fft_size=1024 and
    // 50% overlap (hop=512), we should get ~62 windows.
    let samples = sine_wave(440.0, 16000, 2.0);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "gg").expect("spectrum");
    assert!(
        report.windows_analyzed > 50,
        "should analyze many windows, got {}",
        report.windows_analyzed
    );
}

#[test]
fn subliminal_detected_in_second_window_only() {
    // First second: 440 Hz normal tone. Second second: 5 Hz sub-audible.
    let mut samples = sine_wave(440.0, 16000, 1.0);
    let mut sub = sine_wave(5.0, 16000, 1.0);
    for s in &mut sub {
        *s *= 10.0;
    }
    samples.extend(sub);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "hh").expect("spectrum");
    assert!(
        !report.subliminal_findings.is_empty(),
        "sub-audible in second window should be detected across full signal"
    );
}

#[test]
fn downmix_stereo_to_mono_simple() {
    let samples = vec![100i16, 200, 200, 300];
    let mono = downmix_to_mono(&samples, 2);
    assert_eq!(mono.len(), 2);
    assert!((mono[0] - (150.0 / i16::MAX as f32)).abs() < 0.001);
}

#[test]
fn downmix_51_excludes_lfe_channel() {
    // 5.1: L=100, R=100, C=100, LFE=32767 (max), Ls=0, Rs=0
    // Weighted: L*1.0 + R*1.0 + C*0.707 + LFE*0.0 + Ls*0.707 + Rs*0.707
    // = 100 + 100 + 70.7 + 0 + 0 + 0 = 270.7
    // Simple avg would include LFE: (100+100+100+32767+0+0)/6 = 5511.2
    let samples = vec![100i16, 100, 100, 32767, 0, 0];
    let mono_weighted = downmix_to_mono_weighted(&samples, 6);
    let mono_simple = downmix_to_mono(&samples, 6);
    assert_eq!(mono_weighted.len(), 1);
    assert_eq!(mono_simple.len(), 1);
    // Weighted should be much smaller than simple (LFE excluded).
    assert!(
        mono_weighted[0] < mono_simple[0] * 0.1,
        "weighted downmix should exclude LFE: weighted={}, simple={}",
        mono_weighted[0],
        mono_simple[0]
    );
}

#[test]
fn pcm_conversion_preserves_amplitude() {
    let pcm = vec![0i16, i16::MAX, i16::MIN];
    let f32_samples = pcm_to_f32(&pcm);
    assert!((f32_samples[0] - 0.0).abs() < 0.001);
    assert!((f32_samples[1] - 1.0).abs() < 0.01);
    assert!((f32_samples[2] - (-1.0)).abs() < 0.01);
}

#[test]
fn artifact_digest_computes_sha384() {
    let digest = artifact_digest(b"test");
    assert_eq!(digest.len(), 96, "SHA-384 hex = 96 chars");
}

fn mixed(base_freq: f32, tone_freq: f32, tone_amp: f32, sr: u32, secs: f32) -> Vec<f32> {
    let n = (sr as f32 * secs) as usize;
    (0..n)
        .map(|i| {
            (2.0 * std::f32::consts::PI * base_freq * i as f32 / sr as f32).sin()
                + tone_amp * (2.0 * std::f32::consts::PI * tone_freq * i as f32 / sr as f32).sin()
        })
        .collect()
}

#[test]
fn narrowband_covert_tone_detected_below_band_threshold() {
    // 1 kHz carrier + weak 7 kHz tone at ~3.8% of window energy: the
    // aggregate high-band share stays under the 5% stego gate, but the
    // Hann-windowed peak bin holds ~2.5% — over the 2% narrowband
    // threshold.
    let samples = mixed(1000.0, 7000.0, 0.2, 16000, 0.5);
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "ii").expect("spectrum");
    let labels: Vec<&str> = report
        .steganography_findings
        .iter()
        .map(|f| f.label.as_str())
        .collect();
    assert!(
        labels.contains(&"narrowband_high_freq_peak"),
        "expected narrowband peak finding, got {labels:?}"
    );
    assert!(
        !labels.contains(&"high_frequency_anomaly"),
        "aggregate band fraction should stay under threshold: {labels:?}"
    );
}

#[test]
fn frequency_hopping_across_bins_is_labeled() {
    // Four 0.25 s segments, each with a different covert tone in the
    // 6-8 kHz band — peaks land on >=3 distinct bins across windows.
    let mut samples = Vec::new();
    for tone in [6200.0f32, 6600.0, 7000.0, 7400.0] {
        samples.extend(mixed(1000.0, tone, 0.2, 16000, 0.25));
    }
    let report =
        analyze_spectrum(&samples, 16000, &SpectralConfig::default(), "jj").expect("spectrum");
    let labels: Vec<&str> = report
        .steganography_findings
        .iter()
        .map(|f| f.label.as_str())
        .collect();
    assert!(
        labels.contains(&"frequency_hopping"),
        "expected frequency_hopping finding, got {labels:?}"
    );
}

#[test]
fn broadband_high_frequency_noise_is_not_narrowband() {
    // Deterministic broadband pattern: high-band energy is spread over
    // many bins, so no single bin exceeds the peak threshold.
    let sr = 16000u32;
    let n = sr as usize / 2;
    let samples: Vec<f32> = (0..n)
        .map(|i| {
            let t = i as f32 / sr as f32;
            (2.0 * std::f32::consts::PI * 1000.0 * t).sin()
                + 0.03 * (((i * 37) % 13) as f32 - 6.0) / 6.0
        })
        .collect();
    let report =
        analyze_spectrum(&samples, sr, &SpectralConfig::default(), "kk").expect("spectrum");
    let labels: Vec<&str> = report
        .steganography_findings
        .iter()
        .map(|f| f.label.as_str())
        .collect();
    assert!(
        !labels.contains(&"narrowband_high_freq_peak") && !labels.contains(&"frequency_hopping"),
        "broadband noise should not produce narrowband findings: {labels:?}"
    );
}

mod downmix_tests {
    use super::super::downmix::*;

    #[test]
    fn mono_passthrough() {
        let out = downmix_to_mono(&[i16::MAX / 2], 1);
        assert_eq!(out.len(), 1);
        assert!((out[0] - 0.5).abs() < 0.01);
    }

    #[test]
    fn stereo_averages_channels() {
        let out = downmix_to_mono(&[1000, 2000], 2);
        assert_eq!(out.len(), 1);
        let expected = 1500.0 / i16::MAX as f32;
        assert!((out[0] - expected).abs() < 1e-6);
    }

    #[test]
    fn zero_channels_returns_empty() {
        assert!(downmix_to_mono(&[1, 2, 3], 0).is_empty());
        assert!(downmix_to_mono_weighted(&[1, 2, 3], 0).is_empty());
        assert!(downmix_to_mono_f32(&[1.0], 0).is_empty());
        assert!(downmix_to_mono_weighted_f32(&[1.0], 0).is_empty());
    }

    #[test]
    fn weighted_51_excludes_lfe() {
        // 5.1 frame: L=100, R=100, C=100, LFE=32000 (full-scale hidden
        // payload), Ls=100, Rs=100. LFE weight is 0.0 — the hidden channel
        // must not contribute.
        let frame = [100i16, 100, 100, i16::MAX, 100, 100];
        let out = downmix_to_mono_weighted(&frame, 6);
        assert_eq!(out.len(), 1);
        // Without LFE exclusion the sum would exceed i16::MAX and clamp
        // wildly; with it the result is a sane weighted mix.
        let expected =
            (100.0 + 100.0 + 100.0 * 0.707 + 0.0 + 100.0 * 0.707 + 100.0 * 0.707) / i16::MAX as f32;
        assert!((out[0] - expected).abs() < 1e-5, "got {}", out[0]);
    }

    #[test]
    fn weighted_odd_channel_count_falls_back_to_equal() {
        // 3 channels has no ITU layout — equal 1/3 weights.
        let out = downmix_to_mono_weighted(&[3000, 3000, 3000], 3);
        assert_eq!(out.len(), 1);
        assert!((out[0] - 3000.0 / i16::MAX as f32).abs() < 1e-5);
    }

    #[test]
    fn f32_variants_mirror_i16() {
        let stereo = [0.5f32, -0.5];
        assert_eq!(downmix_to_mono_f32(&stereo, 2).len(), 1);
        assert_eq!(downmix_to_mono_f32(&stereo, 2)[0], 0.0);
        let w = downmix_to_mono_weighted_f32(&stereo, 2);
        assert_eq!(w.len(), 1);
        assert!((w[0] - 0.0).abs() < 1e-6);
    }

    #[test]
    fn normalization_factor_per_bit_depth() {
        assert_eq!(normalization_factor(8), i8::MAX as f32);
        assert_eq!(normalization_factor(16), i16::MAX as f32);
        assert_eq!(normalization_factor(24), ((1 << 23) - 1) as f32);
        assert_eq!(normalization_factor(32), i32::MAX as f32);
        assert_eq!(normalization_factor(0), 1.0);
    }

    #[test]
    fn pcm_to_f32_normalizes() {
        let out = pcm_to_f32(&[i16::MAX, 0, i16::MIN]);
        assert!((out[0] - 1.0).abs() < 1e-6);
        assert_eq!(out[1], 0.0);
        assert!((out[2] - (-1.0)).abs() < 1e-4);
    }
}
