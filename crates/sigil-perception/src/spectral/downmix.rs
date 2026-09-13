/// Downmix multi-channel WAV samples to mono by simple averaging.
///
/// **WARNING (CVE-2026-34760)**: Simple averaging gives equal weight to
/// all channels, including sub-audible low-frequency effects (LFE) and
/// surround channels. An attacker can embed hidden commands in channels
/// that humans cannot hear but ASR will transcribe. For >2 channels,
/// prefer `downmix_to_mono_weighted` which applies ITU-R BS.775-4
/// attenuation to non-front channels.
pub fn downmix_to_mono(samples: &[i16], channels: u16) -> Vec<f32> {
    if channels == 0 {
        return Vec::new();
    }
    let ch = channels as usize;
    samples
        .chunks(ch)
        .map(|frame| {
            let sum: i32 = frame.iter().map(|&s| s as i32).sum();
            (sum / ch as i32) as f32 / i16::MAX as f32
        })
        .collect()
}

/// Downmix multi-channel WAV samples to mono using ITU-R BS.775-4
/// weighted coefficients. Non-front channels (center, surround, LFE)
/// are attenuated to prevent sub-audible and surround-channel injection
/// (CVE-2026-34760 mitigation).
///
/// Channel layout assumptions (0-indexed):
/// - 1 ch: mono (weight 1.0)
/// - 2 ch: stereo L/R (weights 1.0, 1.0)
/// - 6 ch: 5.1 — L, R, C, LFE, Ls, Rs (weights 1.0, 1.0, 0.707, 0.0, 0.707, 0.707)
///
/// For other channel counts, falls back to simple averaging with a
/// warning in the returned weights.
pub fn downmix_to_mono_weighted(samples: &[i16], channels: u16) -> Vec<f32> {
    if channels == 0 {
        return Vec::new();
    }
    let ch = channels as usize;
    let weights = itu_r_bs775_weights(ch);

    samples
        .chunks(ch)
        .map(|frame| {
            let sum: f32 = frame
                .iter()
                .zip(weights.iter())
                .map(|(&s, &w)| s as f32 * w)
                .sum();
            sum / i16::MAX as f32
        })
        .collect()
}

/// ITU-R BS.775-4 downmix weights for common channel layouts.
/// LFE is excluded (weight 0.0) to prevent sub-audible injection.
fn itu_r_bs775_weights(channels: usize) -> Vec<f32> {
    match channels {
        1 => vec![1.0],
        2 => vec![1.0, 1.0],
        // 5.1: L, R, C, LFE, Ls, Rs
        6 => vec![1.0, 1.0, 0.707, 0.0, 0.707, 0.707],
        // 7.1: L, R, C, LFE, Ls, Rs, Lb, Rb
        8 => vec![1.0, 1.0, 0.707, 0.0, 0.707, 0.707, 0.707, 0.707],
        // Fallback: equal weights (same as simple average).
        _ => vec![1.0 / channels as f32; channels],
    }
}

/// Downmix multi-channel samples (already normalized to -1.0..1.0) to mono.
/// Same channel-layout assumptions as `downmix_to_mono_weighted`.
pub fn downmix_to_mono_f32(samples: &[f32], channels: u16) -> Vec<f32> {
    if channels == 0 {
        return Vec::new();
    }
    let ch = channels as usize;
    samples
        .chunks(ch)
        .map(|frame| frame.iter().sum::<f32>() / ch as f32)
        .collect()
}

/// Downmix multi-channel samples (already normalized to -1.0..1.0) to mono
/// using ITU-R BS.775-4 weighted coefficients.
pub fn downmix_to_mono_weighted_f32(samples: &[f32], channels: u16) -> Vec<f32> {
    if channels == 0 {
        return Vec::new();
    }
    let ch = channels as usize;
    let weights = itu_r_bs775_weights(ch);
    samples
        .chunks(ch)
        .map(|frame| frame.iter().zip(weights.iter()).map(|(&s, &w)| s * w).sum())
        .collect()
}

/// Normalize an integer sample to -1.0..1.0 based on the WAV bit depth.
/// hound does not normalize — callers must scale by the format's max value.
/// For `Float` format WAVs the samples are already normalized; return `1.0`
/// so the caller can skip scaling.
pub fn normalization_factor(bits_per_sample: u16) -> f32 {
    match bits_per_sample {
        8 => i8::MAX as f32,
        16 => i16::MAX as f32,
        24 => ((1 << 23) - 1) as f32,
        32 => i32::MAX as f32,
        _ => 1.0, // Float or unknown — assume already normalized
    }
}

/// Convert i16 PCM samples to f32 normalized (-1.0..1.0).
pub fn pcm_to_f32(samples: &[i16]) -> Vec<f32> {
    samples
        .iter()
        .map(|&s| s as f32 / i16::MAX as f32)
        .collect()
}
