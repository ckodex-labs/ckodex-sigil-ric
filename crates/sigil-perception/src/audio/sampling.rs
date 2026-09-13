use sigil_multimodal::{ChannelKind, ExtractedChannel, ExtractorIdentity};
use std::io::Cursor;

/// Estimate duration in seconds from the WAV spec and sample count.
///
/// `hound::WavReader::len()` returns the total number of samples across
/// all channels. To get the frame count (which determines duration), we
/// divide by the channel count.
pub(crate) fn estimate_duration(spec: &hound::WavSpec, sample_count: u32) -> f64 {
    if spec.sample_rate == 0 || spec.channels == 0 {
        return 0.0;
    }
    sample_count as f64 / spec.channels as f64 / spec.sample_rate as f64
}

/// Format facts rendered as `key = value` lines; scanned by the kernel
/// like any other text channel.
pub(crate) fn metadata_channel(
    spec: &hound::WavSpec,
    duration_secs: f64,
    adapter_id: &str,
    artifact_digest: &str,
) -> ExtractedChannel {
    let content = format!(
        "sample_rate = {}\nchannels = {}\nbits_per_sample = {}\nsample_format = {:?}\nduration_secs = {:.3}\n",
        spec.sample_rate,
        spec.channels,
        spec.bits_per_sample,
        spec.sample_format,
        duration_secs,
    );
    ExtractedChannel {
        channel_kind: ChannelKind::Metadata,
        content,
        extractor: ExtractorIdentity {
            name: format!("{adapter_id}/wav-header"),
            version: "hound/3.5".to_string(),
            config_digest: artifact_digest.to_string(),
        },
        confidence: None,
        truncated: false,
    }
}

/// Read all samples normalized to f32 in -1.0..1.0.
///
/// The sample type must match `spec.sample_format` (hound returns `Err`
/// for every sample on mismatch) and `bits_per_sample` determines the
/// normalization factor — hound does not normalize integer samples
/// (see ruuda/hound#57). Corrupted samples are counted, not silently
/// dropped: the caller surfaces the count via `truncated` evidence.
pub(crate) fn read_samples_f32(
    bytes: &[u8],
    spec: &hound::WavSpec,
    scale: f32,
) -> (Vec<f32>, usize) {
    let reader = match hound::WavReader::new(Cursor::new(bytes)) {
        Ok(reader) => reader,
        Err(_) => return (Vec::new(), 0),
    };
    let mut samples = Vec::new();
    let mut dropped = 0usize;
    match spec.sample_format {
        hound::SampleFormat::Float => {
            for r in reader.into_samples::<f32>() {
                match r {
                    Ok(s) => samples.push(s),
                    Err(_) => dropped += 1,
                }
            }
        }
        hound::SampleFormat::Int if spec.bits_per_sample > 16 => {
            for r in reader.into_samples::<i32>() {
                match r {
                    Ok(s) => samples.push(s as f32 / scale),
                    Err(_) => dropped += 1,
                }
            }
        }
        hound::SampleFormat::Int => {
            for r in reader.into_samples::<i16>() {
                match r {
                    Ok(s) => samples.push(s as f32 / scale),
                    Err(_) => dropped += 1,
                }
            }
        }
    }
    (samples, dropped)
}

/// FFT-based subliminal + steganography analysis serialized as JSON for
/// the kernel to consume. `None` when analysis cannot run (e.g. too few
/// samples); `truncated` marks channels built from partial sample data.
pub(crate) fn spectral_channel(
    mono: &[f32],
    spec: &hound::WavSpec,
    adapter_id: &str,
    artifact_digest: &str,
    dropped_samples: usize,
) -> Option<ExtractedChannel> {
    let report = crate::spectral::analyze_spectrum(
        mono,
        spec.sample_rate,
        &crate::spectral::SpectralConfig::default(),
        artifact_digest,
    )?;
    let content = serde_json::to_string_pretty(&report)
        .unwrap_or_else(|_| "spectral_analysis_error".to_string());
    Some(ExtractedChannel {
        channel_kind: ChannelKind::Metadata,
        content,
        extractor: ExtractorIdentity {
            name: format!("{adapter_id}/spectral"),
            version: "realfft/3.5".to_string(),
            config_digest: artifact_digest.to_string(),
        },
        confidence: None,
        truncated: dropped_samples > 0,
    })
}
