//! Audio adapter (Phase 2 — audio).
//!
//! Decomposes WAV artifacts into governed text channels following the same
//! Option B contract as the image adapter: the adapter produces *channels*,
//! the kernel judges. The adapter cannot fabricate authority (RIC-R-7
//! enforced at the type level via `ExtractedChannel` carrying no provenance
//! field).
//!
//! Decodes WAV via `hound` (pure Rust, no system deps). Reports format
//! facts (sample rate, channels, bit depth, duration). An optional external
//! transcript extractor (ASR) is pinned by digest at construction, receives
//! artifact bytes on stdin, and returns text on stdout — the same
//! argument-injection-closed contract as the image OCR path.

mod sampling;
mod transcript;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use sigil_multimodal::{ChannelKind, ExtractedChannel};
use std::io::Cursor;

pub use sigil_multimodal::{PerceptionAdapter, PerceptionError, PerceptionReport};
pub use transcript::ExternalTranscript;

/// Audio adapter: decodes WAV, reports format facts, and optionally
/// extracts a transcript channel through a pinned external ASR binary.
///
/// The ASR binary is pinned at construction (its SHA-384 digest is recorded
/// in every channel's extractor identity), receives artifact bytes on
/// stdin, and returns text on stdout. Artifact bytes never appear in an
/// argument — the argument-injection surface is closed by construction.
pub struct AudioAdapter {
    pub transcript: Option<ExternalTranscript>,
    /// The target model's preprocessor profile (see `ImageAdapter::profile`).
    pub profile: Option<crate::preprocess::PreprocessorProfile>,
    /// A pinned ffmpeg for profiles whose resampler is ffmpeg
    /// (`whisper/16k-filtered`). Pin it with
    /// [`crate::model_view::resampler_args`] for the profile.
    pub resampler: Option<crate::ExternalPipe>,
}

impl PerceptionAdapter for AudioAdapter {
    fn modality(&self) -> sigil_multimodal::Modality {
        sigil_multimodal::Modality::Audio
    }

    fn adapter_id(&self) -> &str {
        "sigil-perception/audio/0.1"
    }

    fn perceive(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
    ) -> Result<PerceptionReport, PerceptionError> {
        let mut hasher = Sha384::new();
        hasher.update(artifact.bytes);
        let artifact_digest = hex_digest(&hasher.finalize());

        // Decode WAV. hound reads the WAV header + samples; we only need
        // format facts, so we read the spec and a minimal sample count.
        let reader = hound::WavReader::new(Cursor::new(artifact.bytes))
            .map_err(|_| PerceptionError::DecodeFailed)?;
        let spec = reader.spec();
        let duration_secs = sampling::estimate_duration(&spec, reader.len());
        let adapter_id = self.adapter_id();

        let mut properties = wav_properties(&spec, duration_secs, adapter_id);
        let mut channels = vec![sampling::metadata_channel(&spec, duration_secs, adapter_id)];

        let (spectral, dropped_samples) =
            spectral_channel(artifact.bytes, &spec, adapter_id, &artifact_digest);
        channels.extend(spectral);
        if dropped_samples > 0 {
            properties.push((
                format!("{adapter_id}.dropped_samples"),
                dropped_samples.to_string(),
            ));
        }

        // Transcript channel via the pinned external ASR binary, when configured.
        let mut source_text = None;
        if let Some(transcript) = &self.transcript {
            let channel = transcript_channel(transcript, artifact.bytes)?;
            source_text = Some(channel.content.clone());
            channels.push(channel);
        }
        let mut consumed = None;
        if let Some(profile) = &self.profile {
            let tool = self.transcript.as_ref().zip(source_text.as_deref());
            let view = crate::model_view::audio_view(
                profile,
                artifact.bytes,
                self.resampler.as_ref(),
                tool,
                adapter_id,
            )?;
            channels.extend(view.channels);
            consumed = Some(view.consumed);
        }

        Ok(PerceptionReport {
            source_id: artifact.source_id.clone(),
            artifact_digest,
            media_type: artifact
                .media_type
                .clone()
                .unwrap_or_else(|| "audio/wav".to_string()),
            properties,
            channels,
            consumed,
        })
    }
}

/// Spectral analysis channel: low-frequency deception detection. Downmixes
/// to mono (weighted per ITU-R BS.775-4 for >2 channels, mitigating
/// CVE-2026-34760) and runs FFT-based subliminal and steganography
/// detection. Also returns how many samples could not be read.
fn spectral_channel(
    bytes: &[u8],
    spec: &hound::WavSpec,
    adapter_id: &str,
    artifact_digest: &str,
) -> (Option<ExtractedChannel>, usize) {
    let scale = crate::spectral::normalization_factor(spec.bits_per_sample);
    let (samples_f32, dropped_samples) = sampling::read_samples_f32(bytes, spec, scale);
    let mono = if spec.channels > 2 {
        crate::spectral::downmix_to_mono_weighted_f32(&samples_f32, spec.channels)
    } else {
        crate::spectral::downmix_to_mono_f32(&samples_f32, spec.channels)
    };
    let channel =
        sampling::spectral_channel(&mono, spec, adapter_id, artifact_digest, dropped_samples);
    (channel, dropped_samples)
}

fn wav_properties(
    spec: &hound::WavSpec,
    duration_secs: f64,
    adapter_id: &str,
) -> Vec<(String, String)> {
    vec![
        (
            format!("{adapter_id}.sample_rate"),
            spec.sample_rate.to_string(),
        ),
        (format!("{adapter_id}.channels"), spec.channels.to_string()),
        (
            format!("{adapter_id}.bits_per_sample"),
            spec.bits_per_sample.to_string(),
        ),
        (
            format!("{adapter_id}.duration_secs"),
            format!("{duration_secs:.3}"),
        ),
        (
            format!("{adapter_id}.wav_format"),
            format!("{:?}", spec.sample_format),
        ),
    ]
}

/// A non-zero ASR exit is an error; a clean exit that left input unread is
/// declared as a truncated channel. Truncation inside the ASR binary itself
/// (e.g. a model that stops decoding early) is not observable here.
fn transcript_channel(
    transcript: &ExternalTranscript,
    bytes: &[u8],
) -> Result<ExtractedChannel, PerceptionError> {
    let run = transcript.extract(bytes)?;
    Ok(ExtractedChannel {
        channel_kind: ChannelKind::Transcript,
        content: run.output,
        extractor: transcript.identity(crate::TRANSCRIPT_EXTRACTOR),
        confidence: None,
        truncated: run.input_unread,
    })
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AudioPerceptionOutcome {
    pub report: PerceptionReport,
}

#[cfg(test)]
mod tests;
