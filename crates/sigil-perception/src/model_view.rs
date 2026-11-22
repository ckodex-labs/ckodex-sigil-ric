//! The model's view (RIC-MM-001 WP4, P-MM-1, docs/ADR-001).
//!
//! Under a preprocessor profile, SIGIL produces the representation the target
//! model consumes, extracts text from it with the same pinned tool it ran on
//! the source, and reports what only the view carries as a `Divergence`
//! channel. These are facts; the kernel judges them.
//!
//! Extractor identities for view channels carry the tool's pinned arguments
//! followed by `view:`-tagged entries (profile digest, transformation to the
//! tool's input), the role-tagging convention of the document adapter's
//! render chain. Tagged entries are not argv.

use crate::preprocess::{PreprocessorProfile, Rgb8};
use crate::vlm::Qwen2VlInterpreter;
use crate::{OCR_EXTRACTOR, PinnedTool, TRANSCRIPT_EXTRACTOR, in_process_identity};
use sha2::{Digest, Sha384};
use sigil_multimodal::{
    ChannelKind, ConsumedParity, ConsumedView, ExtractedChannel, ExtractorIdentity, PerceptionError,
};
use std::io::Cursor;

/// The specimen measurement read the 80² view after a ×6 nearest upscale:
/// Tesseract needs glyphs of some minimum size. The view is upscaled by the
/// smallest whole factor that brings its shorter side to this many pixels.
/// Whole-factor pixel replication adds no content.
const OCR_MIN_SIDE: usize = 480;

use crate::document::DIVERGENCE_VERSION;

/// What a profile produced for one artifact.
pub(crate) struct ViewExtraction {
    pub consumed: ConsumedView,
    pub channels: Vec<ExtractedChannel>,
}

/// Source pixels a profile will convert to RGB8 and resample: larger inputs
/// are rejected rather than allocated (3 bytes per pixel, 192 MiB).
pub(crate) const MAX_SOURCE_PIXELS: u64 = 64 * 1024 * 1024;

/// True when a source of `width` × `height` fits [`MAX_SOURCE_PIXELS`].
pub(crate) fn within_source_budget(width: u32, height: u32) -> bool {
    u64::from(width) * u64::from(height) <= MAX_SOURCE_PIXELS
}

/// The image the model sees, OCR on it, and the divergence from the source
/// OCR text when one was extracted.
///
/// `decode_covered`: the artifact was decoded on a path a parity vector
/// covers (8-bit RGB PNG). Any other decode (JPEG, 16-bit, palette, alpha,
/// grey) may differ from the reference's, so the view is approximate.
/// `interpreter`: the target model's pinned interpreter; when given, the
/// placeholder stream and the interpreter identity are bound too.
///
/// # Errors
///
/// `ExtractorFailed` when the profile has no image view for this input (an
/// audio profile, or a size the resize rule rejects), when the interpreter's
/// processor config disagrees with the profile, or when the OCR run fails.
pub(crate) fn image_view(
    profile: &PreprocessorProfile,
    image: &Rgb8,
    decode_covered: bool,
    ocr: Option<(&PinnedTool, &str)>,
    interpreter: Option<&Qwen2VlInterpreter>,
    adapter_id: &str,
) -> Result<ViewExtraction, PerceptionError> {
    let view = profile.model_view(image).ok_or_else(|| {
        PerceptionError::ExtractorFailed(format!(
            "profile {} has no image view for a {}x{} image",
            profile.name, image.width, image.height
        ))
    })?;
    let (width, height) = (view.image.width as u64, view.image.height as u64);
    let mut consumed = ConsumedView {
        profile: profile.name.clone(),
        profile_digest: profile.digest(),
        digest: sha384_hex(&view.image.data),
        parity: if decode_covered {
            view.parity
        } else {
            ConsumedParity::Approximate
        },
        extractor: None,
        placeholders: profile.placeholder_count(width, height),
        placeholder_stream_digest: None,
        interpreter: None,
    };
    if let Some(interpreter) = interpreter {
        bind_interpreter(&mut consumed, profile, interpreter, width, height)?;
    }
    let mut channels = Vec::new();
    if let Some((tool, source_text)) = ocr {
        let factor = OCR_MIN_SIDE
            .div_ceil(view.image.width.min(view.image.height).max(1))
            .max(1);
        let png = encode_png(&replicate(&view.image, factor))?;
        let run = tool.extract(&png)?;
        let identity = view_identity(tool, OCR_EXTRACTOR, profile, &format!("nearest-x{factor}"));
        consumed.extractor = Some(identity.identity_digest.clone());
        channels.extend(divergence(
            &run.output,
            source_text,
            &tool.identity(OCR_EXTRACTOR),
            &identity,
            adapter_id,
        ));
        channels.insert(
            0,
            ExtractedChannel {
                channel_kind: ChannelKind::OcrText,
                content: run.output,
                extractor: identity,
                confidence: None,
                truncated: run.input_unread,
            },
        );
    }
    Ok(ViewExtraction { consumed, channels })
}

/// Bind the placeholder stream the interpreter derives from the view size.
/// The interpreter must patch exactly as the profile does, and its count must
/// equal the profile's: anything else would bind a stream the model never
/// receives.
fn bind_interpreter(
    consumed: &mut ConsumedView,
    profile: &PreprocessorProfile,
    interpreter: &Qwen2VlInterpreter,
    width: u64,
    height: u64,
) -> Result<(), PerceptionError> {
    let failed = |why: String| PerceptionError::ExtractorFailed(why);
    if !interpreter.matches_profile(profile) {
        return Err(failed(format!(
            "interpreter processor config does not match profile {}",
            profile.name
        )));
    }
    let grid = interpreter.grid_for_view(width, height);
    let count = interpreter
        .placeholders(grid)
        .map_err(|e| failed(e.to_string()))?;
    if Some(count) != consumed.placeholders {
        return Err(failed(format!(
            "interpreter expands the view to {count} placeholders, the profile to {:?}",
            consumed.placeholders
        )));
    }
    let digest = interpreter
        .placeholder_stream_digest(grid)
        .map_err(|e| failed(e.to_string()))?;
    consumed.placeholder_stream_digest = Some(digest);
    consumed.interpreter = Some(interpreter.identity().to_string());
    Ok(())
}

/// The waveform the model hears (16-bit PCM), ASR on it, and the
/// divergence from the source transcript when one was extracted.
///
/// An in-process profile (`audio/16k-decimate`) keeps channel 0. A profile
/// whose resampler is ffmpeg (`whisper/16k-filtered`) needs `resampler`: a
/// pinned ffmpeg SIGIL runs with the reference command, built from the
/// profile ([`resampler_args`]). Its binary digest is part of the view's
/// transform tag, so any extractor that reads the view binds it.
///
/// # Errors
///
/// `DecodeFailed` for a WAV that is not 16-bit integer PCM with a non-zero
/// rate and channel count; `ExtractorFailed` when the profile has no view
/// for this input, needs a resampler that was not given, or a tool fails.
pub(crate) fn audio_view(
    profile: &PreprocessorProfile,
    wav: &[u8],
    resampler: Option<&PinnedTool>,
    transcript: Option<(&PinnedTool, &str)>,
    adapter_id: &str,
) -> Result<ViewExtraction, PerceptionError> {
    let waveform = waveform_view(profile, wav, resampler)?;
    let bytes: Vec<u8> = waveform
        .samples
        .iter()
        .flat_map(|s| s.to_le_bytes())
        .collect();
    let mut consumed = ConsumedView {
        profile: profile.name.clone(),
        profile_digest: profile.digest(),
        digest: sha384_hex(&bytes),
        parity: waveform.parity,
        extractor: None,
        placeholders: None,
        placeholder_stream_digest: None,
        interpreter: None,
    };
    let mut channels = Vec::new();
    if let Some((tool, source_text)) = transcript {
        let run = tool.extract(&encode_wav(&waveform.samples, waveform.rate)?)?;
        let identity = view_identity(tool, TRANSCRIPT_EXTRACTOR, profile, &waveform.transform);
        consumed.extractor = Some(identity.identity_digest.clone());
        channels.extend(divergence(
            &run.output,
            source_text,
            &tool.identity(TRANSCRIPT_EXTRACTOR),
            &identity,
            adapter_id,
        ));
        channels.insert(
            0,
            ExtractedChannel {
                channel_kind: ChannelKind::Transcript,
                content: run.output,
                extractor: identity,
                confidence: None,
                truncated: run.input_unread,
            },
        );
    }
    Ok(ViewExtraction { consumed, channels })
}

/// The waveform a profile produces, with its parity, rate and the transform
/// tag that names how it was made.
struct Waveform {
    samples: Vec<i16>,
    parity: ConsumedParity,
    rate: u32,
    transform: String,
}

fn failed(why: String) -> PerceptionError {
    PerceptionError::ExtractorFailed(why)
}

/// The ffmpeg arguments for a resampling profile: WAV on stdin, 16-bit
/// little-endian mono PCM at the profile's rate on stdout. This is the
/// reference command (`scripts/reference/whisper-stdin`), so the caller
/// cannot choose a different resampling under the profile's name.
#[must_use]
pub fn resampler_args(profile: &PreprocessorProfile) -> Option<Vec<String>> {
    let crate::preprocess::ProfileSpec::Audio {
        target_rate_hz,
        resampler: crate::preprocess::AudioResampler::FfmpegSwrDefault,
    } = profile.spec
    else {
        return None;
    };
    let rate = target_rate_hz.to_string();
    Some(
        [
            "-loglevel",
            "error",
            "-i",
            "pipe:0",
            "-f",
            "s16le",
            "-ac",
            "1",
            "-ar",
            &rate,
            "pipe:1",
        ]
        .map(str::to_string)
        .to_vec(),
    )
}

fn waveform_view(
    profile: &PreprocessorProfile,
    wav: &[u8],
    resampler: Option<&PinnedTool>,
) -> Result<Waveform, PerceptionError> {
    let mut reader =
        hound::WavReader::new(Cursor::new(wav)).map_err(|_| PerceptionError::DecodeFailed)?;
    let spec = reader.spec();
    if spec.bits_per_sample != 16
        || spec.sample_format != hound::SampleFormat::Int
        || spec.sample_rate == 0
        || spec.channels == 0
    {
        return Err(PerceptionError::DecodeFailed);
    }
    let crate::preprocess::ProfileSpec::Audio { target_rate_hz, .. } = profile.spec else {
        return Err(failed(format!(
            "profile {} is not an audio profile",
            profile.name
        )));
    };
    let rate = u32::try_from(target_rate_hz)
        .map_err(|_| failed(format!("profile {} rate", profile.name)))?;
    if let Some(args) = resampler_args(profile) {
        return resampled(profile, wav, resampler, &args, rate);
    }
    let channel0: Vec<i16> = reader
        .samples::<i16>()
        .step_by(usize::from(spec.channels.max(1)))
        .collect::<Result<_, _>>()
        .map_err(|_| PerceptionError::DecodeFailed)?;
    let source_rate = u64::from(spec.sample_rate);
    let (samples, parity) = profile.audio_view(&channel0, source_rate).ok_or_else(|| {
        failed(format!(
            "profile {} has no in-process audio view for {source_rate} Hz",
            profile.name
        ))
    })?;
    Ok(Waveform {
        samples,
        // The view keeps channel 0, as the reference does; an engine that
        // downmixes hears the other channels too. Only mono is covered.
        parity: if spec.channels == 1 {
            parity
        } else {
            ConsumedParity::Approximate
        },
        rate,
        transform: "channel0-pcm16".to_string(),
    })
}

/// Run the pinned resampler. Its output is ffmpeg's own resampling, but the
/// specimen's recorded reference hash was not reproduced with ffmpeg 9.0.2
/// (docs/ADR-001), so the view is approximate.
fn resampled(
    profile: &PreprocessorProfile,
    wav: &[u8],
    resampler: Option<&PinnedTool>,
    args: &[String],
    rate: u32,
) -> Result<Waveform, PerceptionError> {
    let tool = resampler.ok_or_else(|| {
        failed(format!(
            "profile {} needs a pinned resampler (ffmpeg)",
            profile.name
        ))
    })?;
    let identity = tool.identity("resampler");
    if identity.args != args {
        return Err(failed(format!(
            "resampler for {} must be pinned with the profile's arguments",
            profile.name
        )));
    }
    let run = tool.run(wav)?;
    if run.input_unread || !run.output.len().is_multiple_of(2) {
        return Err(failed(
            "resampler output is not whole 16-bit samples".to_string(),
        ));
    }
    let samples = run
        .output
        .chunks_exact(2)
        .map(|pair| i16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    Ok(Waveform {
        samples,
        parity: ConsumedParity::Approximate,
        rate,
        transform: format!("ffmpeg-s16le:{}", identity.config_digest),
    })
}

/// Lines only the model's view carries, as a `Divergence` channel bound to
/// both extractions. `None` when every view line is covered by the source.
fn divergence(
    view_text: &str,
    source_text: &str,
    source: &ExtractorIdentity,
    view: &ExtractorIdentity,
    adapter_id: &str,
) -> Option<ExtractedChannel> {
    let lines = crate::document::divergent_lines(view_text, source_text);
    (!lines.is_empty()).then(|| ExtractedChannel {
        channel_kind: ChannelKind::Divergence,
        content: lines.join("\n"),
        extractor: in_process_identity(
            format!("{adapter_id}/model-view-divergence"),
            DIVERGENCE_VERSION,
            &[
                ("source", source.identity_digest.clone()),
                ("view", view.identity_digest.clone()),
            ],
        ),
        confidence: None,
        truncated: false,
    })
}

fn view_identity(
    tool: &PinnedTool,
    name: &str,
    profile: &PreprocessorProfile,
    transform: &str,
) -> ExtractorIdentity {
    let mut args = tool.args.clone();
    args.push(format!("view:profile={}", profile.digest()));
    args.push(format!("view:transform={transform}"));
    ExtractorIdentity::bound(
        format!("{name}/model-view"),
        tool.version.clone(),
        tool.binary_digest.clone(),
        args,
        tool.model_digests.clone(),
    )
}

fn replicate(image: &Rgb8, factor: usize) -> Rgb8 {
    let (width, height) = (image.width * factor, image.height * factor);
    let mut data = Vec::with_capacity(width * height * 3);
    for y in 0..height {
        for x in 0..width {
            let i = ((y / factor) * image.width + x / factor) * 3;
            data.extend_from_slice(&image.data[i..i + 3]);
        }
    }
    Rgb8 {
        width,
        height,
        data,
    }
}

fn encode_png(image: &Rgb8) -> Result<Vec<u8>, PerceptionError> {
    let failed = || PerceptionError::ExtractorFailed("encode model view".to_string());
    let width = u32::try_from(image.width).map_err(|_| failed())?;
    let height = u32::try_from(image.height).map_err(|_| failed())?;
    let buffer = image::RgbImage::from_raw(width, height, image.data.clone()).ok_or_else(failed)?;
    let mut out = Cursor::new(Vec::new());
    buffer
        .write_to(&mut out, image::ImageFormat::Png)
        .map_err(|_| failed())?;
    Ok(out.into_inner())
}

fn encode_wav(samples: &[i16], rate: u32) -> Result<Vec<u8>, PerceptionError> {
    let failed = || PerceptionError::ExtractorFailed("encode model view".to_string());
    let spec = hound::WavSpec {
        channels: 1,
        sample_rate: rate,
        bits_per_sample: 16,
        sample_format: hound::SampleFormat::Int,
    };
    let mut out = Cursor::new(Vec::new());
    let mut writer = hound::WavWriter::new(&mut out, spec).map_err(|_| failed())?;
    for sample in samples {
        writer.write_sample(*sample).map_err(|_| failed())?;
    }
    writer.finalize().map_err(|_| failed())?;
    Ok(out.into_inner())
}

fn sha384_hex(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_source_budget_rejects_huge_images_before_conversion() {
        assert!(within_source_budget(8_192, 8_192));
        assert!(!within_source_budget(23_170, 23_170), "the 1.5 GiB L8 case");
        assert!(!within_source_budget(u32::MAX, u32::MAX), "no overflow");
    }
}
