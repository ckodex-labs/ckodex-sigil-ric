//! `sigil-cli perceive`: route an artifact to its adapter, then optionally
//! run the kernel over the channels it extracted.

use crate::cli::helpers::*;
use crate::cli::types::*;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sigil_core::Vocab;
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_multimodal::{ArtifactRef, Modality, PerceptionReport};
use sigil_perception::preprocess::PreprocessorProfile;
use sigil_perception::vlm::Qwen2VlInterpreter;
use sigil_perception::{ImageAdapter, PerceptionAdapter};
use std::fs;
use std::sync::Arc;

fn sniff_modality(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || bytes.starts_with(b"GIF8")
    {
        Some("image")
    } else if bytes.starts_with(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == b"WAVE"
        || bytes.starts_with(b"fLaC")
    {
        Some("audio")
    } else if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        Some("video")
    } else if bytes.starts_with(b"%PDF") {
        Some("document")
    } else {
        None
    }
}

/// Outcome of `sigil-cli perceive`: the adapter's channel report plus, when
/// `--analyze` is set, the kernel's fusion audit over those channels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerceiveOutcome {
    pub adapter_id: String,
    pub report: sigil_perception::PerceptionReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<sigil_multimodal::MultimodalAssessment>,
}

/// Which modalities each adapter flag applies to. A flag the routed adapter
/// would silently ignore reads as "configured" to the operator, so it is an
/// error instead.
fn flag_scopes(command: &PerceiveCommand) -> [(&'static str, bool, &'static [&'static str]); 13] {
    const VISUAL: &[&str] = &["image", "video", "document"];
    const SOUND: &[&str] = &["audio", "video"];
    [
        ("--ocr-binary", command.ocr_binary.is_some(), VISUAL),
        ("--ocr-args", !command.ocr_args.is_empty(), VISUAL),
        (
            "--transcript-binary",
            command.transcript_binary.is_some(),
            SOUND,
        ),
        (
            "--transcript-args",
            !command.transcript_args.is_empty(),
            SOUND,
        ),
        ("--ocr-model", !command.ocr_model.is_empty(), VISUAL),
        (
            "--transcript-model",
            !command.transcript_model.is_empty(),
            SOUND,
        ),
        (
            "--render-binary",
            command.render_binary.is_some(),
            &["document"],
        ),
        (
            "--render-args",
            !command.render_args.is_empty(),
            &["document"],
        ),
        (
            "--ffmpeg-binary",
            command.ffmpeg_binary.is_some(),
            &["video"],
        ),
        ("--profile", command.profile.is_some(), &["image", "audio"]),
        ("--vlm-assets", command.vlm_assets.is_some(), &["image"]),
        (
            "--resampler-binary",
            command.resampler_binary.is_some(),
            &["audio"],
        ),
        (
            "--delivery",
            command.delivery.is_some(),
            &["image", "audio"],
        ),
    ]
}

fn check_flags(command: &PerceiveCommand, modality: &str) -> Result<()> {
    // A declared model with no tool to load it would read as "bound" while
    // binding nothing.
    if !command.ocr_model.is_empty() && command.ocr_binary.is_none() {
        return Err(anyhow!("--ocr-model needs --ocr-binary"));
    }
    if !command.transcript_model.is_empty() && command.transcript_binary.is_none() {
        return Err(anyhow!("--transcript-model needs --transcript-binary"));
    }
    for (flag, present, allowed) in flag_scopes(command) {
        if present && !allowed.contains(&modality) {
            return Err(anyhow!(
                "{flag} applies to --modality {}; effective modality is {modality}",
                allowed.join("|"),
            ));
        }
    }
    Ok(())
}

fn resolve_profile(command: &PerceiveCommand) -> Result<Option<PreprocessorProfile>> {
    command
        .profile
        .as_deref()
        .map(|name| {
            sigil_perception::preprocess::builtin(name).ok_or_else(|| {
                anyhow!(
                    "unknown --profile `{name}`; built-in: {}",
                    sigil_perception::preprocess::BUILTIN_PROFILES.join(", ")
                )
            })
        })
        .transpose()
}

fn load_interpreter(command: &PerceiveCommand) -> Result<Option<Arc<Qwen2VlInterpreter>>> {
    command
        .vlm_assets
        .as_deref()
        .map(|dir| {
            Qwen2VlInterpreter::load(dir, &sigil_perception::vlm::QWEN2_VL_2B)
                .map(Arc::new)
                .map_err(|err| anyhow!("--vlm-assets {}: {err}", dir.display()))
        })
        .transpose()
}

/// Pin ffmpeg for a profile whose resampler is ffmpeg, with the profile's
/// own arguments. A resampler for any other profile would be ignored, so it
/// is an error.
fn pin_resampler(
    command: &PerceiveCommand,
    profile: Option<&PreprocessorProfile>,
) -> Result<Option<sigil_perception::ExternalPipe>> {
    let Some(binary) = &command.resampler_binary else {
        return Ok(None);
    };
    let args = profile
        .and_then(sigil_perception::model_view::resampler_args)
        .ok_or_else(|| anyhow!("--resampler-binary needs an ffmpeg-resampled --profile"))?;
    sigil_perception::ExternalPipe::pin(binary.clone(), args, "external".to_string())
        .map(Some)
        .map_err(|err| anyhow!("pin resampler binary: {err}"))
}

fn split_args(args: &str) -> Vec<String> {
    args.split_whitespace().map(str::to_string).collect()
}

fn pin_ocr(command: &PerceiveCommand) -> Result<Option<sigil_perception::ExternalOcr>> {
    command
        .ocr_binary
        .as_ref()
        .map(|binary| {
            sigil_perception::ExternalOcr::pin(
                binary.clone(),
                split_args(&command.ocr_args),
                "external".to_string(),
            )
            .and_then(|tool| tool.with_models(&command.ocr_model))
            .map_err(|err| anyhow!("pin ocr binary: {err}"))
        })
        .transpose()
}

fn pin_transcript(
    command: &PerceiveCommand,
) -> Result<Option<sigil_perception::audio::ExternalTranscript>> {
    command
        .transcript_binary
        .as_ref()
        .map(|binary| {
            sigil_perception::audio::ExternalTranscript::pin(
                binary.clone(),
                split_args(&command.transcript_args),
                "external".to_string(),
            )
            .and_then(|tool| tool.with_models(&command.transcript_model))
            .map_err(|err| anyhow!("pin transcript binary: {err}"))
        })
        .transpose()
}

/// Stream extraction is opt-in via --ffmpeg-binary. OCR or ASR of the
/// streams needs the pipe (frames never exist without ffmpeg), so either
/// without it is a config error.
fn pin_stream_extract(
    command: &PerceiveCommand,
) -> Result<Option<sigil_perception::video::StreamExtract>> {
    let Some(ffmpeg) = &command.ffmpeg_binary else {
        if command.ocr_binary.is_some() || command.transcript_binary.is_some() {
            return Err(anyhow!("video stream extraction needs --ffmpeg-binary"));
        }
        return Ok(None);
    };
    sigil_perception::video::StreamExtract::pin(
        ffmpeg.clone(),
        command
            .ocr_binary
            .clone()
            .map(|b| (b, split_args(&command.ocr_args))),
        command
            .transcript_binary
            .clone()
            .map(|b| (b, split_args(&command.transcript_args))),
    )
    .and_then(|extract| extract.with_models(&command.ocr_model, &command.transcript_model))
    .map(Some)
    .map_err(|err| anyhow!("pin video stream extractors: {err}"))
}

/// Render-compare needs both halves: a renderer (PDF to pixels) and an OCR
/// (pixels to text). Wiring only one is a config error, not a silent skip.
fn pin_render_compare(
    command: &PerceiveCommand,
) -> Result<Option<sigil_perception::document::RenderCompare>> {
    let renderer = match (&command.render_binary, &command.ocr_binary) {
        (Some(renderer), Some(_)) => renderer,
        (None, None) => return Ok(None),
        _ => {
            return Err(anyhow!(
                "render-compare needs both --render-binary and --ocr-binary"
            ));
        }
    };
    if !command
        .render_args
        .split_whitespace()
        .any(|a| a == "-singlefile")
    {
        return Err(anyhow!(
            "render-compare renders one page per run — \
             --render-args must include -singlefile"
        ));
    }
    let renderer = sigil_perception::ExternalPipe::pin(
        renderer.clone(),
        split_args(&command.render_args),
        "external".to_string(),
    )
    .map_err(|err| anyhow!("pin render binary: {err}"))?;
    let ocr = pin_ocr(command)?.ok_or_else(|| anyhow!("render-compare needs --ocr-binary"))?;
    Ok(Some(sigil_perception::document::RenderCompare {
        renderer,
        ocr,
    }))
}

fn run_adapter(
    adapter: &dyn PerceptionAdapter,
    artifact: &ArtifactRef<'_>,
    modality: &str,
) -> Result<(String, PerceptionReport, Modality)> {
    let report = adapter
        .perceive(artifact)
        .map_err(|err| perceive_err(err, artifact.bytes, modality))?;
    Ok((adapter.adapter_id().to_string(), report, adapter.modality()))
}

fn perceive_routed(
    command: &PerceiveCommand,
    artifact: &ArtifactRef<'_>,
    modality: &str,
) -> Result<(String, PerceptionReport, Modality)> {
    let profile = resolve_profile(command)?;
    let interpreter = load_interpreter(command)?;
    match modality {
        "audio" => {
            let adapter = sigil_perception::audio::AudioAdapter {
                transcript: pin_transcript(command)?,
                resampler: pin_resampler(command, profile.as_ref())?,
                profile,
            };
            run_adapter(&adapter, artifact, modality)
        }
        "video" => {
            let adapter = sigil_perception::video::VideoAdapter {
                stream_extract: pin_stream_extract(command)?,
            };
            run_adapter(&adapter, artifact, modality)
        }
        "document" => {
            let adapter = sigil_perception::document::DocumentAdapter {
                render_compare: pin_render_compare(command)?,
            };
            run_adapter(&adapter, artifact, modality)
        }
        "code" => run_adapter(&sigil_perception::code::CodeAdapter, artifact, modality),
        _ => {
            let adapter = ImageAdapter {
                ocr: pin_ocr(command)?,
                profile,
                interpreter,
            };
            run_adapter(&adapter, artifact, modality)
        }
    }
}

/// The caller's statement of how the engine obtains the view, recorded in the
/// consumed block it signs (decision O-5). clap restricts the label.
fn record_delivery(command: &PerceiveCommand, report: &mut PerceptionReport) {
    let delivery = command
        .delivery
        .as_deref()
        .and_then(sigil_multimodal::Delivery::from_label);
    if let Some(consumed) = report.consumed.as_mut() {
        consumed.delivery = delivery;
    }
}

pub fn perceive_command(
    command: PerceiveCommand,
    policy: Policy,
    vocab: Vocab,
    receipt_signer: Option<&std::sync::Arc<dyn ReceiptSigner>>,
) -> Result<PerceiveOutcome> {
    let bytes =
        fs::read(&command.input).with_context(|| format!("read {}", command.input.display()))?;
    let artifact = ArtifactRef {
        source_id: command.input.display().to_string(),
        bytes: &bytes,
        media_type: None,
    };

    // Declared-vs-actual routing: a --modality hint that contradicts the
    // magic bytes should not silently decode-fail — route to the sniffed
    // adapter and record the override as evidence. Adapters produce
    // channels either way; the kernel's judgment is untouched.
    let sniffed = sniff_modality(&bytes);
    let routed = sniffed.filter(|s| *s != command.modality.as_str());
    let effective_modality = sniffed.unwrap_or(command.modality.as_str());
    check_flags(&command, effective_modality)?;

    let (adapter_id, mut report, modality) =
        perceive_routed(&command, &artifact, effective_modality)?;
    record_delivery(&command, &mut report);
    if let Some(sniffed) = routed {
        report.properties.push((
            "sigil.modality_routed".to_string(),
            format!(
                "declared {} but magic says {sniffed} — routed to {sniffed}",
                command.modality
            ),
        ));
    }

    let analysis = if command.analyze {
        let inputs = channels_to_modal_inputs(&report, modality);
        let engine = build_multimodal_engine(policy, vocab, receipt_signer)?;
        Some(engine.analyze(&inputs)?)
    } else {
        None
    };

    Ok(PerceiveOutcome {
        adapter_id,
        report,
        analysis,
    })
}

/// Decode failures name the routed modality and suggest a fix — bare
/// "artifact decoding failed" is not actionable for a new user. Input
/// bytes are never echoed into the error.
fn perceive_err(
    err: sigil_multimodal::perception::PerceptionError,
    bytes: &[u8],
    modality: &str,
) -> anyhow::Error {
    use sigil_multimodal::perception::PerceptionError;
    match err {
        PerceptionError::DecodeFailed => {
            let hint = if std::str::from_utf8(bytes).is_ok() {
                "the input is UTF-8 text; try --modality document or --modality code"
            } else {
                "the bytes do not match the routed adapter's format; \
                 check the file or pick a different --modality"
            };
            anyhow!("cannot decode input as {modality}: {hint}")
        }
        other => anyhow!("{other}"),
    }
}
