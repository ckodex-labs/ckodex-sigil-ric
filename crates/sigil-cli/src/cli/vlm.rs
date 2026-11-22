//! `sigil-cli vlm-request`: the exact token-ID stream a vision-language
//! model receives for a request, from its digest-pinned interpreter
//! (RIC-MM-001 WP6).

use crate::cli::types::VlmRequestCommand;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sigil_perception::vlm::{Part, QWEN2_VL_2B, Qwen2VlInterpreter, ids_sha384};
use std::fs;

/// One image part of the request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VlmImagePart {
    pub path: String,
    pub grid_thw: [u64; 3],
    pub placeholders: u64,
    pub placeholder_stream_digest: String,
}

/// Outcome of `sigil-cli vlm-request`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VlmRequestOutcome {
    /// Identity digest of the interpreter that produced the stream.
    pub interpreter: String,
    pub profile: String,
    pub ids: Vec<u32>,
    /// SHA-384 over `ids` as little-endian `u32`.
    pub ids_sha384: String,
    pub images: Vec<VlmImagePart>,
}

enum ParsedPart {
    Text(String),
    Image(String),
}

fn parse_part(part: &str) -> Result<ParsedPart> {
    if let Some(text) = part.strip_prefix("text:") {
        Ok(ParsedPart::Text(text.to_string()))
    } else if let Some(path) = part.strip_prefix("image:") {
        Ok(ParsedPart::Image(path.to_string()))
    } else {
        Err(anyhow!(
            "--part must start with text: or image:, got {part:?}"
        ))
    }
}

pub fn vlm_request_command(command: &VlmRequestCommand) -> Result<VlmRequestOutcome> {
    let profile = sigil_perception::preprocess::builtin(&command.profile)
        .ok_or_else(|| anyhow!("unknown --profile `{}`", command.profile))?;
    let interpreter = Qwen2VlInterpreter::load(&command.vlm_assets, &QWEN2_VL_2B)
        .map_err(|err| anyhow!("--vlm-assets {}: {err}", command.vlm_assets.display()))?;
    let parsed = command
        .parts
        .iter()
        .map(|part| parse_part(part))
        .collect::<Result<Vec<_>>>()?;
    let mut images = Vec::new();
    for part in &parsed {
        if let ParsedPart::Image(path) = part {
            let bytes = fs::read(path).with_context(|| format!("read {path}"))?;
            let grid_thw = interpreter
                .image_grid(&profile, &bytes)
                .map_err(|err| anyhow!("{path}: {err}"))?;
            images.push(VlmImagePart {
                path: path.clone(),
                grid_thw,
                placeholders: interpreter.placeholders(grid_thw)?,
                placeholder_stream_digest: interpreter.placeholder_stream_digest(grid_thw)?,
            });
        }
    }
    let mut image_grids = images.iter().map(|image| image.grid_thw);
    let request: Vec<Part<'_>> = parsed
        .iter()
        .map(|part| match part {
            ParsedPart::Text(text) => Part::Text(text),
            ParsedPart::Image(_) => Part::Image {
                grid_thw: image_grids.next().unwrap_or([0, 0, 0]),
            },
        })
        .collect();
    let stream = interpreter.encode_request(&request)?;
    Ok(VlmRequestOutcome {
        interpreter: interpreter.identity().to_string(),
        profile: profile.name,
        ids_sha384: ids_sha384(&stream.ids),
        ids: stream.ids,
        images,
    })
}

/// Human rendering: the identity, the stream digest and its length.
#[must_use]
pub fn render_vlm_request(outcome: &VlmRequestOutcome) -> String {
    let images: String = outcome
        .images
        .iter()
        .map(|image| {
            format!(
                "  image       {} grid {:?}, {} placeholders\n",
                image.path, image.grid_thw, image.placeholders
            )
        })
        .collect();
    format!(
        "vlm-request\n  interpreter {}\n  profile     {}\n  ids         {} (sha384 {})\n{images}",
        outcome.interpreter,
        outcome.profile,
        outcome.ids.len(),
        outcome.ids_sha384
    )
}
