//! Qwen2-VL request ID streams from digest-pinned assets (RIC-MM-001 WP6).
//!
//! The interpreter is the tokenizer, chat template, processor config and
//! model config the target model reads, loaded only when every file's
//! SHA-384 equals its pin. Its identity digest covers the model, revision and
//! all file digests, so a different template or processor config is a
//! different interpreter (RIC-R-4).

use std::path::Path;

use serde_json::Value;
use sha2::{Digest, Sha384};

use super::bpe::{ByteLevelBpe, TokenizerError};
use crate::preprocess::{PreprocessorProfile, ProfileSpec, ResizeRule};

/// A digest-pinned set of model assets.
#[derive(Clone, Copy, Debug)]
pub struct AssetPin {
    pub model: &'static str,
    pub revision: &'static str,
    /// `(file name, SHA-384 hex)`, in identity order.
    pub files: &'static [(&'static str, &'static str)],
}

/// `mlx-community/Qwen2-VL-2B-4bit` at the revision vendored in
/// `assets/qwen2-vl-2b` (see its PROVENANCE.md).
pub const QWEN2_VL_2B: AssetPin = AssetPin {
    model: "mlx-community/Qwen2-VL-2B-4bit",
    revision: "949a35dce2ee94a3337551e02051ab00dde3e3b4",
    files: &[
        (
            "tokenizer.json",
            "30aedba44ef99e56dd9ed1b3d87639bcf53a3b340f1141ce31c7f8b8614f19c38a0b4012f05cd95d0f4e10178d5bb876",
        ),
        (
            "chat_template.json",
            "f5a8f61b5506abec91df2b22d5ce7831ecb3839a6dc8295cc05b33f60f04f6db696b4aaaeec0228ffb356f3609579237",
        ),
        (
            "preprocessor_config.json",
            "4ec0b01c8eeb212bca1510da729737625a3ee0374ac0ad3ba4f384f5351997b67a464853625cfe3678ef55612530c082",
        ),
        (
            "config.json",
            "997410891ba417414080c97d7a11394c2424dbb37e501786c951000d5d6c3c5a40e8ac4820074ae0352369bb694d122f",
        ),
    ],
};

const IDENTITY_DOMAIN: &str = "sigil-vlm-interpreter-v1";
const IMAGE_PAD: &str = "<|image_pad|>";
const VISION_START: &str = "<|vision_start|>";
const VISION_END: &str = "<|vision_end|>";
/// Upper bound on the text of one request.
pub const MAX_REQUEST_TEXT_BYTES: usize = 1 << 20;

/// Why the interpreter could not load or encode.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum InterpreterError {
    #[error("cannot read pinned asset {0}")]
    Missing(String),
    #[error("asset {file} has SHA-384 {found}, pinned {pinned}")]
    DigestMismatch {
        file: String,
        found: String,
        pinned: String,
    },
    #[error("asset {0} lacks a field the interpreter needs")]
    Malformed(String),
    #[error(transparent)]
    Tokenizer(#[from] TokenizerError),
    #[error("text contains the special-token literal {0:?}")]
    SpecialTokenInText(String),
    #[error("grid {0:?} is not a whole number of merged patches")]
    Grid([u64; 3]),
    #[error("request text exceeds {MAX_REQUEST_TEXT_BYTES} bytes")]
    TooLarge,
}

/// One part of a request, in template order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part<'a> {
    Text(&'a str),
    /// An image with its processor grid `[t, h, w]` in patches.
    Image {
        grid_thw: [u64; 3],
    },
}

/// The ID stream of a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IdStream {
    pub ids: Vec<u32>,
    /// Placeholder tokens per image, in order.
    pub placeholders: Vec<u64>,
}

/// Processor values the interpreter's assets declare.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProcessorConfig {
    pub patch_size: u64,
    pub temporal_patch_size: u64,
    pub merge_size: u64,
    pub min_pixels: u64,
    pub max_pixels: u64,
    pub image_mean: [f64; 3],
    pub image_std: [f64; 3],
}

/// A loaded Qwen2-VL interpreter.
#[derive(Debug)]
pub struct Qwen2VlInterpreter {
    bpe: ByteLevelBpe,
    vision_start: u32,
    vision_end: u32,
    image_pad: u32,
    processor: ProcessorConfig,
    identity: String,
}

fn sha384_hex(bytes: &[u8]) -> String {
    Sha384::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn put(hasher: &mut Sha384, value: &str) {
    hasher.update((value.len() as u64).to_be_bytes());
    hasher.update(value.as_bytes());
}

/// Read every pinned file, refusing any whose digest differs from its pin.
fn read_pinned(dir: &Path, pin: &AssetPin) -> Result<Vec<Vec<u8>>, InterpreterError> {
    pin.files
        .iter()
        .map(|(name, pinned)| {
            let bytes = std::fs::read(dir.join(name))
                .map_err(|_| InterpreterError::Missing((*name).to_string()))?;
            let found = sha384_hex(&bytes);
            if found == *pinned {
                Ok(bytes)
            } else {
                Err(InterpreterError::DigestMismatch {
                    file: (*name).to_string(),
                    found,
                    pinned: (*pinned).to_string(),
                })
            }
        })
        .collect()
}

/// The interpreter identity: SHA-384 over the model, revision and every
/// file name and digest, length-prefixed under its domain.
#[must_use]
pub fn identity_digest(pin: &AssetPin) -> String {
    let mut hasher = Sha384::new();
    put(&mut hasher, IDENTITY_DOMAIN);
    put(&mut hasher, pin.model);
    put(&mut hasher, pin.revision);
    for (name, digest) in pin.files {
        put(&mut hasher, name);
        put(&mut hasher, digest);
    }
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn json(bytes: &[u8], name: &str) -> Result<Value, InterpreterError> {
    serde_json::from_slice(bytes).map_err(|_| InterpreterError::Malformed(name.to_string()))
}

fn uint(value: &Value, key: &str, name: &str) -> Result<u64, InterpreterError> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| InterpreterError::Malformed(format!("{name}:{key}")))
}

fn triple(value: &Value, key: &str) -> Result<[f64; 3], InterpreterError> {
    let malformed = || InterpreterError::Malformed(format!("preprocessor_config.json:{key}"));
    let items = value
        .get(key)
        .and_then(Value::as_array)
        .ok_or_else(malformed)?;
    let mut out = [0.0; 3];
    if items.len() != 3 {
        return Err(malformed());
    }
    for (slot, item) in out.iter_mut().zip(items) {
        *slot = item.as_f64().ok_or_else(malformed)?;
    }
    Ok(out)
}

fn processor_config(bytes: &[u8]) -> Result<ProcessorConfig, InterpreterError> {
    const NAME: &str = "preprocessor_config.json";
    let value = json(bytes, NAME)?;
    Ok(ProcessorConfig {
        patch_size: uint(&value, "patch_size", NAME)?,
        temporal_patch_size: uint(&value, "temporal_patch_size", NAME)?,
        merge_size: uint(&value, "merge_size", NAME)?,
        min_pixels: uint(&value, "min_pixels", NAME)?,
        max_pixels: uint(&value, "max_pixels", NAME)?,
        image_mean: triple(&value, "image_mean")?,
        image_std: triple(&value, "image_std")?,
    })
}

fn token_id(config: &Value, key: &str) -> Result<u32, InterpreterError> {
    u32::try_from(uint(config, key, "config.json")?)
        .map_err(|_| InterpreterError::Malformed(format!("config.json:{key}")))
}

impl Qwen2VlInterpreter {
    /// Load the pinned assets from `dir`.
    ///
    /// # Errors
    /// `Missing` or `DigestMismatch` for a file that is absent or differs
    /// from its pin; `Malformed` or `Tokenizer` when a pinned file lacks
    /// what the interpreter needs, including token IDs that disagree between
    /// `config.json` and the tokenizer.
    pub fn load(dir: &Path, pin: &AssetPin) -> Result<Self, InterpreterError> {
        let files = read_pinned(dir, pin)?;
        let bpe = ByteLevelBpe::from_tokenizer_json(&files[0])?;
        let processor = processor_config(&files[2])?;
        let config = json(&files[3], "config.json")?;
        let (vision_start, vision_end, image_pad) = (
            token_id(&config, "vision_start_token_id")?,
            token_id(&config, "vision_end_token_id")?,
            token_id(&config, "image_token_id")?,
        );
        let agrees = [
            (VISION_START, vision_start),
            (VISION_END, vision_end),
            (IMAGE_PAD, image_pad),
        ]
        .iter()
        .all(|(literal, id)| bpe.added_token_id(literal) == Some(*id));
        if !agrees {
            return Err(InterpreterError::Malformed(
                "config.json token ids".to_string(),
            ));
        }
        Ok(Self {
            bpe,
            vision_start,
            vision_end,
            image_pad,
            processor,
            identity: identity_digest(pin),
        })
    }

    /// The interpreter identity digest bound into receipts.
    #[must_use]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The processor values the pinned `preprocessor_config.json` declares.
    #[must_use]
    pub fn processor(&self) -> ProcessorConfig {
        self.processor
    }

    /// True when a preprocessor profile resizes and patches exactly as this
    /// interpreter's processor config declares.
    #[must_use]
    pub fn matches_profile(&self, profile: &PreprocessorProfile) -> bool {
        let p = self.processor;
        let ProfileSpec::Image {
            resize:
                ResizeRule::SmartResize {
                    factor,
                    min_pixels,
                    max_pixels,
                },
            patching: Some(patching),
            ..
        } = &profile.spec
        else {
            return false;
        };
        *factor == p.patch_size * p.merge_size
            && *min_pixels == p.min_pixels
            && *max_pixels == p.max_pixels
            && patching.patch_size == p.patch_size
            && patching.temporal_patch_size == p.temporal_patch_size
            && patching.merge_size == p.merge_size
            && patching.image_mean == p.image_mean
            && patching.image_std == p.image_std
    }

    /// The still-image grid `[1, h/p, w/p]` for a view of this size.
    #[must_use]
    pub fn grid_for_view(&self, view_width: u64, view_height: u64) -> [u64; 3] {
        let p = self.processor.patch_size;
        [1, view_height / p, view_width / p]
    }

    /// Placeholder tokens for one image: `t·h·w / merge²`, as transformers'
    /// `Qwen2VLProcessor.replace_image_token` computes it.
    ///
    /// # Errors
    /// `Grid` when the grid is empty or not a whole number of merges.
    pub fn placeholders(&self, grid_thw: [u64; 3]) -> Result<u64, InterpreterError> {
        let merge = self.processor.merge_size * self.processor.merge_size;
        let cells = grid_thw.iter().product::<u64>();
        if cells == 0 || merge == 0 || !cells.is_multiple_of(merge) {
            return Err(InterpreterError::Grid(grid_thw));
        }
        Ok(cells / merge)
    }

    /// The token IDs one image contributes:
    /// `<|vision_start|>`, the placeholders, `<|vision_end|>`.
    ///
    /// # Errors
    /// As [`Self::placeholders`].
    pub fn image_stream(&self, grid_thw: [u64; 3]) -> Result<Vec<u32>, InterpreterError> {
        let count = usize::try_from(self.placeholders(grid_thw)?)
            .map_err(|_| InterpreterError::Grid(grid_thw))?;
        let mut ids = Vec::with_capacity(count + 2);
        ids.push(self.vision_start);
        ids.resize(count + 1, self.image_pad);
        ids.push(self.vision_end);
        Ok(ids)
    }

    /// SHA-384 over one image's stream as little-endian `u32` IDs.
    ///
    /// # Errors
    /// As [`Self::placeholders`].
    pub fn placeholder_stream_digest(
        &self,
        grid_thw: [u64; 3],
    ) -> Result<String, InterpreterError> {
        Ok(ids_sha384(&self.image_stream(grid_thw)?))
    }

    /// The exact ID stream the pinned template, processor and tokenizer
    /// produce for a request. The pinned `chat_template.json` renders an
    /// image part as `<|vision_start|><|image_pad|><|vision_end|>` and a text
    /// part as its text; this implements that template only, and its digest
    /// pin keeps any other template from loading. Adjacent text parts concatenate before
    /// encoding, as the template renders them. Text that contains a
    /// special-token literal is refused: Hugging Face would turn it into a
    /// control ID such as an image placeholder.
    ///
    /// # Errors
    /// `SpecialTokenInText`, `TooLarge`, `Grid`, or a tokenizer error.
    pub fn encode_request(&self, parts: &[Part<'_>]) -> Result<IdStream, InterpreterError> {
        let text_bytes: usize = parts
            .iter()
            .map(|part| match part {
                Part::Text(text) => text.len(),
                Part::Image { .. } => 0,
            })
            .sum();
        if text_bytes > MAX_REQUEST_TEXT_BYTES {
            return Err(InterpreterError::TooLarge);
        }
        let mut stream = IdStream {
            ids: Vec::new(),
            placeholders: Vec::new(),
        };
        let mut text = String::new();
        for part in parts {
            match part {
                Part::Text(piece) => text.push_str(piece),
                Part::Image { grid_thw } => {
                    self.flush_text(&mut text, &mut stream.ids)?;
                    stream.placeholders.push(self.placeholders(*grid_thw)?);
                    stream.ids.extend(self.image_stream(*grid_thw)?);
                }
            }
        }
        self.flush_text(&mut text, &mut stream.ids)?;
        Ok(stream)
    }

    fn flush_text(&self, text: &mut String, ids: &mut Vec<u32>) -> Result<(), InterpreterError> {
        if let Some(literal) = self.bpe.added_token_in(text) {
            return Err(InterpreterError::SpecialTokenInText(literal.to_string()));
        }
        ids.extend(self.bpe.encode(text)?);
        text.clear();
        Ok(())
    }

    /// The tokenizer, for Hugging Face-parity encoding of plain text.
    #[must_use]
    pub fn tokenizer(&self) -> &ByteLevelBpe {
        &self.bpe
    }
}

/// SHA-384 over IDs as little-endian `u32`.
#[must_use]
pub fn ids_sha384(ids: &[u32]) -> String {
    let bytes: Vec<u8> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
    sha384_hex(&bytes)
}
