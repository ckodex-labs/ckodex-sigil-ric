//! Model-side preprocessor profiles (RIC-MM-001 WP4, docs/ADR-001).
//!
//! A profile names the transformation a target model applies to media before
//! it consumes it. SIGIL produces that representation itself, scans it, and
//! binds it (P-MM-1). A profile is a typed value whose SHA-384 digest over a
//! length-prefixed encoding is its identity; the name is a label.

mod resample;

pub use resample::{PassOrder, Rgb8, pillow13_pass_order, resize_bicubic, resize_nearest};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
pub use sigil_multimodal::ConsumedParity;

const PROFILE_DOMAIN: &[u8] = b"sigil-preprocessor-profile-v1";

/// Image resampling kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImageKernel {
    /// Pillow 13.0.0 bicubic (a = −0.5, support 2 scaled on downscale,
    /// 22-bit fixed point, version-specific pass order).
    PillowBicubic,
    /// Pillow 13.0.0 nearest (pixel-centre sampling, accumulated position).
    PillowNearest,
}

/// How the output size is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "rule")]
pub enum ResizeRule {
    Fixed {
        width: u64,
        height: u64,
    },
    /// transformers' Qwen2-VL `smart_resize`.
    SmartResize {
        factor: u64,
        min_pixels: u64,
        max_pixels: u64,
    },
}

/// Vision-language patching: how the resized view becomes placeholder tokens.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct Patching {
    pub patch_size: u64,
    pub temporal_patch_size: u64,
    pub merge_size: u64,
    pub image_mean: [f64; 3],
    pub image_std: [f64; 3],
}

/// Audio resampler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AudioResampler {
    /// `x[::k]` on float32 samples, no anti-alias filter (integer ratio only).
    Decimate,
    /// ffmpeg swresample with its defaults (`-ar <rate> -ac 1`).
    FfmpegSwrDefault,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "modality")]
pub enum ProfileSpec {
    Image {
        kernel: ImageKernel,
        resize: ResizeRule,
        patching: Option<Patching>,
    },
    Audio {
        target_rate_hz: u64,
        resampler: AudioResampler,
    },
}

/// A profile's output for one input.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelView {
    pub image: Rgb8,
    /// Parity for this input: never stronger than the profile's.
    pub parity: ConsumedParity,
}

/// Every `k`-th sample from the first, `k = in_rate / out_rate`: numpy's
/// `x[::k]`, no anti-alias filter. `None` unless the ratio is a whole number.
#[must_use]
pub fn decimate(samples: &[i16], in_rate: u64, out_rate: u64) -> Option<Vec<i16>> {
    if in_rate == 0 || out_rate == 0 || !in_rate.is_multiple_of(out_rate) {
        return None;
    }
    let step = usize::try_from(in_rate / out_rate).ok()?;
    Some(samples.iter().step_by(step).copied().collect())
}

/// A named, versioned preprocessor profile.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PreprocessorProfile {
    pub name: String,
    pub spec: ProfileSpec,
    pub parity: ConsumedParity,
}

impl PreprocessorProfile {
    /// SHA-384 (hex) over the domain, name and typed spec. Floats are encoded
    /// as IEEE-754 binary64 bits, big-endian, never as decimal text. Parity is
    /// a measured property of the implementation, not part of the identity.
    #[must_use]
    pub fn digest(&self) -> String {
        let mut h = Sha384::new();
        put(&mut h, PROFILE_DOMAIN);
        put(&mut h, self.name.as_bytes());
        match &self.spec {
            ProfileSpec::Image {
                kernel,
                resize,
                patching,
            } => hash_image_spec(&mut h, *kernel, *resize, patching.as_ref()),
            ProfileSpec::Audio {
                target_rate_hz,
                resampler,
            } => hash_audio_spec(&mut h, *target_rate_hz, *resampler),
        }
        h.finalize().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Output size for an image of `width` × `height`, or `None` for audio
    /// profiles and for inputs the rule rejects.
    #[must_use]
    pub fn output_size(&self, width: u64, height: u64) -> Option<(u64, u64)> {
        match &self.spec {
            ProfileSpec::Image {
                resize:
                    ResizeRule::Fixed {
                        width: w,
                        height: h,
                    },
                ..
            } => Some((*w, *h)),
            ProfileSpec::Image {
                resize:
                    ResizeRule::SmartResize {
                        factor,
                        min_pixels,
                        max_pixels,
                    },
                ..
            } => {
                smart_resize(height, width, *factor, *min_pixels, *max_pixels).map(|(h, w)| (w, h))
            }
            ProfileSpec::Audio { .. } => None,
        }
    }

    /// The model view of an image under this profile, with the parity that
    /// holds for this input. A reference-matched profile still yields an
    /// approximate view where the reference's behaviour for this input is
    /// unknown (Pillow 13's bicubic pass order when both axes shrink).
    #[must_use]
    pub fn model_view(&self, image: &Rgb8) -> Option<ModelView> {
        let ProfileSpec::Image { kernel, .. } = &self.spec else {
            return None;
        };
        let (w, h) = self.output_size(image.width as u64, image.height as u64)?;
        let (w, h) = (usize::try_from(w).ok()?, usize::try_from(h).ok()?);
        let (image, parity) = match kernel {
            ImageKernel::PillowBicubic => {
                match pillow13_pass_order(image.width, image.height, w, h) {
                    Some(order) => (resize_bicubic(image, w, h, order), self.parity),
                    None => (
                        resize_bicubic(image, w, h, PassOrder::HorizontalFirst),
                        ConsumedParity::Approximate,
                    ),
                }
            }
            ImageKernel::PillowNearest => (resize_nearest(image, w, h), self.parity),
        };
        Some(ModelView { image, parity })
    }

    /// The waveform the model consumes, from channel-0 16-bit samples at
    /// `rate` Hz. `None` for image profiles, for resamplers with no in-process
    /// implementation (ffmpeg's), and for rates the resampler cannot serve.
    #[must_use]
    pub fn audio_view(&self, channel0: &[i16], rate: u64) -> Option<(Vec<i16>, ConsumedParity)> {
        match &self.spec {
            ProfileSpec::Audio {
                target_rate_hz,
                resampler: AudioResampler::Decimate,
            } => decimate(channel0, rate, *target_rate_hz).map(|view| (view, self.parity)),
            _ => None,
        }
    }

    /// Placeholder tokens a vision-language model emits for an image of this
    /// view size: `(t · h/p · w/p) / merge²` with t = 1 for a still image.
    #[must_use]
    pub fn placeholder_count(&self, view_width: u64, view_height: u64) -> Option<u64> {
        let ProfileSpec::Image {
            patching: Some(p), ..
        } = &self.spec
        else {
            return None;
        };
        let grid = (view_height / p.patch_size) * (view_width / p.patch_size);
        Some(grid / (p.merge_size * p.merge_size))
    }
}

/// transformers' `smart_resize` for Qwen2-VL, returning (height, width).
/// Python's `round` rounds half to even, as `round_ties_even` does here.
#[must_use]
pub fn smart_resize(
    height: u64,
    width: u64,
    factor: u64,
    min_pixels: u64,
    max_pixels: u64,
) -> Option<(u64, u64)> {
    const MAX_ASPECT: f64 = 200.0;
    let (h, w, f) = (height as f64, width as f64, factor as f64);
    if height == 0 || width == 0 || h.max(w) / h.min(w) > MAX_ASPECT {
        return None;
    }
    let mut h_bar = (h / f).round_ties_even() * f;
    let mut w_bar = (w / f).round_ties_even() * f;
    if h_bar * w_bar > max_pixels as f64 {
        let beta = (h * w / max_pixels as f64).sqrt();
        h_bar = f.max((h / beta / f).floor() * f);
        w_bar = f.max((w / beta / f).floor() * f);
    } else if h_bar * w_bar < min_pixels as f64 {
        let beta = (min_pixels as f64 / (h * w)).sqrt();
        h_bar = (h * beta / f).ceil() * f;
        w_bar = (w * beta / f).ceil() * f;
    }
    Some((h_bar as u64, w_bar as u64))
}

/// Built-in profiles shipped with this crate.
pub const BUILTIN_PROFILES: &[&str] = &[
    "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow",
    "thumbnail/nearest-80",
    "audio/16k-decimate",
    "whisper/16k-filtered",
];

/// Looks up a built-in profile by name.
#[must_use]
pub fn builtin(name: &str) -> Option<PreprocessorProfile> {
    let (spec, parity) = builtin_spec(name)?;
    Some(PreprocessorProfile {
        name: name.to_string(),
        spec,
        parity,
    })
}

fn builtin_spec(name: &str) -> Option<(ProfileSpec, ConsumedParity)> {
    let spec = match name {
        "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow" => {
            (qwen2_vl_spec(), ConsumedParity::ReferenceMatched)
        }
        "thumbnail/nearest-80" => (
            ProfileSpec::Image {
                kernel: ImageKernel::PillowNearest,
                resize: ResizeRule::Fixed {
                    width: 80,
                    height: 80,
                },
                patching: None,
            },
            ConsumedParity::ReferenceMatched,
        ),
        "audio/16k-decimate" => (
            ProfileSpec::Audio {
                target_rate_hz: 16_000,
                resampler: AudioResampler::Decimate,
            },
            ConsumedParity::ReferenceMatched,
        ),
        // No in-process swresample: the profile names the engine's
        // behaviour, and declaring it yields no consumed view.
        "whisper/16k-filtered" => (
            ProfileSpec::Audio {
                target_rate_hz: 16_000,
                resampler: AudioResampler::FfmpegSwrDefault,
            },
            ConsumedParity::Approximate,
        ),
        _ => return None,
    };
    Some(spec)
}

fn qwen2_vl_spec() -> ProfileSpec {
    ProfileSpec::Image {
        kernel: ImageKernel::PillowBicubic,
        // Qwen/Qwen2-VL-7B-Instruct preprocessor_config.json values,
        // as recorded in scripts/reference/README.md.
        resize: ResizeRule::SmartResize {
            factor: 28,
            min_pixels: 3_136,
            max_pixels: 12_845_056,
        },
        patching: Some(Patching {
            patch_size: 14,
            temporal_patch_size: 2,
            merge_size: 2,
            image_mean: [0.481_454_66, 0.457_827_5, 0.408_210_73],
            image_std: [0.268_629_54, 0.261_302_58, 0.275_777_11],
        }),
    }
}

fn hash_image_spec(
    h: &mut Sha384,
    kernel: ImageKernel,
    resize: ResizeRule,
    patching: Option<&Patching>,
) {
    put(h, b"image");
    put(
        h,
        match kernel {
            // The reference version is part of the identity: Pillow
            // 12.3.0 and 13.0.0 produce different bicubic bytes.
            ImageKernel::PillowBicubic => b"pillow-13.0.0/bicubic".as_slice(),
            ImageKernel::PillowNearest => b"pillow-13.0.0/nearest".as_slice(),
        },
    );
    match resize {
        ResizeRule::Fixed { width, height } => {
            put(h, b"fixed");
            ints(h, &[width, height]);
        }
        ResizeRule::SmartResize {
            factor,
            min_pixels,
            max_pixels,
        } => {
            put(h, b"smart-resize");
            ints(h, &[factor, min_pixels, max_pixels]);
        }
    }
    match patching {
        None => put(h, b"no-patching"),
        Some(p) => {
            put(h, b"patching");
            ints(h, &[p.patch_size, p.temporal_patch_size, p.merge_size]);
            for value in p.image_mean.iter().chain(&p.image_std) {
                h.update(value.to_bits().to_be_bytes());
            }
        }
    }
}

fn hash_audio_spec(h: &mut Sha384, target_rate_hz: u64, resampler: AudioResampler) {
    put(h, b"audio");
    ints(h, &[target_rate_hz]);
    put(
        h,
        match resampler {
            AudioResampler::Decimate => b"decimate".as_slice(),
            AudioResampler::FfmpegSwrDefault => b"ffmpeg-swr-default".as_slice(),
        },
    );
}

fn put(h: &mut Sha384, bytes: &[u8]) {
    h.update((bytes.len() as u64).to_be_bytes());
    h.update(bytes);
}

fn ints(h: &mut Sha384, values: &[u64]) {
    h.update((values.len() as u64).to_be_bytes());
    for v in values {
        h.update(v.to_be_bytes());
    }
}

#[cfg(test)]
mod tests;
