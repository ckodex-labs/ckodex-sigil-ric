//! Arguments of `sigil-cli perceive`.

use std::path::PathBuf;

use super::types::FailOn;

#[derive(clap::Args, Debug)]
pub struct PerceiveCommand {
    /// Artifact file to decompose (image or audio).
    #[arg(long)]
    pub input: PathBuf,
    /// Modality hint: `image` (default), `audio`, `video`, `document`, or
    /// `code`. Container magic overrides a contradicting hint — the
    /// override is recorded as `sigil.modality_routed` evidence, never
    /// silent.
    #[arg(long, default_value = "image")]
    pub modality: String,
    /// External OCR binary to pin for the text channel (image, optional).
    #[arg(long)]
    pub ocr_binary: Option<PathBuf>,
    /// Arguments for the OCR binary (artifact bytes travel on stdin).
    #[arg(long, default_value = "")]
    pub ocr_args: String,
    /// External ASR binary to pin for the transcript channel (audio, optional).
    #[arg(long)]
    pub transcript_binary: Option<PathBuf>,
    /// Arguments for the ASR binary (artifact bytes travel on stdin).
    #[arg(long, default_value = "")]
    pub transcript_args: String,
    /// Model artifact the OCR binary loads (e.g. traineddata). Repeatable.
    /// Each file is pinned by SHA-384 and bound into the extractor identity;
    /// a missing file is a configuration error.
    #[arg(long = "ocr-model")]
    pub ocr_model: Vec<PathBuf>,
    /// Model artifact the ASR binary loads (encoder, decoder, tokens).
    /// Repeatable; pinned and bound like --ocr-model.
    #[arg(long = "transcript-model")]
    pub transcript_model: Vec<PathBuf>,
    /// Target model's preprocessor profile (image or audio), e.g.
    /// `qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow`,
    /// `thumbnail/nearest-80`, `audio/16k-decimate`. SIGIL produces the
    /// model's view under it, binds it in the report's `consumed` block and
    /// extracts from it. Without one, `--analyze` caps the ceiling of pixel
    /// and sound inputs at observe (RIC-R-8).
    #[arg(long)]
    pub profile: Option<String>,
    /// Directory holding the target model's digest-pinned interpreter assets
    /// (tokenizer, chat template, processor and model config), e.g.
    /// `assets/qwen2-vl-2b`. With a vision-language `--profile` it binds the
    /// view's placeholder stream and the interpreter identity in `consumed`.
    /// A file that differs from its pin is an error.
    #[arg(long, requires = "profile")]
    pub vlm_assets: Option<PathBuf>,
    /// ffmpeg binary to pin as the resampler of an ffmpeg-resampled audio
    /// profile (`whisper/16k-filtered`). SIGIL runs it with the profile's
    /// reference command and binds its digest in the view's transform.
    #[arg(long, requires = "profile")]
    pub resampler_binary: Option<PathBuf>,
    /// External renderer binary to pin for render-vs-extract comparison
    /// (document/PDF, optional — e.g. `pdftoppm`).
    #[arg(long)]
    pub render_binary: Option<PathBuf>,
    /// Arguments for the renderer binary (artifact bytes travel on stdin;
    /// e.g. `-png -singlefile -r 150 -`).
    #[arg(long, default_value = "")]
    pub render_args: String,
    /// External ffmpeg binary to pin for video stream extraction (video,
    /// optional). Demuxes the container twice: audio track → WAV →
    /// spectral/transcript, video track → PNG frames → `--ocr-binary`.
    #[arg(long)]
    pub ffmpeg_binary: Option<PathBuf>,
    /// Also run the fusion audit over the extracted channels.
    #[arg(long)]
    pub analyze: bool,
    /// Exit non-zero when the --analyze verdict reaches this level.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,
}
