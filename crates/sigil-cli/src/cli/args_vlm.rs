//! Arguments of `sigil-cli vlm-request`.

use std::path::PathBuf;

#[derive(clap::Args, Debug)]
pub struct VlmRequestCommand {
    /// Directory holding the model's digest-pinned interpreter assets
    /// (`assets/qwen2-vl-2b`). A file that differs from its pin is an error.
    #[arg(long)]
    pub vlm_assets: PathBuf,
    /// Preprocessor profile that sizes each image part.
    #[arg(
        long,
        default_value = "qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow"
    )]
    pub profile: String,
    /// One request part, in order: `text:<text>` or `image:<path>`.
    /// Repeat for each part. Text containing a special-token literal such as
    /// `<|image_pad|>` is refused.
    #[arg(long = "part", required = true)]
    pub parts: Vec<String>,
}
