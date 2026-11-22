//! The target model's interpreter for vision-language requests (RIC-MM-001
//! WP6): a byte-level BPE loader and the Qwen2-VL request ID stream, both
//! read from digest-pinned assets.

pub mod bpe;
pub mod qwen2vl;

pub use bpe::{ByteLevelBpe, TokenizerError};
pub use qwen2vl::{
    AssetPin, IdStream, InterpreterError, Part, ProcessorConfig, QWEN2_VL_2B, Qwen2VlInterpreter,
    identity_digest, ids_sha384,
};
