use thiserror::Error;

#[derive(Debug, Error)]
pub enum SigilError {
    #[error("input exceeds maximum configured bytes")]
    InputTooLarge,
    #[error("invalid utf-8 input")]
    InvalidUtf8,
    #[error("failed to parse policy: {0}")]
    PolicyParse(#[from] toml::de::Error),
    #[error("failed to parse json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("schema validation error: {0}")]
    Schema(String),
}

pub type Result<T> = std::result::Result<T, SigilError>;
