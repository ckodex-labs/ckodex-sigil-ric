use crate::types::{McpEvidenceRecord, Result};
use std::io::Write;

/// Persistence surface for `McpEvidenceRecord`s.
///
/// Every inspected MCP response produces an evidence record that must be
/// persisted — the gate hands each record to the configured sink so the
/// record outlives the session's in-memory history.
pub trait EvidenceSink {
    fn record(&mut self, record: &McpEvidenceRecord) -> Result<()>;
}

/// Append-only JSONL sink — one serialized record per line, created or
/// appended at the configured path.
pub struct JsonlEvidenceSink {
    inner: Box<dyn Write + Send>,
}

impl JsonlEvidenceSink {
    pub fn new(inner: impl Write + Send + 'static) -> Self {
        Self {
            inner: Box::new(inner),
        }
    }

    /// Open (or create) an append-only JSONL file at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        Ok(Self::new(file))
    }
}

impl EvidenceSink for JsonlEvidenceSink {
    fn record(&mut self, record: &McpEvidenceRecord) -> Result<()> {
        serde_json::to_writer(&mut self.inner, record)?;
        self.inner.write_all(b"\n")?;
        self.inner.flush()?;
        Ok(())
    }
}
