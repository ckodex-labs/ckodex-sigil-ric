//! The evidence-sink surface lives in `sigil-core` so `EvidenceBundle`
//! (scan path) and `McpEvidenceRecord` (this crate) share one persistence
//! contract. Re-exported here to keep the `sigil-mcp` public API stable.

pub use sigil_core::sink::{EvidenceSink, JsonlEvidenceSink};
