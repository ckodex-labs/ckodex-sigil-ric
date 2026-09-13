//! SIGIL MCP gate.
//!
//! This crate wraps SIGIL-core with per-server trust profiles, schema
//! validation, token budgeting, and cross-tool taint accumulation so that
//! MCP responses never enter a model context uninspected.

mod helpers;
mod session;
mod types;

pub use session::{McpGate, McpSession};
pub use types::{
    ContentType, McpEvidenceRecord, McpInspection, McpScanConfig, ResourcePolicy, ResponseSchema,
    Result, ServerHistory, ServerTrustProfile,
};

#[cfg(test)]
mod tests;
