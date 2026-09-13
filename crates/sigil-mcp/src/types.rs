use crate::helpers::stable_hash;
use serde::{Deserialize, Serialize};
use sigil_core::{
    error::Result as CoreResult,
    policy::TaintPolicy,
    types::{Provenance, Severity, SigilOutput, TrustLevel, Verdict},
};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

pub type Result<T> = CoreResult<T>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentType {
    #[default]
    Text,
    Json,
    Markdown,
    Xml,
    Binary,
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourcePolicy {
    #[default]
    Scan,
    ScanAndQuarantine,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct ServerHistory {
    #[serde(default)]
    pub seen_responses: usize,
    #[serde(default)]
    pub allowed: usize,
    #[serde(default)]
    pub flagged: usize,
    #[serde(default)]
    pub denied: usize,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ServerTrustProfile {
    pub server_id: String,
    #[serde(default)]
    pub trust_level: TrustLevel,
    #[serde(default = "ServerTrustProfile::default_allowed_content_types")]
    pub allowed_content_types: Vec<ContentType>,
    #[serde(default = "ServerTrustProfile::default_injection_threshold")]
    pub injection_threshold: f32,
    #[serde(default = "ServerTrustProfile::default_token_budget")]
    pub token_budget: usize,
    #[serde(default)]
    pub history: ServerHistory,
}

impl ServerTrustProfile {
    fn default_allowed_content_types() -> Vec<ContentType> {
        vec![ContentType::Text, ContentType::Json, ContentType::Markdown]
    }

    fn default_injection_threshold() -> f32 {
        0.65
    }

    fn default_token_budget() -> usize {
        4_096
    }

    pub fn default_for(server_id: impl Into<String>) -> Self {
        Self {
            server_id: server_id.into(),
            trust_level: TrustLevel::Untrusted,
            allowed_content_types: Self::default_allowed_content_types(),
            injection_threshold: Self::default_injection_threshold(),
            token_budget: Self::default_token_budget(),
            history: ServerHistory::default(),
        }
    }
}

impl Default for ServerTrustProfile {
    fn default() -> Self {
        Self::default_for("unknown")
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ResponseSchema {
    #[serde(default)]
    pub content_type: ContentType,
    #[serde(default)]
    pub required_fields: Vec<String>,
    #[serde(default = "ResponseSchema::default_allow_additional")]
    pub allow_additional: bool,
}

impl ResponseSchema {
    fn default_allow_additional() -> bool {
        true
    }
}

impl Default for ResponseSchema {
    fn default() -> Self {
        Self {
            content_type: ContentType::Text,
            required_fields: Vec::new(),
            allow_additional: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpScanConfig {
    #[serde(default = "McpScanConfig::default_true")]
    pub schema_validation: bool,
    #[serde(default = "McpScanConfig::default_max_response_tokens")]
    pub max_response_tokens: usize,
    #[serde(default)]
    pub server_profiles: HashMap<String, ServerTrustProfile>,
    #[serde(default)]
    pub cross_tool_taint: TaintPolicy,
    #[serde(default)]
    pub resource_policy: ResourcePolicy,
}

impl McpScanConfig {
    fn default_true() -> bool {
        true
    }

    fn default_max_response_tokens() -> usize {
        4_096
    }
}

impl Default for McpScanConfig {
    fn default() -> Self {
        Self {
            schema_validation: true,
            max_response_tokens: Self::default_max_response_tokens(),
            server_profiles: HashMap::new(),
            cross_tool_taint: TaintPolicy::Accumulate,
            resource_policy: ResourcePolicy::Scan,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpInspection {
    pub server_id: String,
    pub request_hash: String,
    pub response_hash: String,
    pub trust_profile: ServerTrustProfile,
    pub schema_valid: bool,
    pub token_budget_used: usize,
    pub accumulated_taint: Severity,
    pub context_output: SigilOutput,
    pub verdict: Verdict,
    pub evidence: McpEvidenceRecord,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpEvidenceRecord {
    pub server_id: String,
    pub request_hash: String,
    pub response_hash: String,
    pub scan_result: SigilOutput,
    pub taint_applied: Provenance,
    pub tokens_consumed: usize,
    pub schema_valid: bool,
    pub final_verdict: Verdict,
    pub timestamp_unix_ms: u64,
    pub sigil_version: String,
}

#[derive(Clone, Debug)]
pub(crate) struct McpEvidenceRecordInput<'a> {
    pub(crate) server_id: &'a str,
    pub(crate) request_hash: &'a str,
    pub(crate) response: &'a str,
    pub(crate) context_output: &'a SigilOutput,
    pub(crate) final_verdict: Verdict,
    pub(crate) schema_valid: bool,
    pub(crate) tokens_consumed: usize,
    pub(crate) sigil_version: String,
}

impl McpEvidenceRecord {
    pub(crate) fn new(input: McpEvidenceRecordInput<'_>) -> Self {
        let timestamp_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_millis() as u64)
            .unwrap_or_default();

        Self {
            server_id: input.server_id.to_string(),
            request_hash: input.request_hash.to_string(),
            response_hash: stable_hash(input.response),
            scan_result: input.context_output.clone(),
            taint_applied: Provenance::McpTool,
            tokens_consumed: input.tokens_consumed,
            schema_valid: input.schema_valid,
            final_verdict: input.final_verdict,
            timestamp_unix_ms,
            sigil_version: input.sigil_version,
        }
    }
}
