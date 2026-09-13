use crate::helpers::{compose_verdict, stable_hash, truncate_output, validate_schema};
use crate::types::*;
use sigil_core::{
    engine::Sigil,
    policy::{Policy, TaintPolicy},
    types::{FlagReason, Provenance, Severity, TextSegment, TrustLevel, Verdict},
    Vocab,
};

#[derive(Clone, Debug)]
pub struct McpGate {
    sigil: Sigil,
    config: McpScanConfig,
}

impl McpGate {
    pub fn new(policy: Policy, config: McpScanConfig, vocab: Vocab) -> Result<Self> {
        Ok(Self {
            sigil: Sigil::new(vocab, policy)?,
            config,
        })
    }

    pub fn config(&self) -> &McpScanConfig {
        &self.config
    }
}

#[derive(Clone, Debug)]
pub struct McpSession {
    gate: McpGate,
    combined_taint: Severity,
}

impl McpSession {
    pub fn new(gate: McpGate) -> Self {
        Self {
            gate,
            combined_taint: Severity::None,
        }
    }

    pub fn inspect_response(
        &mut self,
        server_id: &str,
        request_hash: &str,
        response: &str,
        declared_schema: Option<&ResponseSchema>,
    ) -> Result<McpInspection> {
        let profile = self
            .gate
            .config
            .server_profiles
            .get(server_id)
            .cloned()
            .unwrap_or_else(|| ServerTrustProfile::default_for(server_id));

        let core_output = self.gate.sigil.process_text_segments(&[TextSegment {
            text: response,
            provenance: Provenance::McpTool,
        }])?;

        let schema_valid = if self.gate.config.schema_validation {
            match declared_schema {
                Some(schema) => validate_schema(response, schema),
                None => true,
            }
        } else {
            true
        };

        let budget = profile
            .token_budget
            .min(self.gate.config.max_response_tokens);
        let token_budget_used = core_output.token_ids.len().min(budget);
        let context_output = truncate_output(core_output.clone(), token_budget_used);

        let mut final_verdict = compose_verdict(
            &self.gate.sigil.policy().sigil.mode,
            &profile,
            &context_output,
            self.combined_taint,
            schema_valid,
            self.gate.config.resource_policy,
        );

        if profile.trust_level <= TrustLevel::Bounded
            && matches!(
                context_output.assessment.max_severity,
                Severity::Low | Severity::Medium
            )
            && matches!(final_verdict, Verdict::Allow)
        {
            final_verdict = Verdict::Flag {
                reasons: vec![FlagReason::DlpFinding],
            };
        }

        self.update_history(&profile, &final_verdict);
        self.combine_taint(context_output.assessment.max_severity);

        let evidence = McpEvidenceRecord::new(McpEvidenceRecordInput {
            server_id,
            request_hash,
            response,
            context_output: &context_output,
            final_verdict: final_verdict.clone(),
            schema_valid,
            tokens_consumed: token_budget_used,
            sigil_version: self.gate.sigil.policy().sigil.version.clone(),
        });

        Ok(McpInspection {
            server_id: server_id.to_string(),
            request_hash: request_hash.to_string(),
            response_hash: stable_hash(response),
            trust_profile: profile,
            schema_valid,
            token_budget_used,
            accumulated_taint: self.combined_taint,
            context_output,
            verdict: final_verdict,
            evidence,
        })
    }

    fn update_history(&mut self, profile: &ServerTrustProfile, verdict: &Verdict) {
        let mut updated = profile.clone();
        updated.history.seen_responses += 1;
        match verdict {
            Verdict::Allow => updated.history.allowed += 1,
            Verdict::Flag { .. } => updated.history.flagged += 1,
            Verdict::Deny { .. } => updated.history.denied += 1,
        }

        self.gate
            .config
            .server_profiles
            .insert(updated.server_id.clone(), updated);
    }

    fn combine_taint(&mut self, severity: Severity) {
        self.combined_taint = match self.gate.config.cross_tool_taint {
            TaintPolicy::Accumulate => self.combined_taint.max(severity),
            TaintPolicy::Reset => severity,
            TaintPolicy::Inherit => self.combined_taint.max(severity),
        };
    }
}
