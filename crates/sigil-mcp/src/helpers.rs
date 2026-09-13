use crate::types::*;
use sigil_core::{
    policy::Mode,
    types::{FlagReason, Severity, SigilOutput, Verdict},
};

pub(crate) fn truncate_output(output: SigilOutput, budget: usize) -> SigilOutput {
    if output.token_ids.len() <= budget {
        return output;
    }

    let mut receipt = output.receipt;
    receipt.token_count = budget;
    SigilOutput {
        token_ids: output.token_ids[..budget].to_vec(),
        annotations: output.annotations[..budget].to_vec(),
        assessment: output.assessment,
        evidence: output.evidence,
        receipt,
    }
}

pub(crate) fn compose_verdict(
    mode: &Mode,
    profile: &ServerTrustProfile,
    output: &SigilOutput,
    accumulated_taint: Severity,
    schema_valid: bool,
    resource_policy: ResourcePolicy,
) -> Verdict {
    let effective_severity = output.assessment.max_severity.max(accumulated_taint);
    let injection_score = output.assessment.injection_score;

    let mut base = match output.assessment.verdict.clone() {
        Verdict::Allow if effective_severity >= Severity::Critical => Verdict::Deny {
            reasons: vec![sigil_core::types::DenyReason::CriticalFinding],
        },
        Verdict::Allow if effective_severity >= Severity::High => {
            if matches!(mode, Mode::Monitor) {
                Verdict::Flag {
                    reasons: vec![FlagReason::InjectionPattern],
                }
            } else {
                Verdict::Deny {
                    reasons: vec![sigil_core::types::DenyReason::PolicyViolation],
                }
            }
        }
        Verdict::Allow if effective_severity >= Severity::Medium => Verdict::Flag {
            reasons: vec![FlagReason::DlpFinding],
        },
        verdict => verdict,
    };

    if injection_score >= profile.injection_threshold {
        base = match resource_policy {
            ResourcePolicy::Deny => Verdict::Deny {
                reasons: vec![sigil_core::types::DenyReason::PolicyViolation],
            },
            _ => Verdict::Flag {
                reasons: vec![FlagReason::InjectionPattern],
            },
        };
    }

    if !schema_valid {
        base = match resource_policy {
            ResourcePolicy::Deny => Verdict::Deny {
                reasons: vec![sigil_core::types::DenyReason::SchemaViolation],
            },
            ResourcePolicy::Scan | ResourcePolicy::ScanAndQuarantine => Verdict::Flag {
                reasons: vec![FlagReason::SchemaMismatch],
            },
        };
    }

    base
}

pub(crate) fn validate_schema(response: &str, schema: &ResponseSchema) -> bool {
    match schema.content_type {
        ContentType::Json => {
            let value: serde_json::Value = match serde_json::from_str(response) {
                Ok(value) => value,
                Err(_) => return false,
            };

            let object = match value.as_object() {
                Some(object) => object,
                None => return false,
            };

            schema
                .required_fields
                .iter()
                .all(|field| object.contains_key(field))
        }
        ContentType::Text
        | ContentType::Markdown
        | ContentType::Xml
        | ContentType::Binary
        | ContentType::Unknown => schema.required_fields.is_empty(),
    }
}

pub(crate) fn stable_hash(input: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("mcp-{:016x}", hash)
}
