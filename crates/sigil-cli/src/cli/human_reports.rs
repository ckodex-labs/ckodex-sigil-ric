//! Human renderers for the non-pipeline commands. Same discipline as
//! `human.rs`: render the kernel/command outcome; never recompute it.

use crate::cli::commands::{KeygenOutcome, PerceiveOutcome};
use crate::cli::human::{esc, sev};
use crate::cli::output::{paint, style};
use crate::cli::results::{BatchDecodeResult, BatchTokenizeResult, DecodeResult};
use sigil_core::attestation::DsseEnvelope;
use sigil_core::types::Verdict;
use sigil_mcp::McpInspection;
use sigil_multimodal::MultimodalAssessment;
use sigil_probe::{HealthAction, HealthReport};
use sigil_s::{CompositeVerdict, SentinelVerdict};

pub fn render_decode(r: &DecodeResult, color: bool) -> String {
    format!(
        "  {} id{} → \"{}\"\n",
        paint(color, style::BOLD, "DECODE"),
        r.ids.len(),
        esc(&r.text)
    )
}

pub fn render_batch_tokenize(r: &BatchTokenizeResult, color: bool) -> String {
    let mut out = format!(
        "  {}  {} input{}\n",
        paint(color, style::BOLD, "BATCH TOKENIZE"),
        r.inputs.len(),
        plural(r.inputs.len())
    );
    for (input, ids) in r.inputs.iter().zip(&r.token_ids).take(10) {
        out.push_str(&format!(
            "    \"{}\" → {} token{}\n",
            esc(&truncate(input, 40)),
            ids.len(),
            plural(ids.len())
        ));
    }
    if r.inputs.len() > 10 {
        out.push_str("    … more — --format json for the full list\n");
    }
    out
}

pub fn render_batch_decode(r: &BatchDecodeResult, color: bool) -> String {
    let mut out = format!(
        "  {}  {} batch{}\n",
        paint(color, style::BOLD, "BATCH DECODE"),
        r.batches.len(),
        plural(r.batches.len())
    );
    for (ids, text) in r.batches.iter().zip(&r.texts).take(10) {
        out.push_str(&format!(
            "    {} id{} → \"{}\"\n",
            ids.len(),
            plural(ids.len()),
            esc(&truncate(text, 60))
        ));
    }
    if r.batches.len() > 10 {
        out.push_str("    … more — --format json for the full list\n");
    }
    out
}

pub fn render_keygen(r: &KeygenOutcome, color: bool) -> String {
    format!(
        "  {}  ecdsa-p384 signing key\n  key id      {}\n  private     {}\n  public      {}\n  verify      {}\n",
        paint(color, style::BOLD, "KEYGEN"),
        r.key_id,
        r.private_key_path,
        r.public_key_path,
        paint(color, style::DIM, "keep the private key out of VCS"),
    )
}

pub fn render_verification(valid: bool, detail: &str, error: Option<&str>, color: bool) -> String {
    let (label, code) = if valid {
        ("VALID", style::GREEN)
    } else {
        ("INVALID", style::RED)
    };
    let mut out = format!(
        "  {}\n{detail}",
        paint(color, &format!("{};{}", style::BOLD, code), label)
    );
    if let Some(err) = error {
        out.push_str(&format!("  error       {err}\n"));
    }
    out
}

pub fn render_attest(env: &DsseEnvelope, color: bool) -> String {
    format!(
        "  {}  dsse envelope\n  payload     {}\n  signatures  {}\n",
        paint(color, style::BOLD, "ATTEST"),
        env.payload_type,
        env.signatures
            .iter()
            .map(|s| s.keyid.clone())
            .collect::<Vec<_>>()
            .join(", ")
    )
}

pub fn render_mcp(r: &McpInspection, color: bool) -> String {
    let mut out = verdict_line(&r.verdict, color);
    out.push_str(&format!(
        "  server      {} (trust {:?})\n  schema      {} · tokens {} · taint {}\n",
        r.trust_profile.server_id,
        r.trust_profile.trust_level,
        r.schema_valid,
        r.token_budget_used,
        sev(r.accumulated_taint, color)
    ));
    out.push_str(&format!(
        "  evidence    request {}… response {}…\n",
        truncate(&r.evidence.request_hash, 12),
        truncate(&r.evidence.response_hash, 12)
    ));
    out
}

pub fn render_probe(r: &HealthReport, color: bool) -> String {
    let mut out = format!(
        "  {}  score {:.2} · identity {:.2}\n  action      {}\n  drift       {:.2} ({}) triggered {}\n",
        paint(color, style::BOLD, "PROBE"),
        r.score,
        r.identity_confidence,
        health_action(&r.action),
        r.drift.score,
        format!("{:?}", r.drift.category).to_lowercase(),
        r.drift.triggered
    );
    for s in &r.signals {
        out.push_str(&format!(
            "    {:<8} {:<32} {:.2}  {}\n",
            sev(s.severity, color),
            format!("{:?}", s.kind).to_lowercase(),
            s.score,
            truncate(&s.detail, 48)
        ));
    }
    out
}

fn health_action(action: &HealthAction) -> String {
    match action {
        HealthAction::Nominal => "nominal".to_string(),
        HealthAction::IncreasedMonitoring { reason } => format!("monitor ({reason})"),
        HealthAction::Alert { severity, reason } => {
            format!("alert {severity} ({reason})")
        }
        HealthAction::TriggerShieldAudit { .. } => "shield audit".to_string(),
        HealthAction::IdentityVerification { confidence } => {
            format!("verify identity ({confidence:.2})")
        }
        HealthAction::Failover { reason } => format!("failover ({reason})"),
    }
}

pub fn render_multimodal(r: &MultimodalAssessment, color: bool) -> String {
    let mut out = verdict_line(&r.verdict, color);
    out.push_str(&format!(
        "  authority ceiling   {}\n  cross-modal         {} · fusion max {}\n",
        format!("{:?}", r.authority_ceiling).to_lowercase(),
        sev(r.cross_modal.max_severity, color),
        sev(r.fusion.max_severity, color)
    ));
    for (name, m) in [
        ("vision", &r.vision),
        ("audio", &r.audio),
        ("code", &r.code),
    ]
    .into_iter()
    .filter_map(|(n, m)| m.as_ref().map(|m| (n, m)))
    {
        out.push_str(&format!(
            "    {:<8} {} · {} finding{} · taint {}\n",
            name,
            verdict_word(&m.verdict, color),
            m.findings.len(),
            plural(m.findings.len()),
            sev(m.cross_modal_taint, color)
        ));
    }
    for c in &r.cross_modal.correlations {
        out.push_str(&format!(
            "    {:<8} {}  {}\n",
            sev(c.severity, color),
            c.modalities
                .iter()
                .map(|m| format!("{m:?}").to_lowercase())
                .collect::<Vec<_>>()
                .join("+"),
            truncate(&c.detail, 48)
        ));
    }
    out
}

pub fn render_sentinel(r: &SentinelVerdict, color: bool) -> String {
    format!(
        "  {}  {:?} · confidence {:.2}\n  threat {:.2}  injection {:.2}  jailbreak {:.2}\n  dlp {:.2}  safety {:.2}  adversarial {:.2}\n  {}\n",
        paint(color, style::BOLD, "SENTINEL"),
        r.action,
        r.confidence,
        r.threat_score,
        r.injection_score,
        r.jailbreak_score,
        r.dlp_risk,
        r.safety_score,
        r.adversarial_score,
        paint(color, style::DIM, &r.rationale)
    )
}

pub fn render_composite(r: &CompositeVerdict, color: bool) -> String {
    let mut out = verdict_line(&r.final_verdict, color);
    out.push_str(&format!(
        "  sigil severity {} · sentinel {:?}\n  {}\n",
        sev(r.sigil_severity, color),
        r.sentinel.action,
        paint(color, style::DIM, &r.rationale)
    ));
    out
}

pub fn render_perceive(r: &PerceiveOutcome, color: bool) -> String {
    let report = &r.report;
    let mut out = format!(
        "  {}  {} via {}\n  artifact    sha384 {}…\n",
        paint(color, style::BOLD, "PERCEIVE"),
        report.media_type,
        r.adapter_id,
        truncate(&report.artifact_digest, 16)
    );
    for ch in &report.channels {
        out.push_str(&format!(
            "    {:?}  \"{}\"{}{}\n",
            ch.channel_kind,
            esc(&truncate(&ch.content, 56)),
            if ch.truncated { " [truncated]" } else { "" },
            ch.confidence
                .map(|c| format!("  conf {c:.2}"))
                .unwrap_or_default()
        ));
    }
    if let Some(analysis) = &r.analysis {
        out.push_str(&verdict_line(&analysis.verdict, color));
    }
    out
}

// ── shared ──────────────────────────────────────────────────────────

fn verdict_line(verdict: &Verdict, color: bool) -> String {
    format!("  {}\n", verdict_word(verdict, color))
}

fn verdict_word(verdict: &Verdict, color: bool) -> String {
    let (word, code) = match verdict {
        Verdict::Allow => ("ALLOW", style::GREEN),
        Verdict::Flag { .. } => ("FLAG", style::YELLOW),
        Verdict::Deny { .. } => ("DENY", style::RED),
    };
    paint(color, &format!("{};{}", style::BOLD, code), word)
}

fn plural(n: usize) -> &'static str {
    if n == 1 {
        ""
    } else {
        "s"
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}
