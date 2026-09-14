//! Human presentation for the SIGIL pipeline. Presentation only — it
//! renders the kernel's `SigilOutput`; it never recomputes or re-derives
//! verdicts, severities, or evidence.

use crate::cli::output::{paint, style};
use sigil_core::types::{
    ByteRange, DenyReason, DetectorId, FlagReason, ScanFinding, Severity, SigilOutput, Verdict,
};

const TOKEN_DISPLAY_LIMIT: usize = 40;
const DIGEST_PREVIEW: usize = 12;

/// Full pipeline view for `tokenize`/`scan`. `input` is the raw source
/// text when available (used to slice token spans); `explain` adds the
/// stage narration that teaches the pipeline.
pub fn render_sigil(
    output: &SigilOutput,
    input: Option<&str>,
    explain: bool,
    color: bool,
) -> String {
    let mut out = String::new();
    let a = &output.assessment;

    // ── verdict banner ────────────────────────────────────────────
    out.push_str(&verdict_banner(&a.verdict, color));
    out.push('\n');
    out.push_str(&format!(
        "  severity {} · findings {} · injection {:.2}\n",
        sev(a.max_severity, color),
        a.threat_count,
        a.injection_score
    ));
    if let Some(report) = &a.perplexity {
        out.push_str(&format!("  perplexity {}\n", perplexity_line(report)));
    }
    if let Some(report) = &a.terminal {
        out.push_str(&format!("  terminal   {}\n", terminal_line(report)));
    }
    out.push_str(rule());

    // ── INTAKE ────────────────────────────────────────────────────
    if explain {
        out.push_str(&paint(
            color,
            style::CYAN,
            "  INTAKE   bytes → UTF-8 → canonical grapheme stream + provenance\n",
        ));
        out.push_str(&paint(
            color,
            style::DIM,
            "           the model never sees your bytes — it sees token IDs;\n           this stage decides which text those IDs stand for\n",
        ));
    }
    if let Some(text) = input {
        out.push_str(&format!(
            "  INPUT    \"{}\"  {} bytes · {} codepoints\n",
            esc(&truncate(text, 80)),
            text.len(),
            text.chars().count()
        ));
    }

    // ── SCAN ──────────────────────────────────────────────────────
    let findings = collect_findings(output);
    if explain {
        out.push_str(&paint(
            color,
            style::CYAN,
            "  SCAN     detectors → findings → severity → verdict\n",
        ));
    }
    if findings.is_empty() {
        out.push_str("  SCAN     no findings\n");
    } else {
        out.push_str(&format!("  FINDINGS {}\n", findings.len()));
        for finding in &findings {
            out.push_str(&render_finding(finding, input, color));
        }
    }

    // ── MERGE / TOKENS ────────────────────────────────────────────
    if explain {
        out.push_str(&paint(
            color,
            style::CYAN,
            "  MERGE    BPE merges over the canonical stream — boundaries are\n           provenance-aware; unsafe cross-boundary merges are refused\n",
        ));
    }
    out.push_str(&render_tokens(output, input, color));

    // ── EMIT / RECEIPT / EVIDENCE ─────────────────────────────────
    if explain {
        out.push_str(&paint(
            color,
            style::CYAN,
            "  EMIT     token IDs + annotations + receipt binding raw → canonical\n",
        ));
    }
    let r = &output.receipt;
    out.push_str(&format!(
        "  RECEIPT  {} raw {} canonical {}\n           normalization {} · vocab {} · tokens {}\n",
        r.digest_algorithm,
        short(&r.raw_digest, DIGEST_PREVIEW),
        short(&r.canonical_digest, DIGEST_PREVIEW),
        r.normalization,
        r.vocab,
        r.token_count
    ));
    if let Some(sig) = &r.signature {
        out.push_str(&format!(
            "           signature {} · key {}\n",
            sig.algorithm,
            short(&sig.key_id, 16)
        ));
    }
    if let Some(ev) = &output.evidence {
        out.push_str(&format!(
            "  EVIDENCE bundle {} · {} findings · persisted {}\n",
            short(&ev.id, 16),
            ev.findings.len(),
            ev.persisted
        ));
    }
    out.push_str(rule());
    out.push_str(&paint(
        color,
        style::DIM,
        "  the kernel owns this verdict — this view explains it; full detail: --format json\n",
    ));
    out
}

fn verdict_banner(verdict: &Verdict, color: bool) -> String {
    let (label, reasons, code) = match verdict {
        Verdict::Allow => ("ALLOW", String::new(), style::GREEN),
        Verdict::Flag { reasons } => (
            "FLAG",
            format!("   ·  {}", flag_reasons(reasons)),
            style::YELLOW,
        ),
        Verdict::Deny { reasons } => (
            "DENY",
            format!("   ·  {}", deny_reasons(reasons)),
            style::RED,
        ),
    };
    format!(
        "  {}{}",
        paint(color, &format!("{};{}", style::BOLD, code), label),
        reasons
    )
}

fn render_finding(finding: &ScanFinding, input: Option<&str>, color: bool) -> String {
    let mut out = format!(
        "    {:<8} {:<22} bytes {}..{}  \"{}\"\n",
        sev(finding.severity, color),
        detectors(finding),
        finding.byte_range.start,
        finding.byte_range.end,
        esc(&truncate(&finding.evidence, 60))
    );
    if let Some(span) = input.and_then(|t| slice_at(t, &finding.byte_range)) {
        out.push_str(&format!(
            "             span \"{}\"\n",
            paint(color, style::RED, &esc(&truncate(&span, 40)))
        ));
    }
    out
}

fn render_tokens(output: &SigilOutput, input: Option<&str>, color: bool) -> String {
    let n = output.token_ids.len();
    let mut out = format!("  TOKENS   {n}\n");
    let shown = n.min(TOKEN_DISPLAY_LIMIT);
    for (i, id) in output.token_ids.iter().take(shown).enumerate() {
        let ann = output.annotations.get(i);
        let text = ann
            .and_then(|a| input.and_then(|t| slice_at(t, &a.byte_range)))
            .map(|s| esc(&s))
            .unwrap_or_default();
        let range = ann
            .map(|a| format!("{}..{}", a.byte_range.start, a.byte_range.end))
            .unwrap_or_else(|| "-".to_string());
        let prov = ann
            .map(|a| format!("{:?}", a.provenance))
            .unwrap_or_default();
        let threat = ann
            .filter(|a| a.threat.severity != Severity::None)
            .map(|a| sev(a.threat.severity, color))
            .unwrap_or_default();
        let slot = if i % 2 == 0 { style::BG_A } else { style::BG_B };
        out.push_str(&format!(
            "    {:>8}  {:<14} {:<10} {:<9} {}\n",
            id,
            paint(color, slot, &format!("\"{text}\"")),
            range,
            prov.to_lowercase(),
            threat
        ));
    }
    if n > shown {
        out.push_str(&format!(
            "    … {} more tokens — --format json for the full list\n",
            n - shown
        ));
    }
    out
}

// ── shared helpers ──────────────────────────────────────────────────

fn rule() -> &'static str {
    "  ────────────────────────────────────────────────\n"
}

pub(crate) fn sev(severity: Severity, color: bool) -> String {
    let code = match severity {
        Severity::None | Severity::Low => style::CYAN,
        Severity::Medium => style::YELLOW,
        Severity::High | Severity::Critical => style::RED,
    };
    paint(color, code, &severity.to_string())
}

fn detectors(finding: &ScanFinding) -> String {
    if finding.detectors.is_empty() {
        return "-".to_string();
    }
    finding
        .detectors
        .iter()
        .map(detector_name)
        .collect::<Vec<_>>()
        .join(",")
}

fn detector_name(id: &DetectorId) -> String {
    // CamelCase → snake_case, e.g. `TokenSmuggling` → `token_smuggling`.
    let dbg = format!("{id:?}");
    let mut out = String::with_capacity(dbg.len() + 4);
    for (i, c) in dbg.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

fn flag_reasons(reasons: &[FlagReason]) -> String {
    reasons
        .iter()
        .map(|r| detectorish(&format!("{r:?}")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn deny_reasons(reasons: &[DenyReason]) -> String {
    reasons
        .iter()
        .map(|r| detectorish(&format!("{r:?}")))
        .collect::<Vec<_>>()
        .join(", ")
}

fn detectorish(dbg: &str) -> String {
    let mut out = String::with_capacity(dbg.len() + 4);
    for (i, c) in dbg.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            out.push('_');
        }
        out.push(c.to_ascii_lowercase());
    }
    out
}

/// Render text so invisible/format codepoints are visible: zero-width
/// spaces, bidi marks, and controls appear as `\u{…}` escapes rather
/// than silently vanishing — the human view must not launder the
/// representation it is explaining.
pub(crate) fn esc(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if c.is_control() || is_invisible(c) {
            out.push_str(&format!("\\u{{{:04x}}}", c as u32));
        } else {
            out.push(c);
        }
    }
    out
}

fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{200B}'..='\u{200F}'
            | '\u{202A}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{FEFF}'
    )
}

fn slice_at(text: &str, range: &ByteRange) -> Option<String> {
    if range.end > text.len() || range.start > range.end {
        return None;
    }
    Some(String::from_utf8_lossy(&text.as_bytes()[range.start..range.end]).into_owned())
}

fn short(s: &str, n: usize) -> String {
    truncate(s, n)
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n).collect::<String>())
    }
}

fn collect_findings(output: &SigilOutput) -> Vec<&ScanFinding> {
    // Prefer the evidence bundle's complete finding list; fall back to
    // annotation threats when no bundle was emitted (e.g. Allow verdict
    // under the default evidence policy).
    if let Some(evidence) = &output.evidence {
        if !evidence.findings.is_empty() {
            return evidence.findings.iter().collect();
        }
    }
    output
        .annotations
        .iter()
        .map(|a| &a.threat)
        .filter(|t| t.severity != Severity::None)
        .collect()
}

fn perplexity_line(report: &sigil_core::perplexity::PerplexityReport) -> String {
    use sigil_core::perplexity::PerplexityStatus;
    match &report.status {
        PerplexityStatus::Evaluated => format!(
            "evaluated · scorer {} · {} flagged window{}",
            report.scorer,
            report.flagged.len(),
            if report.flagged.len() == 1 { "" } else { "s" }
        ),
        PerplexityStatus::Skipped { reason } => format!("skipped ({reason})"),
        PerplexityStatus::Failed { reason } => format!("failed ({reason})"),
    }
}

fn terminal_line(report: &sigil_core::terminal::TerminalReport) -> String {
    use sigil_core::terminal::TerminalStatus;
    match &report.status {
        TerminalStatus::Evaluated => format!(
            "evaluated · scanner {} · {} sequence{}",
            report.scanner,
            report.sequence_count,
            if report.sequence_count == 1 { "" } else { "s" }
        ),
        TerminalStatus::Skipped { reason } => format!("skipped ({reason})"),
        TerminalStatus::Failed { reason } => format!("failed ({reason})"),
    }
}
