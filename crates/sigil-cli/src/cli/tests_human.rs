use crate::cli::human::{esc, render_sigil};
use crate::cli::human_reports::*;
use crate::cli::output::{paint, style, Printer};
use crate::cli::types::{ColorMode, OutputFormat};
use sigil_core::{Policy, Sigil, Vocab};

fn scan(text: &str) -> sigil_core::SigilOutput {
    Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default())
        .expect("engine")
        .scan_text(text)
        .expect("scan")
}

#[test]
fn render_allow_verdict_contains_pipeline_sections() {
    let output = scan("hello world");
    let rendered = render_sigil(&output, Some("hello world"), false, false);
    assert!(rendered.contains("ALLOW"));
    assert!(rendered.contains("TOKENS"));
    assert!(rendered.contains("RECEIPT"));
    assert!(rendered.contains("15339"));
    // no color → no escape sequences
    assert!(!rendered.contains('\x1b'));
}

#[test]
fn render_flag_verdict_shows_reason_and_visible_invisible() {
    let output = scan("hello\u{200B}world");
    let rendered = render_sigil(&output, Some("hello\u{200B}world"), false, false);
    assert!(rendered.contains("FLAG"));
    assert!(rendered.contains("smuggling"));
    // zero-width space must be rendered as a visible escape, never raw
    assert!(rendered.contains("\\u{200b}"));
    assert!(!rendered.contains('\u{200B}'));
}

#[test]
fn render_explain_adds_stage_narration() {
    let output = scan("hello world");
    let rendered = render_sigil(&output, Some("hello world"), true, false);
    for stage in ["INTAKE", "SCAN", "MERGE", "EMIT"] {
        assert!(rendered.contains(stage), "missing stage {stage}");
    }
}

#[test]
fn render_bounded_tokens_truncate_notice() {
    let long = "lorem ipsum dolor sit amet ".repeat(30);
    let output = scan(&long);
    let rendered = render_sigil(&output, Some(&long), false, false);
    if output.token_ids.len() > 40 {
        assert!(rendered.contains("more tokens"));
    }
}

#[test]
fn esc_renders_invisible_codepoints_visibly() {
    assert_eq!(esc("a\u{200B}b"), "a\\u{200b}b");
    assert_eq!(esc("x\u{202E}y"), "x\\u{202e}y");
    assert_eq!(esc("plain"), "plain");
    assert_eq!(esc("nl\n"), "nl\\u{000a}");
}

#[test]
fn paint_respects_enabled_flag() {
    assert_eq!(paint(true, style::RED, "x"), "\x1b[31mx\x1b[0m");
    assert_eq!(paint(false, style::RED, "x"), "x");
    assert_eq!(paint(true, style::RED, ""), "");
}

#[test]
fn printer_forced_modes_are_deterministic() {
    let json = Printer::detect(OutputFormat::Json, ColorMode::Never);
    assert!(!json.human);
    assert!(!json.color);
    let human = Printer::detect(OutputFormat::Human, ColorMode::Always);
    assert!(human.human);
    assert!(human.color);
    // ColorMode::Never wins regardless of format
    let human_nocolor = Printer::detect(OutputFormat::Human, ColorMode::Never);
    assert!(human_nocolor.human);
    assert!(!human_nocolor.color);
}

#[test]
fn render_decode_result() {
    let r = crate::cli::results::DecodeResult {
        ids: vec![15339, 1917],
        text: "hello world".to_string(),
    };
    let rendered = render_decode(&r, false);
    assert!(rendered.contains("DECODE"));
    assert!(rendered.contains("hello world"));
}

#[test]
fn render_verification_valid_and_invalid() {
    let ok = render_verification(true, "", None, false);
    assert!(ok.contains("VALID"));
    let bad = render_verification(false, "", Some("bad sig"), false);
    assert!(bad.contains("INVALID"));
    assert!(bad.contains("bad sig"));
}

#[test]
fn render_keygen_outcome_lists_paths() {
    let r = crate::cli::commands::KeygenOutcome {
        key_id: "k1".to_string(),
        verification_key_hex: "ab".to_string(),
        private_key_path: "/tmp/priv.pem".to_string(),
        public_key_path: "/tmp/pub.pem".to_string(),
    };
    let rendered = render_keygen(&r, false);
    assert!(rendered.contains("KEYGEN"));
    assert!(rendered.contains("/tmp/priv.pem"));
    assert!(rendered.contains("k1"));
}

#[test]
fn render_sentinel_verdict_scores() {
    let v = sigil_s::SentinelVerdict::none();
    let rendered = render_sentinel(&v, false);
    assert!(rendered.contains("SENTINEL"));
}
