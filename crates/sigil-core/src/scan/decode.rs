//! Encoded/hidden-surface rescan: content that reaches the model in a form
//! upstream inspection did not see — base64/percent/hex/entity spans and
//! HTML comments — is decoded (or unwrapped) and passed back through the
//! text-level detectors. Findings map to the *source* span, so an
//! instruction inside an encoding can never score below its plaintext.
//! Presence alone is not a finding: only decoded content that trips the
//! inner detectors is reported, which keeps the false-positive rate bounded
//! by the base scanners. Bounded like the window model — span, size, and
//! nesting caps surface findings rather than abort the scan.

use super::detectors::detect_injection;
use super::types::TextMap;
use crate::policy::Policy;
use crate::types::{ByteRange, DetectorId, ScanFinding, Severity};
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine;
use once_cell::sync::Lazy;
use regex::Regex;

const MAX_SPANS: usize = 64;
const MAX_DECODED: usize = 32 * 1024;
const MAX_DEPTH: usize = 2;
const PRINTABLE_MIN: f32 = 0.6;

struct EncodedSpan {
    start: usize,
    end: usize,
    scheme: &'static str,
}

/// Span table: (scheme, regex, capture-group). Group 0 = the whole match;
/// markup schemes capture the *hidden interior* so the rescan targets the
/// content a renderer would conceal, not the markup itself.
fn span_regexes() -> &'static [(&'static str, Regex, usize)] {
    static SPANS: Lazy<Vec<(&'static str, Regex, usize)>> = Lazy::new(|| {
        vec![
            (
                "comment",
                Regex::new(r"<!--[\s\S]*?-->").expect("comment regex"),
                0,
            ),
            (
                "link-target",
                Regex::new(r"\]\(\s*([^)\s]{4,})\s*\)").expect("link-target regex"),
                1,
            ),
            (
                "css-hidden",
                Regex::new(
                    r#"<[a-zA-Z][a-zA-Z0-9]*[^>]*style\s*=\s*"[^"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0)[^"]*"[^>]*>\s*([^<]{4,})"#,
                )
                .expect("css-hidden regex"),
                1,
            ),
            (
                "html-hidden",
                Regex::new(r#"<[a-zA-Z][a-zA-Z0-9]*[^>]*\shidden(?:\s[^>]*)?>\s*([^<]{4,})"#)
                    .expect("html-hidden regex"),
                1,
            ),
            (
                "percent",
                Regex::new(r"(?:%[0-9A-Fa-f]{2}){4,}").expect("percent regex"),
                0,
            ),
            (
                "hex-esc",
                Regex::new(r"(?:\\x[0-9A-Fa-f]{2}){4,}").expect("hex-esc regex"),
                0,
            ),
            (
                "entity",
                Regex::new(r"(?:&#x?[0-9A-Fa-f]{1,6};){3,}").expect("entity regex"),
                0,
            ),
            (
                "base64",
                Regex::new(r"[A-Za-z0-9+/=_-]{20,}").expect("base64 regex"),
                0,
            ),
        ]
    });
    &SPANS
}

/// Collect candidate spans across all schemes, preferring earlier-then-
/// larger spans and dropping overlaps (a comment's interior base64 is
/// handled by the recursive rescan, not a second top-level span).
fn find_spans(text: &str) -> Vec<EncodedSpan> {
    let mut spans: Vec<EncodedSpan> = span_regexes()
        .iter()
        .flat_map(|(scheme, re, group)| {
            re.captures_iter(text).filter_map(|cap| {
                cap.get(*group).map(|m| EncodedSpan {
                    start: m.start(),
                    end: m.end(),
                    scheme,
                })
            })
        })
        .collect();
    spans.sort_by_key(|s| (s.start, usize::MAX - s.end));
    let mut taken: Vec<EncodedSpan> = Vec::new();
    for span in spans {
        if taken
            .iter()
            .all(|t| span.start >= t.end || span.end <= t.start)
        {
            taken.push(span);
        }
    }
    taken
}

fn decode_candidates(text: &str, scheme: &str) -> Vec<(&'static str, String)> {
    match scheme {
        "base64" => {
            let mut out = Vec::new();
            for (label, engine) in [
                ("base64", STANDARD),
                ("base64url", URL_SAFE),
                ("base64-nopad", STANDARD_NO_PAD),
                ("base64url-nopad", URL_SAFE_NO_PAD),
            ] {
                if let Ok(bytes) = engine.decode(text) {
                    out.push((label, String::from_utf8_lossy(&bytes).into_owned()));
                    break;
                }
            }
            // An all-hex run is also valid base64 text — try the hex
            // interpretation when the charset admits it.
            if let Some(hexed) = decode_hex_bare(text) {
                out.push(("hex", hexed));
            }
            out
        }
        "percent" => decode_percent(text)
            .into_iter()
            .map(|d| ("percent", d))
            .collect(),
        "hex-esc" => decode_hex_esc(text)
            .into_iter()
            .map(|d| ("hex-esc", d))
            .collect(),
        "entity" => decode_entities(text)
            .into_iter()
            .map(|d| ("entity", d))
            .collect(),
        "comment" => vec![("comment", text[4..text.len() - 3].to_string())],
        // Markup surfaces pass their interior through verbatim — the
        // "decode" is the unwrap itself.
        "link-target" => vec![("link-target", text.to_string())],
        "css-hidden" => vec![("css-hidden", text.to_string())],
        "html-hidden" => vec![("html-hidden", text.to_string())],
        _ => Vec::new(),
    }
}

fn decode_percent(text: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = text
        .as_bytes()
        .chunks(3)
        .map(|c| {
            (c.len() == 3 && c[0] == b'%')
                .then(|| u8::from_str_radix(std::str::from_utf8(&c[1..]).ok()?, 16).ok())
                .flatten()
        })
        .collect();
    bytes.map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn decode_hex_esc(text: &str) -> Option<String> {
    let bytes: Option<Vec<u8>> = text
        .as_bytes()
        .chunks(4)
        .map(|c| {
            (c.len() == 4 && c[0] == b'\\' && c[1] == b'x')
                .then(|| u8::from_str_radix(std::str::from_utf8(&c[2..]).ok()?, 16).ok())
                .flatten()
        })
        .collect();
    bytes.map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn decode_hex_bare(text: &str) -> Option<String> {
    (text.len() % 2 == 0 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| {
            (0..text.len())
                .step_by(2)
                .filter_map(|i| u8::from_str_radix(&text[i..i + 2], 16).ok())
                .collect::<Vec<u8>>()
        })
        .map(|b| String::from_utf8_lossy(&b).into_owned())
}

fn decode_entities(text: &str) -> Option<String> {
    static ENTITY: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"&#x?([0-9A-Fa-f]{1,6});").expect("entity item regex"));
    let mut out = String::new();
    for cap in ENTITY.captures_iter(text) {
        let digits = cap.get(1)?.as_str();
        let value = if cap.get(0)?.as_str().starts_with("&#x") {
            u32::from_str_radix(digits, 16).ok()?
        } else {
            digits.parse::<u32>().ok()?
        };
        out.push(char::from_u32(value)?);
    }
    Some(out)
}

/// Rescan requires mostly-printable decoded text: a binary blob has no
/// instruction surface for the text detectors.
fn mostly_printable(text: &str) -> bool {
    let total = text.chars().count();
    total > 0
        && text
            .chars()
            .filter(|c| !c.is_control() || c.is_whitespace())
            .count() as f32
            / total as f32
            >= PRINTABLE_MIN
}

/// Rescan decoded content with every finding attributed to the source
/// span of the encoding. Encoding an instruction is deliberate
/// transformation — floor severity at Medium.
fn rescan_decoded(
    source_range: ByteRange,
    label: &str,
    decoded: String,
    policy: &Policy,
    depth: usize,
) -> Vec<ScanFinding> {
    let dmap = TextMap::derived(decoded, source_range);
    let mut inner = detect_injection(&dmap, policy);
    inner.extend(detect_encoded(&dmap, policy, depth + 1));
    for f in inner.iter_mut() {
        if !f.detectors.contains(&DetectorId::EncodedPayload) {
            f.detectors.push(DetectorId::EncodedPayload);
        }
        f.severity = f.severity.max(Severity::Medium);
        f.confidence *= 0.95;
        f.evidence = format!("decoded({}): {}", label, f.evidence);
    }
    inner
}

pub(crate) fn detect_encoded(map: &TextMap, policy: &Policy, depth: usize) -> Vec<ScanFinding> {
    if depth >= MAX_DEPTH {
        return Vec::new();
    }
    let mut findings = Vec::new();
    for (idx, span) in find_spans(&map.text).into_iter().enumerate() {
        if idx >= MAX_SPANS {
            findings.push(ScanFinding {
                byte_range: map.source_range_for(span.start, span.end),
                severity: Severity::Low,
                detectors: vec![DetectorId::EncodedPayload],
                confidence: 0.6,
                evidence: format!("encoded span budget exhausted ({MAX_SPANS} examined)"),
            });
            break;
        }
        let text = map.snippet_for(span.start, span.end);
        let source_range = map.source_range_for(span.start, span.end);
        // Concealment markup is anomalous in model input regardless of
        // what the interior contains — presence is itself a Low finding.
        if matches!(span.scheme, "css-hidden" | "html-hidden") {
            findings.push(ScanFinding {
                byte_range: source_range,
                severity: Severity::Low,
                detectors: vec![DetectorId::EncodedPayload],
                confidence: 0.7,
                evidence: format!("{} markup conceals body text", span.scheme),
            });
        }
        for (label, decoded) in decode_candidates(&text, span.scheme) {
            if decoded.len() > MAX_DECODED {
                findings.push(ScanFinding {
                    byte_range: source_range,
                    severity: Severity::Low,
                    detectors: vec![DetectorId::EncodedPayload],
                    confidence: 0.6,
                    evidence: format!(
                        "decoded({label}) payload exceeds {MAX_DECODED}-byte rescan cap"
                    ),
                });
                break;
            }
            if mostly_printable(&decoded) {
                findings.extend(rescan_decoded(source_range, label, decoded, policy, depth));
                break;
            }
        }
    }
    findings
}
