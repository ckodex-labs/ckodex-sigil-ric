//! Document adapter (Phase 2+ — document).
//!
//! Extracts text channels from document artifacts. Supports:
//! - Plain text (txt, md): direct text extraction.
//! - PDF: text extraction via `lopdf` (proper content-stream decoding,
//!   FlateDecode decompression, font handling). Falls back to basic
//!   string scanning if lopdf cannot parse the document.
//!
//! Follows the same Option B contract as other adapters: the adapter
//! produces *channels*, the kernel judges. The adapter cannot fabricate
//! authority (RIC-R-7 enforced at the type level).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};
use sigil_multimodal::{ChannelKind, ExtractedChannel};
use std::collections::HashMap;

pub use sigil_multimodal::{PerceptionAdapter, PerceptionError, PerceptionReport};

mod render;

/// Optional rendered-vs-extracted comparison: a pinned renderer (e.g.
/// `pdftoppm`) rasterizes the artifact, a pinned OCR reads the pixels back,
/// and text-layer lines that never reach the rendered output surface as a
/// `Divergence` channel — the "white text on white page" class.
#[derive(Clone, Debug)]
pub struct RenderCompare {
    pub renderer: crate::ExternalPipe,
    pub ocr: crate::ExternalOcr,
}

/// Document adapter: extracts text from plain text, markdown, and PDF
/// artifacts.
#[derive(Default)]
pub struct DocumentAdapter {
    pub render_compare: Option<RenderCompare>,
}

impl PerceptionAdapter for DocumentAdapter {
    fn modality(&self) -> sigil_multimodal::Modality {
        sigil_multimodal::Modality::Document
    }

    fn adapter_id(&self) -> &str {
        "sigil-perception/document/0.1"
    }

    fn perceive(
        &self,
        artifact: &sigil_multimodal::ArtifactRef<'_>,
    ) -> Result<PerceptionReport, PerceptionError> {
        let mut hasher = Sha384::new();
        hasher.update(artifact.bytes);
        let artifact_digest = hex_digest(&hasher.finalize());

        let media_type = artifact
            .media_type
            .clone()
            .unwrap_or_else(|| detect_media_type(artifact.bytes));

        let (mut properties, mut channels) = match media_type.as_str() {
            "text/plain" | "text/markdown" | "text/x-markdown" => {
                extract_plain_text(artifact.bytes, self.adapter_id())
            }
            "application/pdf" => extract_pdf_text(artifact.bytes, self.adapter_id()),
            _ => {
                // Try to detect and fall back to plain text.
                if is_likely_text(artifact.bytes) {
                    extract_plain_text(artifact.bytes, self.adapter_id())
                } else {
                    return Err(PerceptionError::UnsupportedMediaType(media_type));
                }
            }
        };

        if media_type == "application/pdf"
            && let Some(compare) = &self.render_compare
        {
            let (props, extra) =
                self.render_compare_channels(compare, artifact.bytes, &channels, &properties);
            properties.extend(props);
            channels.extend(extra);
        }

        Ok(PerceptionReport {
            source_id: artifact.source_id.clone(),
            artifact_digest,
            media_type,
            properties,
            channels,
            consumed: None,
        })
    }
}

/// Version of the divergence comparison, shared with the model-view
/// adapter and part of every divergence channel's identity.
pub(crate) const DIVERGENCE_VERSION: &str = "word-window/2.0";

fn word_sequence(text: &str) -> Vec<String> {
    text.split_whitespace()
        .map(|w| {
            w.to_lowercase()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_string()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

fn normalized_words(text: &str) -> std::collections::HashSet<String> {
    word_sequence(text).into_iter().collect()
}

/// Lines of `extracted` the rendered text does not account for: content the
/// machine receives that a human viewing the render does not. A line is
/// divergent when fewer than 80 % of its distinct words appear in the
/// rendered text, or, for a line of three or more words, when no stretch of
/// `max(2n, n + 4)` consecutive rendered words holds 80 % of them.
///
/// Words, not lines, because OCR re-wraps and reorders freely. The window
/// keeps that tolerance (reordered or re-wrapped words stay near each other)
/// but closes the gap word coverage left: payload words printed visibly but
/// scattered across the source no longer cover a line that only the
/// model's view shows together.
pub(crate) fn divergent_lines(extracted: &str, rendered: &str) -> Vec<String> {
    divergent_lines_within(extracted, rendered, WINDOW_BUDGET)
}

/// [`divergent_lines`] with an explicit window-check budget.
pub(crate) fn divergent_lines_within(
    extracted: &str,
    rendered: &str,
    budget: usize,
) -> Vec<String> {
    let sequence = word_sequence(rendered);
    let mut index: HashMap<&str, Vec<usize>> = HashMap::new();
    for (position, word) in sequence.iter().enumerate() {
        index.entry(word.as_str()).or_default().push(position);
    }
    let mut budget = budget;
    extracted
        .lines()
        .filter(|line| line_diverges(line, &index, &mut budget))
        .map(str::to_string)
        .collect()
}

/// Lines shorter than this are judged on word coverage alone: a window over
/// one or two words says nothing about placement.
const WINDOW_MIN_WORDS: usize = 3;

/// Work allowed for the window checks of one comparison, in index steps.
/// Each comparison's cost is bounded by this, whatever the text sizes; a
/// line not checked within it is reported divergent (unchecked content is
/// uncertainty, and uncertainty degrades).
const WINDOW_BUDGET: usize = 16_000_000;

/// The smallest count that is at least 80 % of `n`, in integers.
fn coverage_needed(n: usize) -> usize {
    (4 * n).div_ceil(5)
}

fn line_diverges(line: &str, index: &HashMap<&str, Vec<usize>>, budget: &mut usize) -> bool {
    let mut words: Vec<String> = normalized_words(line).into_iter().collect();
    if words.is_empty() {
        return false;
    }
    words.sort_unstable();
    let present: Vec<&[usize]> = words
        .iter()
        .filter_map(|w| index.get(w.as_str()).map(Vec::as_slice))
        .collect();
    let needed = coverage_needed(words.len());
    if present.len() < needed {
        return true;
    }
    words.len() >= WINDOW_MIN_WORDS && !within_window(present, words.len(), budget)
}

/// True when some stretch of `max(2n, n + 4)` consecutive source words holds
/// at least 80 % of the line's `n` distinct words. `occurrences` holds the
/// sorted source positions of each line word that occurs in the source.
///
/// A satisfying window misses at most `n - needed` of the words, so it holds
/// an occurrence of one of the `n - needed + 1` rarest. Each such occurrence
/// is an anchor; only the words' occurrences within one window length of it
/// are examined.
fn within_window(mut occurrences: Vec<&[usize]>, n: usize, budget: &mut usize) -> bool {
    let window = (2 * n).max(n + 4);
    let needed = coverage_needed(n);
    occurrences.sort_by_key(|positions| positions.len());
    let anchors = n - needed + 1;
    for rare in occurrences.iter().take(anchors) {
        for &anchor in *rare {
            let cost = occurrences.len() + 2 * window;
            if *budget < cost {
                return false;
            }
            *budget -= cost;
            if anchored_window_holds(&occurrences, anchor, window, needed) {
                return true;
            }
        }
    }
    false
}

/// Whether a window of `window` positions containing `anchor` holds
/// `needed` distinct words.
fn anchored_window_holds(
    occurrences: &[&[usize]],
    anchor: usize,
    window: usize,
    needed: usize,
) -> bool {
    let low = anchor.saturating_sub(window - 1);
    let high = anchor + window;
    let mut events: Vec<(usize, usize)> = Vec::new();
    for (word, positions) in occurrences.iter().enumerate() {
        let start = positions.partition_point(|&p| p < low);
        events.extend(
            positions[start..]
                .iter()
                .take_while(|&&p| p < high)
                .map(|&p| (p, word)),
        );
    }
    events.sort_unstable();
    let mut counts = vec![0usize; occurrences.len()];
    let (mut distinct, mut tail) = (0usize, 0usize);
    for &(position, word) in &events {
        if counts[word] == 0 {
            distinct += 1;
        }
        counts[word] += 1;
        while events[tail].0 + window <= position {
            let leaving = events[tail].1;
            counts[leaving] -= 1;
            if counts[leaving] == 0 {
                distinct -= 1;
            }
            tail += 1;
        }
        if distinct >= needed {
            return true;
        }
    }
    false
}

fn detect_media_type(bytes: &[u8]) -> String {
    if bytes.starts_with(b"%PDF") {
        return "application/pdf".to_string();
    }
    if is_likely_text(bytes) {
        return "text/plain".to_string();
    }
    "application/octet-stream".to_string()
}

fn is_likely_text(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }
    // Heuristic: if >85% of bytes are printable ASCII or common whitespace,
    // treat as text.
    let printable = bytes
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b == b' ' || b == b'\n' || b == b'\r' || b == b'\t')
        .count();
    let ratio = printable as f32 / bytes.len() as f32;
    ratio > 0.85
}

fn extract_plain_text(
    bytes: &[u8],
    adapter_id: &str,
) -> (Vec<(String, String)>, Vec<ExtractedChannel>) {
    let content = String::from_utf8_lossy(bytes).to_string();
    let char_count = content.chars().count();
    let line_count = content.lines().count();

    let properties = vec![
        (format!("{adapter_id}.char_count"), char_count.to_string()),
        (format!("{adapter_id}.line_count"), line_count.to_string()),
        (format!("{adapter_id}.format"), "plain_text".to_string()),
    ];

    let channel = ExtractedChannel {
        channel_kind: ChannelKind::TextLayer,
        content,
        extractor: crate::in_process_identity(format!("{adapter_id}/text"), "utf8/1.0", &[]),
        confidence: Some(1.0),
        truncated: false,
    };

    (properties, vec![channel])
}

/// PDF text extraction using `lopdf` for proper content-stream decoding.
///
/// `lopdf` handles:
/// - FlateDecode-compressed content streams (decompresses before parsing).
/// - Content stream operators (Tj, TJ, BT/ET, etc.).
/// - Font encoding and ToUnicode CMap resolution.
/// - Object streams (PDF 1.5+).
///
/// If lopdf cannot parse the document (corrupt, encrypted with non-empty
/// password, or unsupported features), the function falls back to basic
/// string scanning and sets `truncated = true`.
///
/// **Known limitations** (per lopdf issue #330, 2024-10):
/// - Some CID fonts with non-standard ToUnicode CMaps may fail to parse.
/// - Reading order is not reconstructed (text extracted in stream order).
/// - Encrypted PDFs with non-empty passwords are not decrypted.
fn extract_pdf_text(
    bytes: &[u8],
    adapter_id: &str,
) -> (Vec<(String, String)>, Vec<ExtractedChannel>) {
    let (text, truncated, page_count) = match lopdf::Document::load_mem(bytes) {
        Ok(doc) => extract_pdf_text_via_lopdf(&doc),
        Err(_) => (extract_pdf_text_fallback(bytes), true, 0),
    };

    let char_count = text.chars().count();
    let properties = vec![
        (format!("{adapter_id}.char_count"), char_count.to_string()),
        (format!("{adapter_id}.format"), "pdf".to_string()),
        (format!("{adapter_id}.truncated"), truncated.to_string()),
        (format!("{adapter_id}.pages"), page_count.to_string()),
    ];

    let channel = if char_count > 0 {
        ExtractedChannel {
            channel_kind: ChannelKind::TextLayer,
            content: text,
            extractor: crate::in_process_identity(
                format!("{adapter_id}/pdf-text"),
                "lopdf/0.36",
                &[],
            ),
            confidence: Some(if truncated { 0.6 } else { 0.85 }),
            truncated,
        }
    } else {
        ExtractedChannel {
            channel_kind: ChannelKind::Metadata,
            content: format!(
                "pdf_text_extracted = 0\npdf_pages = {page_count}\npdf_truncated = {truncated}\n"
            ),
            extractor: crate::in_process_identity(
                format!("{adapter_id}/pdf-header"),
                "lopdf/0.36",
                &[],
            ),
            confidence: None,
            truncated: true,
        }
    };

    (properties, vec![channel])
}

/// Extract text from a loaded lopdf Document using `extract_text`.
/// Returns (text, truncated, page_count). If `extract_text` fails on
/// some pages, the partial text is returned with `truncated = true`.
fn extract_pdf_text_via_lopdf(doc: &lopdf::Document) -> (String, bool, usize) {
    let pages = doc.get_pages();
    let page_count = pages.len();
    if page_count == 0 {
        return (String::new(), true, 0);
    }
    let page_numbers: Vec<u32> = pages.keys().cloned().collect();
    // extract_text returns an error if ANY page fails; we still get
    // partial text from successful pages in the Ok variant.
    match doc.extract_text(&page_numbers) {
        Ok(text) => (text, false, page_count),
        Err(_) => {
            // Try page-by-page to salvage partial text.
            let (text, any_ok) = extract_pdf_text_page_by_page(doc, &page_numbers);
            (text, !any_ok, page_count)
        }
    }
}

/// Fallback: extract text page-by-page, salvaging partial results.
fn extract_pdf_text_page_by_page(doc: &lopdf::Document, page_numbers: &[u32]) -> (String, bool) {
    let mut text = String::new();
    let mut any_ok = false;
    for &page_num in page_numbers {
        match doc.extract_text(&[page_num]) {
            Ok(page_text) => {
                text.push_str(&page_text);
                text.push('\n');
                any_ok = true;
            }
            Err(_) => continue,
        }
    }
    (text, any_ok)
}

/// Basic fallback: scan raw bytes for PDF string literals.
/// Used only when lopdf cannot parse the document (corrupt, encrypted,
/// or unsupported). This is a best-effort heuristic, not a real parser.
fn extract_pdf_text_fallback(bytes: &[u8]) -> String {
    let raw = String::from_utf8_lossy(bytes);
    let mut text = String::new();
    let mut in_string = false;
    let mut current = String::new();
    let mut escape = false;

    for ch in raw.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' => escape = true,
            '(' if !in_string => {
                in_string = true;
                current.clear();
            }
            ')' if in_string => {
                in_string = false;
                if !current.is_empty() {
                    text.push_str(&current);
                    text.push(' ');
                }
            }
            _ if in_string => current.push(ch),
            _ => {}
        }
    }

    text.chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ' || *c == '\n')
        .collect()
}

/// Adapter-level result envelope for CLI consumption.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DocumentPerceptionOutcome {
    pub adapter_id: String,
    pub report: PerceptionReport,
}

fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests;
