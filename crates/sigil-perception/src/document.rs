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
use sigil_multimodal::{ChannelKind, ExtractedChannel, ExtractorIdentity};

pub use sigil_multimodal::{PerceptionAdapter, PerceptionError, PerceptionReport};

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
                extract_plain_text(artifact.bytes, &artifact_digest, self.adapter_id())
            }
            "application/pdf" => {
                extract_pdf_text(artifact.bytes, &artifact_digest, self.adapter_id())
            }
            _ => {
                // Try to detect and fall back to plain text.
                if is_likely_text(artifact.bytes) {
                    extract_plain_text(artifact.bytes, &artifact_digest, self.adapter_id())
                } else {
                    return Err(PerceptionError::UnsupportedMediaType(media_type));
                }
            }
        };

        if media_type == "application/pdf" {
            if let Some(compare) = &self.render_compare {
                let (props, extra) =
                    self.render_compare_channels(compare, artifact.bytes, &channels);
                properties.extend(props);
                channels.extend(extra);
            }
        }

        Ok(PerceptionReport {
            source_id: artifact.source_id.clone(),
            artifact_digest,
            media_type,
            properties,
            channels,
        })
    }
}

impl DocumentAdapter {
    /// Render the artifact, OCR the pixels, and diff the text layer against
    /// what actually painted. Emits an `OcrText` channel for the rendered
    /// side and, when lines diverge, a `Divergence` channel carrying exactly
    /// the lines a human viewing the render would not see.
    fn render_compare_channels(
        &self,
        compare: &RenderCompare,
        bytes: &[u8],
        channels: &[ExtractedChannel],
    ) -> (Vec<(String, String)>, Vec<ExtractedChannel>) {
        let mut properties = Vec::new();
        let mut out = Vec::new();
        let key = |name: &str| format!("{}.render_compare.{name}", self.adapter_id());
        let mut hasher = Sha384::new();
        hasher.update(compare.renderer.binary_digest.as_bytes());
        hasher.update(compare.ocr.binary_digest.as_bytes());
        let chain_digest = hex_digest(&hasher.finalize());

        let rendered = compare
            .renderer
            .run(bytes)
            .and_then(|png| compare.ocr.extract(&png));
        let rendered = match rendered {
            Ok(text) => text,
            Err(err) => {
                properties.push((key("status"), format!("failed: {err}")));
                return (properties, out);
            }
        };
        properties.push((key("status"), "ran".to_string()));

        out.push(ExtractedChannel {
            channel_kind: ChannelKind::OcrText,
            content: rendered.clone(),
            extractor: ExtractorIdentity {
                name: format!("{}/render-ocr", self.adapter_id()),
                version: format!("{}+{}", compare.renderer.version, compare.ocr.version),
                config_digest: chain_digest.clone(),
            },
            confidence: Some(0.7),
            truncated: false,
        });

        let extracted = channels
            .iter()
            .find(|c| c.channel_kind == ChannelKind::TextLayer)
            .map(|c| c.content.as_str())
            .unwrap_or_default();
        let divergent = divergent_lines(extracted, &rendered);
        properties.push((key("divergent_lines"), divergent.len().to_string()));
        if !divergent.is_empty() {
            out.push(ExtractedChannel {
                channel_kind: ChannelKind::Divergence,
                content: divergent.join("\n"),
                extractor: ExtractorIdentity {
                    name: format!("{}/divergence", self.adapter_id()),
                    version: "word-coverage/1.0".to_string(),
                    config_digest: chain_digest,
                },
                confidence: Some(0.8),
                truncated: false,
            });
        }
        (properties, out)
    }
}

fn normalized_words(text: &str) -> std::collections::HashSet<String> {
    text.split_whitespace()
        .map(|w| {
            w.to_lowercase()
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_string()
        })
        .filter(|w| !w.is_empty())
        .collect()
}

/// Lines of `extracted` whose normalized words are <80% covered by the
/// rendered text's word set — content the machine receives that a human
/// viewing the render does not. Word-set (not line) comparison because OCR
/// re-wraps and reorders lines freely.
fn divergent_lines(extracted: &str, rendered: &str) -> Vec<String> {
    let rendered_words = normalized_words(rendered);
    extracted
        .lines()
        .filter(|line| {
            let words: Vec<String> = normalized_words(line).into_iter().collect();
            let covered = words.iter().filter(|w| rendered_words.contains(*w)).count() as f32;
            !words.is_empty() && covered / (words.len() as f32) < 0.8
        })
        .map(str::to_string)
        .collect()
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
    artifact_digest: &str,
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
        extractor: ExtractorIdentity {
            name: format!("{adapter_id}/text",),
            version: "utf8/1.0".to_string(),
            config_digest: artifact_digest.to_string(),
        },
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
    artifact_digest: &str,
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
            extractor: ExtractorIdentity {
                name: format!("{adapter_id}/pdf-text"),
                version: "lopdf/0.36".to_string(),
                config_digest: artifact_digest.to_string(),
            },
            confidence: Some(if truncated { 0.6 } else { 0.85 }),
            truncated,
        }
    } else {
        ExtractedChannel {
            channel_kind: ChannelKind::Metadata,
            content: format!(
                "pdf_text_extracted = 0\npdf_pages = {page_count}\npdf_truncated = {truncated}\n"
            ),
            extractor: ExtractorIdentity {
                name: format!("{adapter_id}/pdf-header"),
                version: "lopdf/0.36".to_string(),
                config_digest: artifact_digest.to_string(),
            },
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
