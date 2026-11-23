//! Rendered-vs-extracted comparison for PDF artifacts: see [`RenderCompare`].

use super::*;
use sigil_multimodal::ExtractorIdentity;

/// One render+OCR run per page — pdftoppm cannot stream multiple pages to
/// one stdout, so the renderer is invoked once per page with `-f N -l N`
/// appended to its pinned args. Pages beyond the cap are recorded, not
/// rendered — a page the render never covered is evidence, not silence.
const MAX_RENDER_PAGES: usize = 12;

/// What rendering and reading back the pages produced.
struct RenderedPages {
    text: String,
    count: usize,
    partial_input: bool,
}

impl DocumentAdapter {
    /// Render each page, OCR the pixels, and diff the text layer against
    /// what actually painted. Emits an `OcrText` channel for the rendered
    /// side and, when lines diverge, a `Divergence` channel carrying exactly
    /// the lines a human viewing the render would not see.
    pub(super) fn render_compare_channels(
        &self,
        compare: &RenderCompare,
        bytes: &[u8],
        channels: &[ExtractedChannel],
        existing_properties: &[(String, String)],
    ) -> (Vec<(String, String)>, Vec<ExtractedChannel>) {
        let mut properties = Vec::new();
        let chain_digest = chain_digest(compare);

        let total_pages = self.total_pages(existing_properties);
        let render_pages = total_pages.min(MAX_RENDER_PAGES);
        if total_pages > render_pages {
            properties.push((self.render_key("pages_capped"), total_pages.to_string()));
        }

        let rendered = self.render_pages(compare, bytes, render_pages, &mut properties);
        properties.push((
            self.render_key("pages_rendered"),
            rendered.count.to_string(),
        ));
        if rendered.count == 0 {
            properties.push((
                self.render_key("status"),
                "failed: no page rendered".to_string(),
            ));
            return (properties, Vec::new());
        }
        properties.push((self.render_key("status"), "ran".to_string()));

        let truncated = total_pages > render_pages || rendered.partial_input;
        let mut out =
            vec![self.rendered_text_channel(compare, &chain_digest, &rendered, truncated)];

        let extracted = channels
            .iter()
            .find(|c| c.channel_kind == ChannelKind::TextLayer)
            .map(|c| c.content.as_str())
            .unwrap_or_default();
        let divergent = divergent_lines(extracted, &rendered.text);
        properties.push((
            self.render_key("divergent_lines"),
            divergent.len().to_string(),
        ));
        if !divergent.is_empty() {
            out.push(self.divergence_channel(compare, &chain_digest, &divergent));
        }
        (properties, out)
    }

    /// The OCR of the rendered pages: what a human viewing the render sees.
    fn rendered_text_channel(
        &self,
        compare: &RenderCompare,
        chain_digest: &str,
        rendered: &RenderedPages,
        truncated: bool,
    ) -> ExtractedChannel {
        ExtractedChannel {
            channel_kind: ChannelKind::OcrText,
            content: rendered.text.clone(),
            extractor: chain_identity(
                format!("{}/render-ocr", self.adapter_id()),
                format!("{}+{}", compare.renderer.version, compare.ocr.version),
                chain_digest,
                compare,
            ),
            confidence: Some(0.7),
            truncated,
        }
    }

    /// The text-layer lines the render does not account for.
    fn divergence_channel(
        &self,
        compare: &RenderCompare,
        chain_digest: &str,
        divergent: &[String],
    ) -> ExtractedChannel {
        ExtractedChannel {
            channel_kind: ChannelKind::Divergence,
            content: divergent.join("\n"),
            extractor: chain_identity(
                format!("{}/divergence", self.adapter_id()),
                DIVERGENCE_VERSION.to_string(),
                chain_digest,
                compare,
            ),
            confidence: Some(0.8),
            truncated: false,
        }
    }

    fn render_key(&self, name: &str) -> String {
        format!("{}.render_compare.{name}", self.adapter_id())
    }

    /// The page count the text extraction recorded, at least one.
    fn total_pages(&self, existing_properties: &[(String, String)]) -> usize {
        let pages_key = format!("{}.pages", self.adapter_id());
        existing_properties
            .iter()
            .find(|(k, _)| *k == pages_key)
            .and_then(|(_, v)| v.parse::<usize>().ok())
            .unwrap_or(1)
            .max(1)
    }

    /// Render and OCR pages `1..=pages`, recording each failed or partial
    /// page in `properties`.
    fn render_pages(
        &self,
        compare: &RenderCompare,
        bytes: &[u8],
        pages: usize,
        properties: &mut Vec<(String, String)>,
    ) -> RenderedPages {
        let mut rendered = RenderedPages {
            text: String::new(),
            count: 0,
            partial_input: false,
        };
        for page in 1..=pages {
            let page_args = [
                "-f".to_string(),
                page.to_string(),
                "-l".to_string(),
                page.to_string(),
            ];
            match compare
                .renderer
                .run_with(bytes, &page_args)
                .and_then(|png| {
                    let ocr = compare.ocr.extract(&png.output)?;
                    Ok((ocr.output, png.input_unread || ocr.input_unread))
                }) {
                Ok((text, input_unread)) => {
                    if input_unread {
                        rendered.partial_input = true;
                        properties.push((
                            self.render_key(&format!("page{page}")),
                            "partial-input".to_string(),
                        ));
                    }
                    rendered.text.push_str(&text);
                    rendered.text.push('\n');
                    rendered.count += 1;
                }
                Err(err) => {
                    properties.push((
                        self.render_key(&format!("page{page}")),
                        format!("failed: {err}"),
                    ));
                }
            }
        }
        rendered
    }
}

/// Digest over both tools' binary digests, identifying the render-then-OCR
/// chain.
fn chain_digest(compare: &RenderCompare) -> String {
    let mut hasher = Sha384::new();
    hasher.update(compare.renderer.binary_digest.as_bytes());
    hasher.update(compare.ocr.binary_digest.as_bytes());
    hex_digest(&hasher.finalize())
}

/// Identity of the render-then-OCR chain: the combined binary digest plus both
/// tools' pinned arguments (tagged by role) and their declared models.
fn chain_identity(
    name: String,
    version: String,
    chain_digest: &str,
    compare: &RenderCompare,
) -> ExtractorIdentity {
    let tagged = |role: &str, args: &[String]| {
        args.iter()
            .map(|arg| format!("{role}:{arg}"))
            .collect::<Vec<_>>()
    };
    let mut args = tagged("renderer", &compare.renderer.args);
    args.extend(tagged("ocr", &compare.ocr.args));
    let mut models = compare.renderer.model_digests.clone();
    models.extend(compare.ocr.model_digests.iter().cloned());
    ExtractorIdentity::bound(name, version, chain_digest.to_string(), args, models)
}
