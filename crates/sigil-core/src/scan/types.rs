use crate::types::{ByteRange, DlpFinding, EntropyProfile, ScanFinding, Severity, TaintedGrapheme};

pub struct ScanReport {
    pub findings: Vec<ScanFinding>,
    pub dlp_findings: Vec<DlpFinding>,
    pub max_severity: Severity,
    pub threat_count: usize,
    pub entropy_profile: EntropyProfile,
    pub injection_score: f32,
    /// Slow-rate (cross-input) detection result, if a history was
    /// provided to `run_scan_with_history`.
    pub slow_rate: Option<crate::lfdd::SlowRateReport>,
    /// Multiscale perplexity-anomaly evidence, present whenever the
    /// detector was enabled — including `Skipped`/`Failed` outcomes.
    pub perplexity: Option<crate::perplexity::PerplexityReport>,
    /// Terminal-escape (VT control-sequence) evidence, present whenever
    /// the detector was enabled — including `Skipped`/`Failed` outcomes.
    pub terminal: Option<crate::terminal::TerminalReport>,
}

impl ScanReport {
    /// Fold additional findings (e.g. merge-boundary records from the MERGE
    /// stage) into the report, recomputing the aggregate severity and count.
    pub fn absorb(&mut self, findings: Vec<ScanFinding>) {
        if findings.is_empty() {
            return;
        }
        for finding in &findings {
            if finding.severity > self.max_severity {
                self.max_severity = finding.severity;
            }
            if finding.severity != Severity::None {
                self.threat_count += 1;
            }
        }
        self.findings.extend(findings);
    }
}

pub(crate) struct Summary {
    pub(crate) max_severity: Severity,
    pub(crate) threat_count: usize,
    pub(crate) injection_score: f32,
}

pub(crate) fn summarize_findings(findings: &[ScanFinding]) -> Summary {
    let max_severity = findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::None);
    let threat_count = findings
        .iter()
        .filter(|f| f.severity != Severity::None)
        .count();
    let injection_score = score_findings(findings);
    Summary {
        max_severity,
        threat_count,
        injection_score,
    }
}

pub(crate) fn score_findings(findings: &[ScanFinding]) -> f32 {
    let mut score = 0.0;
    for finding in findings {
        let severity = finding.severity.rank() as f32 / 4.0;
        score += severity * (0.25 + finding.confidence.max(0.1));
    }
    score.clamp(0.0, 1.0)
}

pub(crate) fn annotate_graphemes(tainted: &mut [TaintedGrapheme], findings: &[ScanFinding]) {
    for grapheme in tainted.iter_mut() {
        let mut combined = ScanFinding::none(grapheme.grapheme.byte_range);
        for finding in findings {
            if grapheme.grapheme.byte_range.overlaps(finding.byte_range) {
                combined.severity = combined.severity.max(finding.severity);
                for detector in &finding.detectors {
                    if !combined.detectors.contains(detector) {
                        combined.detectors.push(detector.clone());
                    }
                }
                combined.confidence = combined.confidence.max(finding.confidence);
                if combined.evidence.is_empty() {
                    combined.evidence = finding.evidence.clone();
                }
            }
        }
        grapheme.threat = combined;
    }
}

#[derive(Clone)]
pub(crate) struct TextUnit {
    source_range: ByteRange,
    text_range: ByteRange,
}

pub(crate) struct TextMap {
    pub(crate) text: String,
    units: Vec<TextUnit>,
}

impl TextMap {
    pub(crate) fn new(tainted: &[TaintedGrapheme]) -> Self {
        let mut text = String::new();
        let mut units = Vec::new();
        let mut cursor = 0usize;

        for grapheme in tainted {
            let start = cursor;
            text.push_str(&grapheme.grapheme.text);
            cursor += grapheme.grapheme.text.len();
            let end = cursor;
            units.push(TextUnit {
                source_range: grapheme.grapheme.byte_range,
                text_range: ByteRange::new(start, end),
            });
        }

        Self { text, units }
    }

    /// A text map for *derived* content (decoded payloads, comment
    /// interiors): every position in `text` attributes back to the single
    /// `source_range` in the original input.
    pub(crate) fn derived(text: String, source_range: ByteRange) -> Self {
        let len = text.len();
        Self {
            text,
            units: vec![TextUnit {
                source_range,
                text_range: ByteRange::new(0, len),
            }],
        }
    }

    pub(crate) fn source_range_for(&self, start: usize, end: usize) -> ByteRange {
        let mut range = ByteRange::default();
        let mut initialized = false;

        for unit in &self.units {
            if unit.text_range.start < end && start < unit.text_range.end {
                if !initialized {
                    range = unit.source_range;
                    initialized = true;
                } else {
                    range = range.union(unit.source_range);
                }
            }
        }

        range
    }

    /// Derived view of the Unicode tag characters U+E0020–U+E007E decoded to
    /// the ASCII they shadow, in order, across the whole text. Tokenizers keep
    /// these code points and models read them as text, so the scanner must
    /// read them too. Each decoded character maps back to the source range of
    /// the tag it came from. `None` when the text carries no tag text.
    pub(crate) fn tag_shadow(&self) -> Option<TextMap> {
        const TAG_ASCII_OFFSET: u32 = 0xE0000;
        let mut text = String::new();
        let mut units = Vec::new();
        for (idx, ch) in self.text.char_indices() {
            let code = u32::from(ch);
            let Ok(ascii) = u8::try_from(code.wrapping_sub(TAG_ASCII_OFFSET)) else {
                continue;
            };
            if !(0x20..=0x7E).contains(&ascii) {
                continue;
            }
            let start = text.len();
            text.push(char::from(ascii));
            units.push(TextUnit {
                source_range: self.source_range_for(idx, idx + ch.len_utf8()),
                text_range: ByteRange::new(start, text.len()),
            });
        }
        (!text.trim().is_empty()).then_some(TextMap { text, units })
    }

    pub(crate) fn snippet_for(&self, start: usize, end: usize) -> String {
        self.text.get(start..end).unwrap_or_default().to_string()
    }
}
