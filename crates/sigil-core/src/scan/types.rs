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

    pub(crate) fn snippet_for(&self, start: usize, end: usize) -> String {
        self.text.get(start..end).unwrap_or_default().to_string()
    }
}
