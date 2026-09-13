use crate::{
    types::{ByteRange, Provenance, ScanFinding, Severity, TaintedGrapheme, TrustLevel},
    vocab::{EncodedToken, Vocab},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MergedToken {
    pub token_id: u32,
    pub text: String,
    pub byte_range: ByteRange,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub normalized: bool,
    pub boundary: bool,
}

/// Security-aware tokenization.
///
/// With `suppress_cross_boundary` enabled (the default policy), encoding
/// groups are split at provenance boundaries so no token ever spans two
/// sources; each suppression is recorded as a `MergeBoundary` finding.
///
/// With suppression disabled by policy, merges are allowed to cross
/// provenance boundaries — every such crossing is recorded as a High-severity
/// `MergeBoundary` finding, because the resulting token carries the first
/// source's provenance over bytes that originate elsewhere (unsafe-merge
/// detection, docs/RIC-CONTRACT.md RIC-R-5).
pub fn security_aware_merge(
    vocab: &Vocab,
    graphemes: &[TaintedGrapheme],
    suppress_cross_boundary: bool,
) -> (Vec<MergedToken>, Vec<ScanFinding>) {
    if graphemes.is_empty() {
        return (Vec::new(), Vec::new());
    }

    let mut tokens = Vec::new();
    let mut findings = Vec::new();
    let mut current: Vec<TaintedGrapheme> = Vec::new();
    let mut current_provenance = graphemes[0].provenance;

    for grapheme in graphemes {
        let provenance_changed = grapheme.provenance != current_provenance;
        if provenance_changed && !current.is_empty() {
            let prev = current.last().expect("non-empty group at boundary");
            if suppress_cross_boundary {
                findings.push(preserved_boundary_finding(prev, grapheme));
                tokens.extend(encode_group(vocab, &current));
                current.clear();
            } else {
                findings.push(crossed_boundary_finding(prev, grapheme));
            }
        }

        current_provenance = grapheme.provenance;
        current.push(grapheme.clone());
    }

    if !current.is_empty() {
        tokens.extend(encode_group(vocab, &current));
    }

    (tokens, findings)
}

fn preserved_boundary_finding(prev: &TaintedGrapheme, next: &TaintedGrapheme) -> ScanFinding {
    ScanFinding {
        byte_range: prev.grapheme.byte_range.union(next.grapheme.byte_range),
        severity: if prev.trust_level != next.trust_level {
            Severity::Low
        } else {
            Severity::None
        },
        detectors: vec![crate::types::DetectorId::MergeBoundary],
        confidence: 1.0,
        evidence: format!(
            "merge suppressed at provenance boundary {:?}→{:?} (trust {:?}→{:?})",
            prev.provenance, next.provenance, prev.trust_level, next.trust_level,
        ),
    }
}

fn crossed_boundary_finding(prev: &TaintedGrapheme, next: &TaintedGrapheme) -> ScanFinding {
    ScanFinding {
        byte_range: prev.grapheme.byte_range.union(next.grapheme.byte_range),
        severity: Severity::High,
        detectors: vec![crate::types::DetectorId::MergeBoundary],
        confidence: 1.0,
        evidence: format!(
            "cross-provenance merge permitted by policy at {:?}→{:?} \
             (trust {:?}→{:?}); token inherits {:?} provenance over foreign bytes",
            prev.provenance, next.provenance, prev.trust_level, next.trust_level, prev.provenance,
        ),
    }
}

fn encode_group(vocab: &Vocab, graphemes: &[TaintedGrapheme]) -> Vec<MergedToken> {
    let encoded: Vec<EncodedToken> = vocab.encode_graphemes(graphemes);
    encoded
        .into_iter()
        .map(|token| MergedToken {
            token_id: token.token_id,
            text: token.text,
            byte_range: token.byte_range,
            provenance: token.provenance,
            trust_level: token.trust_level,
            normalized: token.normalized,
            boundary: token.boundary,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BoundaryContext, Grapheme};

    fn grapheme(text: &str, start: usize, provenance: Provenance) -> TaintedGrapheme {
        TaintedGrapheme {
            grapheme: Grapheme {
                text: text.to_string(),
                byte_range: ByteRange::new(start, start + text.len()),
                normalized: false,
            },
            provenance,
            trust_level: provenance.default_trust(),
            boundary_context: BoundaryContext::Interior,
            threat: ScanFinding::none(ByteRange::new(start, start + text.len())),
        }
    }

    #[test]
    fn emits_boundary_finding_on_provenance_change() {
        let vocab = Vocab::tiktoken("cl100k_base");
        let graphemes = vec![
            grapheme("sys ", 0, Provenance::System),
            grapheme("user", 4, Provenance::User),
        ];
        let (tokens, findings) = security_aware_merge(&vocab, &graphemes, true);

        assert_eq!(findings.len(), 1);
        assert!(findings[0]
            .detectors
            .contains(&crate::types::DetectorId::MergeBoundary));
        assert!(findings[0].evidence.contains("System→User"));
        // No token may span the boundary.
        for token in &tokens {
            assert!(
                token.byte_range.end <= 4 || token.byte_range.start >= 4,
                "token spans provenance boundary: {token:?}"
            );
        }
    }

    #[test]
    fn no_findings_for_single_provenance() {
        let vocab = Vocab::tiktoken("cl100k_base");
        let graphemes = vec![grapheme("hello", 0, Provenance::User)];
        let (_, findings) = security_aware_merge(&vocab, &graphemes, true);
        assert!(findings.is_empty());
    }

    #[test]
    fn unsuppressed_merge_crossing_is_high_severity() {
        let vocab = Vocab::tiktoken("cl100k_base");
        let graphemes = vec![
            grapheme("sys ", 0, Provenance::System),
            grapheme("user", 4, Provenance::User),
        ];
        let (tokens, findings) = security_aware_merge(&vocab, &graphemes, false);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].severity, Severity::High);
        assert!(findings[0].evidence.contains("permitted by policy"));
        // With suppression disabled, tokens may span the boundary — that is
        // exactly the condition the finding flags.
        assert!(tokens
            .iter()
            .any(|token| token.byte_range.start < 4 && token.byte_range.end > 4));
    }
}
