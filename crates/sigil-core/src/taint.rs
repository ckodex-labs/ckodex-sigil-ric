use crate::types::{
    BoundaryContext, Grapheme, Provenance, ScanFinding, TaintedGrapheme, TrustLevel,
};

pub fn apply_provenance(graphemes: Vec<Grapheme>, provenance: Provenance) -> Vec<TaintedGrapheme> {
    let trust_level = provenance.default_trust();
    let len = graphemes.len();

    graphemes
        .into_iter()
        .enumerate()
        .map(|(idx, grapheme)| {
            let boundary_context = if len == 1 || idx == 0 {
                BoundaryContext::Start
            } else if idx + 1 == len {
                BoundaryContext::End
            } else {
                BoundaryContext::Interior
            };

            TaintedGrapheme {
                threat: ScanFinding::none(grapheme.byte_range),
                grapheme,
                provenance,
                trust_level,
                boundary_context,
            }
        })
        .collect()
}

/// Restrictive trust composition: combining content from two trust levels
/// yields the *lower* of the two. Trust never elevates through composition
/// (anti-dilution doctrine, SIGIL-SPEC §10.2 INV-002 analog).
pub fn combine_trust(a: TrustLevel, b: TrustLevel) -> TrustLevel {
    if a <= b {
        a
    } else {
        b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Provenance;

    #[test]
    fn trust_composition_is_restrictive() {
        assert_eq!(
            combine_trust(TrustLevel::Untrusted, TrustLevel::Privileged),
            TrustLevel::Untrusted
        );
        assert_eq!(
            combine_trust(TrustLevel::Privileged, TrustLevel::Untrusted),
            TrustLevel::Untrusted
        );
        assert_eq!(
            combine_trust(TrustLevel::Bounded, TrustLevel::Bounded),
            TrustLevel::Bounded
        );
    }

    #[test]
    fn default_trust_matches_spec() {
        assert_eq!(Provenance::System.default_trust(), TrustLevel::Privileged);
        assert_eq!(Provenance::User.default_trust(), TrustLevel::Untrusted);
        assert_eq!(Provenance::McpTool.default_trust(), TrustLevel::Untrusted);
        assert_eq!(Provenance::Unknown.default_trust(), TrustLevel::Untrusted);
    }
}
