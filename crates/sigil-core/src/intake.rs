use crate::{
    error::{Result, SigilError},
    policy::{Normalization, Policy},
    types::{ByteRange, Grapheme},
};
use unicode_normalization::UnicodeNormalization;
use unicode_segmentation::UnicodeSegmentation;

/// Unicode Tags block U+E0000–U+E007F (language tag / ASCII-smuggling channel).
/// Default-ignorable and invisible in every common renderer, which makes the
/// block a covert payload channel into tokenizers (SIGIL-SPEC §3.1 Stage 1).
pub(crate) fn is_unicode_tag(ch: char) -> bool {
    let c = u32::from(ch);
    (0xE0000..=0xE007F).contains(&c)
}

/// Characters that occupy no visible width and have no legitimate use inside
/// model-bound prompts unless a deployment explicitly allows them.
pub(crate) fn is_invisible_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{00AD}' // soft hyphen
            | '\u{180E}' // Mongolian vowel separator (invisible since Unicode 6.3)
            | '\u{200B}'..='\u{200D}' // zero-width space/JOINERs
            | '\u{2060}' // word joiner
            | '\u{2061}'..='\u{2064}' // invisible operators
            | '\u{FEFF}' // zero-width no-break space / BOM
            | '\u{202A}'..='\u{202E}' // bidi embedding/override controls
            | '\u{2066}'..='\u{2069}' // bidi isolates
            | '\u{FFF9}'..='\u{FFFB}' // interlinear annotation
    ) || is_unicode_tag(ch)
}

/// Segment the RAW text into grapheme clusters and normalize each cluster
/// individually. Byte ranges therefore always reference the raw input, even
/// when normalization changes byte length (SIGIL-SPEC INV-007; RIC-R-2).
/// Extended grapheme clusters are closed under NFC, so per-cluster
/// normalization is equivalent to whole-text NFC for well-formed input.
pub fn intake_text_segment(
    text: &str,
    base_offset: usize,
    policy: &Policy,
) -> Result<Vec<Grapheme>> {
    if text.len() > policy.intake.max_input_bytes {
        return Err(SigilError::InputTooLarge);
    }

    let graphemes = graphemes_for_text(text, base_offset, policy.intake.normalization.clone());
    Ok(match policy.intake.invisible_chars {
        crate::policy::InvisibleCharPolicy::Strip => strip_invisible_graphemes(graphemes),
        _ => graphemes,
    })
}

pub fn intake_bytes_segment(
    bytes: &[u8],
    base_offset: usize,
    policy: &Policy,
) -> Result<Vec<Grapheme>> {
    if bytes.len() > policy.intake.max_input_bytes {
        return Err(SigilError::InputTooLarge);
    }

    match std::str::from_utf8(bytes) {
        Ok(text) => intake_text_segment(text, base_offset, policy),
        Err(_) if matches!(policy.sigil.mode, crate::policy::Mode::Monitor) => {
            let lossy = String::from_utf8_lossy(bytes);
            let text = lossy.into_owned();
            Ok(vec![Grapheme {
                text,
                byte_range: ByteRange::new(base_offset, base_offset + bytes.len()),
                normalized: true,
            }])
        }
        Err(_) => Err(SigilError::InvalidUtf8),
    }
}

fn graphemes_for_text(
    text: &str,
    base_offset: usize,
    normalization: Normalization,
) -> Vec<Grapheme> {
    let mut graphemes = Vec::new();
    for (start, cluster) in UnicodeSegmentation::grapheme_indices(text, true) {
        let end = start + cluster.len();
        let normalized = match normalization {
            Normalization::Nfc => cluster.nfc().collect::<String>(),
            Normalization::Nfkc => cluster.nfkc().collect::<String>(),
            Normalization::None => cluster.to_string(),
        };
        graphemes.push(Grapheme {
            text: normalized.clone(),
            byte_range: ByteRange::new(base_offset + start, base_offset + end),
            normalized: normalized != cluster,
        });
    }
    graphemes
}

/// Drop graphemes that consist solely of invisible characters. Byte ranges of
/// surviving graphemes remain valid against the raw segment text.
fn strip_invisible_graphemes(graphemes: Vec<Grapheme>) -> Vec<Grapheme> {
    graphemes
        .into_iter()
        .filter(|grapheme| !grapheme.text.chars().all(is_invisible_char))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{IntakePolicy, InvisibleCharPolicy};

    fn policy(normalization: Normalization, invisible: InvisibleCharPolicy) -> Policy {
        Policy {
            intake: IntakePolicy {
                normalization,
                invisible_chars: invisible,
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn byte_ranges_reference_raw_input_when_normalization_changes_length() {
        // Decomposed é (e + U+0301) is 3 raw bytes; NFC composes it to 2 bytes.
        let raw = "e\u{0301}x";
        let policy = policy(Normalization::Nfc, InvisibleCharPolicy::Flag);
        let graphemes = intake_text_segment(raw, 0, &policy).expect("intake");

        assert_eq!(graphemes.len(), 2);
        assert_eq!(graphemes[0].text, "\u{00E9}");
        assert!(graphemes[0].normalized);
        // Ranges point into the RAW input: "e\u{0301}" occupies 0..3, "x" at 3..4.
        assert_eq!(graphemes[0].byte_range, ByteRange::new(0, 3));
        assert_eq!(graphemes[1].byte_range, ByteRange::new(3, 4));
        assert_eq!(
            &raw[graphemes[1].byte_range.start..graphemes[1].byte_range.end],
            "x"
        );
    }

    #[test]
    fn nfkc_ligature_expansion_keeps_raw_range() {
        // U+FB01 (ﬁ) is 3 raw bytes; NFKC expands to "fi" (2 bytes).
        let raw = "\u{FB01}x";
        let policy = policy(Normalization::Nfkc, InvisibleCharPolicy::Flag);
        let graphemes = intake_text_segment(raw, 0, &policy).expect("intake");

        assert_eq!(graphemes[0].text, "fi");
        assert!(graphemes[0].normalized);
        assert_eq!(graphemes[0].byte_range, ByteRange::new(0, 3));
        assert_eq!(graphemes[1].byte_range, ByteRange::new(3, 4));
    }

    #[test]
    fn strip_removes_invisible_only_graphemes() {
        // ZWSP forms its own cluster here and is stripped.
        let raw = "a\u{200B}b";
        let policy = policy(Normalization::Nfc, InvisibleCharPolicy::Strip);
        let graphemes = intake_text_segment(raw, 0, &policy).expect("intake");

        let visible: String = graphemes.iter().map(|g| g.text.as_str()).collect();
        assert_eq!(visible, "ab");
        for grapheme in &graphemes {
            let raw_slice = &raw[grapheme.byte_range.start..grapheme.byte_range.end];
            assert!(!raw_slice.chars().all(is_invisible_char));
        }
    }

    #[test]
    fn strip_keeps_clusters_with_attached_invisible_characters() {
        // A tag character attaches to the preceding cluster (GB9: × Extend).
        // Strip only removes invisible-ONLY clusters; attached invisibles are
        // a scan concern (Flag/Deny) — silently rewriting them would destroy
        // the raw-evidence binding (RIC-R-1).
        let raw = "b\u{E0041}c";
        let policy = policy(Normalization::Nfc, InvisibleCharPolicy::Strip);
        let graphemes = intake_text_segment(raw, 0, &policy).expect("intake");

        let visible: String = graphemes.iter().map(|g| g.text.as_str()).collect();
        assert_eq!(visible, "b\u{E0041}c");
    }

    #[test]
    fn strip_removes_leading_standalone_tag_cluster() {
        // A leading Extend with nothing to attach to forms its own cluster,
        // which is invisible-only and therefore stripped.
        let raw = "\u{E0041}a";
        let policy = policy(Normalization::Nfc, InvisibleCharPolicy::Strip);
        let graphemes = intake_text_segment(raw, 0, &policy).expect("intake");

        let visible: String = graphemes.iter().map(|g| g.text.as_str()).collect();
        assert_eq!(visible, "a");
    }

    #[test]
    fn tag_characters_are_invisible() {
        assert!(is_unicode_tag('\u{E0001}'));
        assert!(is_unicode_tag('\u{E007F}'));
        assert!(!is_unicode_tag('a'));
        assert!(is_invisible_char('\u{E0041}'));
        assert!(is_invisible_char('\u{00AD}'));
        assert!(!is_invisible_char('a'));
    }
}
