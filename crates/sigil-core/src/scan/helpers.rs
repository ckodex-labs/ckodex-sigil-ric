/// Unicode Tags block U+E0000–U+E007F (language tag / ASCII-smuggling channel).
/// U+E0001 (language tag) through U+E007F (cancelled tag) are default-ignorable
/// and invisible in every common renderer, which makes them a covert payload
/// channel into tokenizers (see SIGIL-SPEC §3.1 Stage 1; Microsoft, Sep 2026).
pub(crate) fn is_smuggling_char(ch: char) -> bool {
    crate::intake::is_invisible_char(ch)
}

/// Contiguous-run gate for base64-like payloads (D-9 tuning).
///
/// The original shape check stripped whitespace first, so any natural-language
/// sentence of 32+ letters qualified — the alphabet test is vacuous for prose.
/// The discriminator that actually separates encoded payloads from language is
/// **contiguity**: prose breaks into short runs at every space (typical run
/// length 3–11), while an encoded blob is one uninterrupted run.
///
/// A run of 32+ standard-base64 characters (`A-Za-z0-9+/=`) with no internal
/// whitespace or punctuation is therefore flagged. `-` and `_` break the run:
/// they are word-connector punctuation in prose (hyphenated compounds), and
/// standard base64 never contains them. Known recall trade: URL-safe base64
/// containing `-`/`_` is not caught by this detector; the windowed
/// entropy-spike detector still covers high-entropy regions in context.
pub(crate) fn looks_like_base64(text: &str) -> bool {
    let mut run = 0usize;
    for ch in text.chars() {
        if !ch.is_whitespace() && (ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=')) {
            run += 1;
            if run >= 32 {
                return true;
            }
        } else {
            run = 0;
        }
    }
    false
}

pub(crate) fn shannon_entropy(bytes: &[u8]) -> f32 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }

    let len = bytes.len() as f32;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f32 / len;
            -probability * probability.log2()
        })
        .sum()
}

pub(crate) fn luhn_valid(raw: &str) -> bool {
    let digits: Vec<u32> = raw
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .filter_map(|ch| ch.to_digit(10))
        .collect();
    if digits.len() < 13 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for digit in digits.iter().rev() {
        let mut value = *digit;
        if double {
            value *= 2;
            if value > 9 {
                value -= 9;
            }
        }
        sum += value;
        double = !double;
    }
    sum.is_multiple_of(10)
}

pub(crate) fn redact_sample(sample: &str) -> String {
    let chars: Vec<char> = sample.chars().collect();
    if chars.len() <= 6 {
        return "*".repeat(chars.len().max(1));
    }

    let prefix = chars.iter().take(3).collect::<String>();
    let suffix = chars.iter().skip(chars.len() - 3).collect::<String>();
    format!("{prefix}…{suffix}")
}

pub(crate) fn load_custom_patterns(path: &str) -> Vec<String> {
    let contents = std::fs::read_to_string(path).unwrap_or_default();
    if contents.is_empty() {
        return Vec::new();
    }
    #[derive(serde::Deserialize)]
    struct CustomPatternFile {
        patterns: Vec<String>,
    }

    match toml::from_str::<CustomPatternFile>(&contents) {
        Ok(file) => file.patterns,
        Err(_) => Vec::new(),
    }
}
