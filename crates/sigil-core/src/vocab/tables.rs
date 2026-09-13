use crate::tokenizer_ffi::ZigTokenizerError;
use crate::vocab::SpecialTokenMode;
use fancy_regex::Regex;
use std::borrow::Cow;
use std::sync::OnceLock;

pub(crate) fn regex_for_encoding(name: &str) -> Result<&'static Regex, ZigTokenizerError> {
    match name {
        "gpt2" | "r50k_base" | "p50k_base" | "p50k_edit" => Ok(r50k_regex()),
        "cl100k_base" => Ok(cl100k_regex()),
        "o200k_base" | "o200k_harmony" => Ok(o200k_regex()),
        _ => Err(ZigTokenizerError::UnknownEncoding),
    }
}

pub(crate) fn r50k_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"'(?:[sdmt]|ll|ve|re)| ?\p{L}++| ?\p{N}++| ?[^\s\p{L}\p{N}]++|\s++$|\s+(?!\S)|\s"#,
        )
        .expect("valid r50k regex")
    })
}

pub(crate) fn cl100k_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"(?i:'(?:[sdmt]|ll|ve|re)|[^\r\n\p{L}\p{N}]?+\p{L}++|\p{N}{1,3}+| ?[^\s\p{L}\p{N}]++[\r\n]*+|\s++$|\s*[\r\n]|\s+(?!\S)|\s)"#,
        )
        .expect("valid cl100k regex")
    })
}

pub(crate) fn o200k_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r#"([^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]*[\p{Ll}\p{Lm}\p{Lo}\p{M}]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}]+[\p{Ll}\p{Lm}\p{Lo}\p{M}]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n/]*|\s*[\r\n]+|\s+(?!\S)|\s+)"#,
        )
        .expect("valid o200k regex")
    })
}

pub(crate) fn special_tokens_for_encoding(name: &str) -> Vec<Cow<'static, str>> {
    match name {
        "gpt2" | "r50k_base" | "p50k_base" => vec![Cow::Borrowed("<|endoftext|>")],
        "p50k_edit" => vec![
            Cow::Borrowed("<|endoftext|>"),
            Cow::Borrowed("<|fim_prefix|>"),
            Cow::Borrowed("<|fim_middle|>"),
            Cow::Borrowed("<|fim_suffix|>"),
        ],
        "cl100k_base" => vec![
            Cow::Borrowed("<|endoftext|>"),
            Cow::Borrowed("<|fim_prefix|>"),
            Cow::Borrowed("<|fim_middle|>"),
            Cow::Borrowed("<|fim_suffix|>"),
            Cow::Borrowed("<|endofprompt|>"),
        ],
        "o200k_base" => vec![
            Cow::Borrowed("<|endoftext|>"),
            Cow::Borrowed("<|endofprompt|>"),
        ],
        "o200k_harmony" => {
            let mut specials = vec![
                Cow::Borrowed("<|startoftext|>"),
                Cow::Borrowed("<|endoftext|>"),
                Cow::Borrowed("<|reserved_200000|>"),
                Cow::Borrowed("<|reserved_200001|>"),
                Cow::Borrowed("<|return|>"),
                Cow::Borrowed("<|constrain|>"),
                Cow::Borrowed("<|reserved_200004|>"),
                Cow::Borrowed("<|channel|>"),
                Cow::Borrowed("<|start|>"),
                Cow::Borrowed("<|end|>"),
                Cow::Borrowed("<|message|>"),
                Cow::Borrowed("<|reserved_200009|>"),
                Cow::Borrowed("<|reserved_200010|>"),
                Cow::Borrowed("<|reserved_200011|>"),
                Cow::Borrowed("<|call|>"),
            ];
            for id in 200013u32..=201087u32 {
                specials.push(Cow::Owned(format!("<|reserved_{id}|>")));
            }
            specials
        }
        _ => Vec::new(),
    }
}

pub(crate) fn contains_disallowed_special(
    text: &str,
    specials: &[Cow<'static, str>],
    mode: &SpecialTokenMode,
) -> bool {
    match mode {
        SpecialTokenMode::AllowAll => false,
        SpecialTokenMode::Disallow => specials
            .iter()
            .any(|special| text.contains(special.as_ref())),
        SpecialTokenMode::AllowOnly(allowed) => specials
            .iter()
            .filter(|special| !allowed.contains(special.as_ref()))
            .any(|special| text.contains(special.as_ref())),
    }
}

pub(crate) fn next_allowed_special<'a>(
    text: &'a str,
    cursor: usize,
    specials: &[Cow<'static, str>],
    mode: &SpecialTokenMode,
) -> Option<(usize, &'a str)> {
    let mut best: Option<(usize, &'a str)> = None;
    for special in specials {
        let special = special.as_ref();
        if !is_special_allowed(special, mode) {
            continue;
        }
        if let Some(relative) = text[cursor..].find(special) {
            let start = cursor + relative;
            match best {
                None => best = Some((start, &text[start..start + special.len()])),
                Some((best_start, best_special)) => {
                    if start < best_start
                        || (start == best_start && special.len() > best_special.len())
                    {
                        best = Some((start, &text[start..start + special.len()]));
                    }
                }
            }
        }
    }
    best
}

pub(crate) fn is_special_allowed(special: &str, mode: &SpecialTokenMode) -> bool {
    match mode {
        SpecialTokenMode::AllowAll => true,
        SpecialTokenMode::Disallow => false,
        SpecialTokenMode::AllowOnly(allowed) => allowed.contains(special),
    }
}
