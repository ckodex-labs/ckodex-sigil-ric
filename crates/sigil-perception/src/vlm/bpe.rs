//! Byte-level BPE from a Hugging Face `tokenizer.json` (RIC-MM-001 WP6).
//!
//! Only the pipeline Qwen2-family tokenizers declare is supported: an NFC
//! normalizer, a regex `Split` (isolated) followed by a `ByteLevel`
//! pre-tokenizer without prefix space or its own regex, and a BPE model with
//! no byte fallback, dropout, subword prefix or suffix. Any other
//! declaration is refused at load, so a tokenizer whose semantics this code
//! does not implement can never produce IDs.

use std::collections::HashMap;

use serde_json::Value;
use unicode_normalization::UnicodeNormalization;

/// Why a `tokenizer.json` could not be loaded or a text encoded.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum TokenizerError {
    #[error("tokenizer.json is not valid JSON")]
    Json,
    #[error("unsupported tokenizer.json: {0}")]
    Unsupported(String),
    #[error("pre-tokenizer regex failed: {0}")]
    Regex(String),
    #[error("no vocabulary entry for symbol {0:?}")]
    UnknownSymbol(String),
}

/// A loaded byte-level BPE tokenizer.
pub struct ByteLevelBpe {
    vocab: HashMap<String, u32>,
    ranks: HashMap<String, u32>,
    /// Added (special) tokens, longest first, matched on the raw text.
    added: Vec<(String, u32)>,
    pretokenizer: fancy_regex::Regex,
    byte_chars: [char; 256],
}

impl std::fmt::Debug for ByteLevelBpe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ByteLevelBpe")
            .field("vocab", &self.vocab.len())
            .field("merges", &self.ranks.len())
            .field("added", &self.added.len())
            .finish()
    }
}

fn unsupported(what: &str) -> TokenizerError {
    TokenizerError::Unsupported(what.to_string())
}

fn str_at<'v>(value: &'v Value, pointer: &str) -> Option<&'v str> {
    value.pointer(pointer).and_then(Value::as_str)
}

fn check_normalizer(json: &Value) -> Result<(), TokenizerError> {
    if str_at(json, "/normalizer/type") == Some("NFC") {
        Ok(())
    } else {
        Err(unsupported("normalizer other than NFC"))
    }
}

/// The Split regex, after checking the pre-tokenizer sequence is exactly
/// Split(regex, isolated) then ByteLevel(no prefix space, no regex).
fn split_pattern(json: &Value) -> Result<&str, TokenizerError> {
    let steps = json
        .pointer("/pre_tokenizer/pretokenizers")
        .and_then(Value::as_array)
        .filter(|steps| str_at(json, "/pre_tokenizer/type") == Some("Sequence") && steps.len() == 2)
        .ok_or_else(|| unsupported("pre-tokenizer other than Sequence[Split, ByteLevel]"))?;
    let (split, byte_level) = (&steps[0], &steps[1]);
    let split_ok = str_at(split, "/type") == Some("Split")
        && str_at(split, "/behavior") == Some("Isolated")
        && split.get("invert") == Some(&Value::Bool(false));
    let byte_level_ok = str_at(byte_level, "/type") == Some("ByteLevel")
        && byte_level.get("add_prefix_space") == Some(&Value::Bool(false))
        && byte_level.get("use_regex") == Some(&Value::Bool(false));
    if !(split_ok && byte_level_ok) {
        return Err(unsupported("Split or ByteLevel options"));
    }
    str_at(split, "/pattern/Regex").ok_or_else(|| unsupported("Split without a regex"))
}

fn check_model(model: &Value) -> Result<(), TokenizerError> {
    // Absent, null and "" all mean "none" in tokenizers' serialization.
    let plain = |key: &str| match model.get(key) {
        None | Some(Value::Null) => true,
        Some(Value::String(s)) => s.is_empty(),
        Some(_) => false,
    };
    let ok = str_at(model, "/type") == Some("BPE")
        && model.get("byte_fallback") == Some(&Value::Bool(false))
        && !matches!(model.get("ignore_merges"), Some(Value::Bool(true)))
        && plain("dropout")
        && plain("unk_token")
        && plain("continuing_subword_prefix")
        && plain("end_of_word_suffix");
    if ok {
        Ok(())
    } else {
        Err(unsupported("BPE options"))
    }
}

fn load_vocab(model: &Value) -> Result<HashMap<String, u32>, TokenizerError> {
    let entries = model
        .get("vocab")
        .and_then(Value::as_object)
        .ok_or_else(|| unsupported("BPE without a vocab"))?;
    entries
        .iter()
        .map(|(token, id)| {
            let id = id.as_u64().and_then(|id| u32::try_from(id).ok());
            id.map(|id| (token.clone(), id))
                .ok_or_else(|| unsupported("vocab id"))
        })
        .collect()
}

fn load_ranks(model: &Value) -> Result<HashMap<String, u32>, TokenizerError> {
    let merges = model
        .get("merges")
        .and_then(Value::as_array)
        .ok_or_else(|| unsupported("BPE without merges"))?;
    let mut ranks = HashMap::with_capacity(merges.len());
    for (rank, pair) in merges.iter().enumerate() {
        let parts = pair.as_array().filter(|p| p.len() == 2);
        let (Some(left), Some(right)) = (
            parts.and_then(|p| p[0].as_str()),
            parts.and_then(|p| p[1].as_str()),
        ) else {
            return Err(unsupported("merges not in [left, right] form"));
        };
        let rank = u32::try_from(rank).map_err(|_| unsupported("merge count"))?;
        ranks.entry(pair_key(left, right)).or_insert(rank);
    }
    Ok(ranks)
}

fn load_added(json: &Value) -> Result<Vec<(String, u32)>, TokenizerError> {
    let tokens = json
        .get("added_tokens")
        .and_then(Value::as_array)
        .ok_or_else(|| unsupported("no added_tokens"))?;
    let mut added = Vec::with_capacity(tokens.len());
    for token in tokens {
        let flag = |key: &str| token.get(key) == Some(&Value::Bool(true));
        if flag("lstrip") || flag("rstrip") || flag("single_word") || flag("normalized") {
            return Err(unsupported(
                "added token with strip, word or normalized options",
            ));
        }
        let content = str_at(token, "/content").ok_or_else(|| unsupported("added token"))?;
        let id = token
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| u32::try_from(id).ok())
            .ok_or_else(|| unsupported("added token id"))?;
        added.push((content.to_string(), id));
    }
    added.sort_by_key(|(content, _)| std::cmp::Reverse(content.len()));
    Ok(added)
}

/// GPT-2's reversible byte-to-character table.
fn byte_chars() -> [char; 256] {
    let printable =
        |b: u32| (33..=126).contains(&b) || (161..=172).contains(&b) || (174..=255).contains(&b);
    let mut table = ['\0'; 256];
    let mut shifted = 256u32;
    for (byte, slot) in (0u32..256).zip(table.iter_mut()) {
        let code = if printable(byte) {
            byte
        } else {
            shifted += 1;
            shifted - 1
        };
        *slot = char::from_u32(code).unwrap_or('\u{fffd}');
    }
    table
}

fn pair_key(left: &str, right: &str) -> String {
    // Byte-level symbols never contain a space (0x20 maps to U+0120).
    format!("{left} {right}")
}

impl ByteLevelBpe {
    /// Load from the bytes of a `tokenizer.json`.
    ///
    /// # Errors
    /// `Json` for malformed input, `Unsupported` for a declaration this
    /// loader does not implement, `Regex` for an invalid split pattern.
    pub fn from_tokenizer_json(bytes: &[u8]) -> Result<Self, TokenizerError> {
        let json: Value = serde_json::from_slice(bytes).map_err(|_| TokenizerError::Json)?;
        check_normalizer(&json)?;
        let pattern = split_pattern(&json)?;
        let pretokenizer =
            fancy_regex::Regex::new(pattern).map_err(|e| TokenizerError::Regex(e.to_string()))?;
        let model = json.get("model").ok_or_else(|| unsupported("no model"))?;
        check_model(model)?;
        Ok(Self {
            vocab: load_vocab(model)?,
            ranks: load_ranks(model)?,
            added: load_added(&json)?,
            pretokenizer,
            byte_chars: byte_chars(),
        })
    }

    /// The ID of an added token, by its literal content.
    #[must_use]
    pub fn added_token_id(&self, content: &str) -> Option<u32> {
        self.added
            .iter()
            .find(|(c, _)| c == content)
            .map(|(_, id)| *id)
    }

    /// The first added-token literal `text` contains, if any.
    #[must_use]
    pub fn added_token_in(&self, text: &str) -> Option<&str> {
        (0..text.len())
            .filter(|i| text.is_char_boundary(*i))
            .find_map(|i| self.added_at(&text[i..]).map(|(content, _)| content))
    }

    fn added_at(&self, rest: &str) -> Option<(&str, u32)> {
        self.added
            .iter()
            .find(|(content, _)| rest.starts_with(content.as_str()))
            .map(|(content, id)| (content.as_str(), *id))
    }

    /// Encode as Hugging Face `tokenizers` does with
    /// `add_special_tokens=False`: added-token literals in the text become
    /// their IDs, the rest is NFC-normalized, split and merged.
    ///
    /// # Errors
    /// `Regex` if the split pattern fails at match time, `UnknownSymbol`
    /// if a merged symbol has no vocabulary entry.
    pub fn encode(&self, text: &str) -> Result<Vec<u32>, TokenizerError> {
        let mut ids = Vec::new();
        let (mut start, mut cursor) = (0, 0);
        while cursor < text.len() {
            match self.added_at(&text[cursor..]) {
                Some((content, id)) => {
                    self.encode_ordinary(&text[start..cursor], &mut ids)?;
                    ids.push(id);
                    cursor += content.len();
                    start = cursor;
                }
                None => {
                    cursor += text[cursor..].chars().next().map_or(1, char::len_utf8);
                }
            }
        }
        self.encode_ordinary(&text[start..], &mut ids)?;
        Ok(ids)
    }

    fn encode_ordinary(&self, text: &str, ids: &mut Vec<u32>) -> Result<(), TokenizerError> {
        let normalized: String = text.nfc().collect();
        let mut last = 0;
        for found in self.pretokenizer.find_iter(&normalized) {
            let found = found.map_err(|e| TokenizerError::Regex(e.to_string()))?;
            if found.start() > last {
                self.merge_piece(&normalized[last..found.start()], ids)?;
            }
            self.merge_piece(found.as_str(), ids)?;
            last = found.end();
        }
        if last < normalized.len() {
            self.merge_piece(&normalized[last..], ids)?;
        }
        Ok(())
    }

    fn best_pair(&self, symbols: &[String]) -> Option<(u32, usize)> {
        symbols
            .windows(2)
            .enumerate()
            .filter_map(|(i, pair)| {
                self.ranks
                    .get(&pair_key(&pair[0], &pair[1]))
                    .map(|r| (*r, i))
            })
            .min()
    }

    fn merge_piece(&self, piece: &str, ids: &mut Vec<u32>) -> Result<(), TokenizerError> {
        let mut symbols: Vec<String> = piece
            .bytes()
            .map(|b| self.byte_chars[usize::from(b)].to_string())
            .collect();
        while let Some((_, at)) = self.best_pair(&symbols) {
            let (left, right) = (symbols[at].clone(), symbols[at + 1].clone());
            let mut merged = Vec::with_capacity(symbols.len());
            let mut i = 0;
            while i < symbols.len() {
                if i + 1 < symbols.len() && symbols[i] == left && symbols[i + 1] == right {
                    merged.push(format!("{left}{right}"));
                    i += 2;
                } else {
                    merged.push(std::mem::take(&mut symbols[i]));
                    i += 1;
                }
            }
            symbols = merged;
        }
        for symbol in symbols {
            let id = self
                .vocab
                .get(&symbol)
                .ok_or(TokenizerError::UnknownSymbol(symbol.clone()))?;
            ids.push(*id);
        }
        Ok(())
    }
}
