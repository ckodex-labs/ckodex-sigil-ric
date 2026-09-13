use crate::tokenizer_ffi::ZigTokenizerError;
use crate::tokenizer_ffi::{tokenizer_for_name, ZigTokenSpan, ZigTokenizer};
use crate::types::{BoundaryContext, ByteRange, Provenance, TaintedGrapheme, TrustLevel};
use crate::vocab::tables::{
    contains_disallowed_special, next_allowed_special, regex_for_encoding,
    special_tokens_for_encoding,
};
use crate::vocab::{EncodedToken, MaterializationContext, SpecialTokenMode, Vocab};
use rayon::prelude::*;
use std::sync::Arc;

impl Vocab {
    pub fn tiktoken(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            unknown_token_id: 0,
        }
    }

    pub fn try_token_id(&self, text: &str) -> Result<u32, ZigTokenizerError> {
        let tokenizer = self.tokenizer()?;
        tokenizer.encode_single_token(text)
    }

    pub fn token_id(&self, text: &str) -> u32 {
        self.try_token_id(text).unwrap_or_else(|err| {
            panic!("failed to encode single token with {}: {err:?}", self.name)
        })
    }

    pub fn try_encode_text(&self, text: &str) -> Result<Vec<EncodedToken>, ZigTokenizerError> {
        self.encode_regex_text(
            text,
            0,
            Provenance::Unknown,
            TrustLevel::Untrusted,
            false,
            false,
        )
    }

    pub fn encode_text(&self, text: &str) -> Vec<EncodedToken> {
        self.try_encode_text(text)
            .unwrap_or_else(|err| panic!("failed to encode text with {}: {err:?}", self.name))
    }

    pub fn try_encode(&self, text: &str) -> Result<Vec<EncodedToken>, ZigTokenizerError> {
        self.try_encode_with_specials(text, SpecialTokenMode::default())
    }

    pub fn encode(&self, text: &str) -> Vec<EncodedToken> {
        self.try_encode(text)
            .unwrap_or_else(|err| panic!("failed to encode with {}: {err:?}", self.name))
    }

    pub fn try_encode_with_specials(
        &self,
        text: &str,
        mode: SpecialTokenMode,
    ) -> Result<Vec<EncodedToken>, ZigTokenizerError> {
        let tokenizer = self.tokenizer()?;
        let specials = special_tokens_for_encoding(&self.name);

        if contains_disallowed_special(text, &specials, &mode) {
            return Err(ZigTokenizerError::InvalidInput);
        }

        let mut output = Vec::new();
        let mut cursor = 0usize;
        while cursor < text.len() {
            if let Some((start, special)) = next_allowed_special(text, cursor, &specials, &mode) {
                if start > cursor {
                    let ordinary = &text[cursor..start];
                    output.extend(self.encode_regex_text(
                        ordinary,
                        cursor,
                        Provenance::Unknown,
                        TrustLevel::Untrusted,
                        false,
                        false,
                    )?);
                }

                let token_id = tokenizer
                    .special_token_id(special)?
                    .ok_or(ZigTokenizerError::TokenNotFound)?;
                output.push(EncodedToken {
                    token_id,
                    text: special.to_string(),
                    byte_range: ByteRange::new(start, start + special.len()),
                    provenance: Provenance::Unknown,
                    trust_level: TrustLevel::Untrusted,
                    normalized: false,
                    boundary: false,
                });
                cursor = start + special.len();
            } else {
                let ordinary = &text[cursor..];
                output.extend(self.encode_regex_text(
                    ordinary,
                    cursor,
                    Provenance::Unknown,
                    TrustLevel::Untrusted,
                    false,
                    false,
                )?);
                break;
            }
        }

        Ok(output)
    }

    pub fn encode_with_specials(&self, text: &str, mode: SpecialTokenMode) -> Vec<EncodedToken> {
        self.try_encode_with_specials(text, mode)
            .unwrap_or_else(|err| panic!("failed to encode with {}: {err:?}", self.name))
    }

    pub fn try_decode_bytes(&self, ids: &[u32]) -> Result<Vec<u8>, ZigTokenizerError> {
        self.tokenizer()?.decode_bytes(ids)
    }

    pub fn decode_bytes(&self, ids: &[u32]) -> Vec<u8> {
        self.try_decode_bytes(ids)
            .unwrap_or_else(|err| panic!("failed to decode bytes with {}: {err:?}", self.name))
    }

    pub fn try_decode(&self, ids: &[u32]) -> Result<String, ZigTokenizerError> {
        let bytes = self.try_decode_bytes(ids)?;
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    pub fn decode(&self, ids: &[u32]) -> String {
        self.try_decode(ids)
            .unwrap_or_else(|err| panic!("failed to decode text with {}: {err:?}", self.name))
    }

    pub fn try_encode_graphemes(
        &self,
        graphemes: &[TaintedGrapheme],
    ) -> Result<Vec<EncodedToken>, ZigTokenizerError> {
        if graphemes.is_empty() {
            return Ok(Vec::new());
        }

        let text = graphemes
            .iter()
            .map(|g| g.grapheme.text.as_str())
            .collect::<String>();
        let provenance = graphemes
            .first()
            .map(|g| g.provenance)
            .unwrap_or(Provenance::Unknown);
        let trust_level = graphemes
            .first()
            .map(|g| g.trust_level)
            .unwrap_or(TrustLevel::Untrusted);
        let normalized = graphemes.iter().any(|g| g.grapheme.normalized);
        let boundary = graphemes
            .first()
            .map(|g| {
                matches!(
                    g.boundary_context,
                    BoundaryContext::Start | BoundaryContext::End | BoundaryContext::CrossBoundary
                )
            })
            .unwrap_or(false);
        let base_offset = graphemes
            .first()
            .map(|g| g.grapheme.byte_range.start)
            .unwrap_or(0);

        let mut tokens = self.encode_regex_text(
            &text,
            base_offset,
            provenance,
            trust_level,
            normalized,
            boundary,
        )?;

        // Token spans were computed in NORMALIZED cluster space but offset by
        // the RAW base offset. Whenever normalization changed byte length,
        // remap every token onto the raw byte ranges of the clusters it
        // covers, so annotations always trace to raw input (INV-007 / RIC-R-2).
        let normalized_len_changed = graphemes
            .iter()
            .any(|g| g.grapheme.text.len() != g.grapheme.byte_range.len());
        if normalized_len_changed {
            let mut cursor = 0usize;
            let mut map: Vec<(ByteRange, ByteRange)> = Vec::with_capacity(graphemes.len());
            for grapheme in graphemes {
                let n_len = grapheme.grapheme.text.len();
                map.push((
                    ByteRange::new(cursor, cursor + n_len),
                    grapheme.grapheme.byte_range,
                ));
                cursor += n_len;
            }
            for token in &mut tokens {
                let rel_start = token.byte_range.start.saturating_sub(base_offset);
                let rel_end = token.byte_range.end.saturating_sub(base_offset);
                let mut remapped: Option<ByteRange> = None;
                for (n_range, raw) in &map {
                    if n_range.start < rel_end && rel_start < n_range.end {
                        remapped = Some(match remapped {
                            Some(current) => current.union(*raw),
                            None => *raw,
                        });
                    }
                }
                if let Some(range) = remapped {
                    token.byte_range = range;
                }
            }
        }

        Ok(tokens)
    }

    pub fn encode_graphemes(&self, graphemes: &[TaintedGrapheme]) -> Vec<EncodedToken> {
        self.try_encode_graphemes(graphemes)
            .unwrap_or_else(|err| panic!("failed to encode graphemes with {}: {err:?}", self.name))
    }

    pub fn try_encode_batch<T: AsRef<str> + Sync>(
        &self,
        texts: &[T],
    ) -> Result<Vec<Vec<EncodedToken>>, ZigTokenizerError> {
        texts
            .par_iter()
            .map(|text| self.try_encode(text.as_ref()))
            .collect()
    }

    pub fn encode_batch<T: AsRef<str> + Sync>(&self, texts: &[T]) -> Vec<Vec<EncodedToken>> {
        self.try_encode_batch(texts)
            .unwrap_or_else(|err| panic!("failed to encode batch with {}: {err:?}", self.name))
    }

    pub fn try_encode_batch_with_specials<T: AsRef<str> + Sync>(
        &self,
        texts: &[T],
        mode: SpecialTokenMode,
    ) -> Result<Vec<Vec<EncodedToken>>, ZigTokenizerError> {
        texts
            .par_iter()
            .map(|text| self.try_encode_with_specials(text.as_ref(), mode.clone()))
            .collect()
    }

    pub fn encode_batch_with_specials<T: AsRef<str> + Sync>(
        &self,
        texts: &[T],
        mode: SpecialTokenMode,
    ) -> Vec<Vec<EncodedToken>> {
        self.try_encode_batch_with_specials(texts, mode)
            .unwrap_or_else(|err| panic!("failed to encode batch with {}: {err:?}", self.name))
    }

    pub fn try_decode_batch(&self, batches: &[Vec<u32>]) -> Result<Vec<String>, ZigTokenizerError> {
        batches.par_iter().map(|ids| self.try_decode(ids)).collect()
    }

    pub fn decode_batch(&self, batches: &[Vec<u32>]) -> Vec<String> {
        self.try_decode_batch(batches)
            .unwrap_or_else(|err| panic!("failed to decode batch with {}: {err:?}", self.name))
    }

    fn encode_regex_text(
        &self,
        text: &str,
        base_offset: usize,
        provenance: Provenance,
        trust_level: TrustLevel,
        normalized: bool,
        boundary: bool,
    ) -> Result<Vec<EncodedToken>, ZigTokenizerError> {
        let regex = regex_for_encoding(&self.name)?;
        let tokenizer = self.tokenizer()?;
        let mut output = Vec::new();
        for piece in regex.find_iter(text) {
            let piece = piece.map_err(|_| ZigTokenizerError::InvalidInput)?;
            let piece_text = &text[piece.start()..piece.end()];
            let spans = tokenizer.encode_piece(piece_text)?;
            output.extend(self.materialize_tokens(
                MaterializationContext {
                    text: piece_text,
                    base_offset: base_offset + piece.start(),
                    provenance,
                    trust_level,
                    normalized,
                    boundary,
                },
                spans,
            ));
        }
        Ok(output)
    }

    fn materialize_tokens(
        &self,
        ctx: MaterializationContext<'_>,
        spans: Vec<ZigTokenSpan>,
    ) -> Vec<EncodedToken> {
        let bytes = ctx.text.as_bytes();
        spans
            .into_iter()
            .map(|span| {
                let token_bytes = bytes
                    .get(span.start..span.end)
                    .unwrap_or_else(|| panic!("token span out of bounds for {}", self.name));
                let token_text = String::from_utf8_lossy(token_bytes).into_owned();
                EncodedToken {
                    token_id: span.token_id,
                    text: token_text,
                    byte_range: ByteRange::new(
                        ctx.base_offset + span.start,
                        ctx.base_offset + span.end,
                    ),
                    provenance: ctx.provenance,
                    trust_level: ctx.trust_level,
                    normalized: ctx.normalized,
                    boundary: ctx.boundary,
                }
            })
            .collect()
    }

    fn tokenizer(&self) -> Result<Arc<ZigTokenizer>, ZigTokenizerError> {
        tokenizer_for_name(&self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Grapheme, ScanFinding};

    fn vocab() -> Vocab {
        Vocab::tiktoken("cl100k_base")
    }

    fn tainted(text: &str, start: usize) -> TaintedGrapheme {
        TaintedGrapheme {
            grapheme: Grapheme {
                text: text.to_string(),
                byte_range: ByteRange::new(start, start + text.len()),
                normalized: false,
            },
            provenance: Provenance::User,
            trust_level: TrustLevel::Untrusted,
            boundary_context: BoundaryContext::Interior,
            threat: ScanFinding::none(ByteRange::new(start, start + text.len())),
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let v = vocab();
        let tokens = v.encode("the quick brown fox");
        assert!(!tokens.is_empty());
        let ids: Vec<u32> = tokens.iter().map(|t| t.token_id).collect();
        assert_eq!(v.decode(&ids), "the quick brown fox");
    }

    #[test]
    fn token_id_for_single_token_piece() {
        let v = vocab();
        let encoded = v.encode_text("hello");
        if encoded.len() == 1 {
            assert_eq!(v.token_id("hello"), encoded[0].token_id);
        }
    }

    #[test]
    fn encode_tracks_byte_ranges() {
        let v = vocab();
        let tokens = v.encode_text("hello world");
        let mut cursor = 0usize;
        for token in &tokens {
            assert_eq!(token.byte_range.start, cursor);
            cursor = token.byte_range.end;
        }
        assert_eq!(cursor, "hello world".len());
    }

    #[test]
    fn specials_disallow_rejects_injection_token() {
        let v = vocab();
        let err = v
            .try_encode_with_specials("x <|endoftext|> y", SpecialTokenMode::Disallow)
            .expect_err("special token must be rejected");
        assert_eq!(err, ZigTokenizerError::InvalidInput);
    }

    #[test]
    fn specials_allow_only_permits_listed() {
        let v = vocab();
        let mut allowed = std::collections::HashSet::new();
        allowed.insert("<|endoftext|>".to_string());
        let tokens = v.encode_with_specials("<|endoftext|>", SpecialTokenMode::AllowOnly(allowed));
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0].token_id, 100257);
        assert_eq!(tokens[0].text, "<|endoftext|>");
    }

    #[test]
    fn encode_graphemes_empty_returns_empty() {
        assert_eq!(vocab().encode_graphemes(&[]), Vec::new());
    }

    #[test]
    fn encode_graphemes_carries_provenance() {
        let v = vocab();
        let g = tainted("test input", 0);
        let tokens = v.encode_graphemes(&[g]);
        assert!(!tokens.is_empty());
        for token in &tokens {
            assert_eq!(token.provenance, Provenance::User);
            assert_eq!(token.trust_level, TrustLevel::Untrusted);
        }
    }

    #[test]
    fn encode_graphemes_remaps_normalized_lengths() {
        // A grapheme whose normalized text differs in byte length from the
        // raw span exercises the INV-007 raw-range remapping path.
        let v = vocab();
        let mut g = tainted("ab", 10);
        g.grapheme.text = "abcd".to_string(); // normalized longer than raw
        g.grapheme.normalized = true;
        let tokens = v.encode_graphemes(&[g]);
        assert!(!tokens.is_empty());
        for token in &tokens {
            // Remapped ranges must stay within the raw span [10, 12).
            assert!(token.byte_range.start >= 10);
            assert!(token.byte_range.end <= 12);
        }
    }

    #[test]
    fn batch_encode_and_decode() {
        let v = vocab();
        let texts = ["alpha", "beta gamma"];
        let batches = v.encode_batch(&texts);
        assert_eq!(batches.len(), 2);
        let decoded = v.decode_batch(
            &batches
                .iter()
                .map(|b| b.iter().map(|t| t.token_id).collect())
                .collect::<Vec<Vec<u32>>>(),
        );
        assert_eq!(decoded, texts);
    }

    #[test]
    fn boundary_flag_propagates() {
        let v = vocab();
        let mut g = tainted("x", 0);
        g.boundary_context = BoundaryContext::Start;
        let tokens = v.encode_graphemes(&[g]);
        assert!(tokens.iter().all(|t| t.boundary));
    }

    #[test]
    fn try_decode_reports_invalid_utf8_as_lossy() {
        let v = vocab();
        // Decoding arbitrary ids must not panic; lossy conversion covers
        // non-UTF8 byte sequences.
        let _ = v.try_decode(&[v.encode_text("ok")[0].token_id]);
    }
}
