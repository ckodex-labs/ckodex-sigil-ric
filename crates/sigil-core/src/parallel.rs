use crate::{
    tokenizer_ffi::ZigTokenizerError,
    vocab::{EncodedToken, SpecialTokenMode, Vocab},
};
use rayon::prelude::*;

#[derive(Clone, Debug)]
pub struct TokenizerActor {
    vocab: Vocab,
}

impl TokenizerActor {
    pub fn new(vocab: Vocab) -> Self {
        Self { vocab }
    }

    pub fn vocab(&self) -> &Vocab {
        &self.vocab
    }

    pub fn encode_batch<T: AsRef<str> + Sync>(
        &self,
        texts: &[T],
    ) -> Result<Vec<Vec<EncodedToken>>, ZigTokenizerError> {
        texts
            .par_iter()
            .map(|text| self.vocab.try_encode(text.as_ref()))
            .collect()
    }

    pub fn encode_batch_with_specials<T: AsRef<str> + Sync>(
        &self,
        texts: &[T],
        mode: SpecialTokenMode,
    ) -> Result<Vec<Vec<EncodedToken>>, ZigTokenizerError> {
        texts
            .par_iter()
            .map(|text| {
                self.vocab
                    .try_encode_with_specials(text.as_ref(), mode.clone())
            })
            .collect()
    }

    pub fn decode_batch(&self, batches: &[Vec<u32>]) -> Result<Vec<String>, ZigTokenizerError> {
        batches
            .par_iter()
            .map(|ids| self.vocab.try_decode(ids))
            .collect()
    }
}
