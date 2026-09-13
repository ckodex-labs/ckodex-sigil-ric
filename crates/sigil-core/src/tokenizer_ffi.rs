use std::{
    collections::HashMap,
    ffi::c_void,
    ptr::{null_mut, NonNull},
    slice,
    sync::{Arc, Mutex, OnceLock},
};
use thiserror::Error;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZigTokenSpan {
    pub token_id: u32,
    pub start: usize,
    pub end: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZigTokenBuffer {
    pub items: *mut ZigTokenSpan,
    pub len: usize,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct ZigByteBuffer {
    pub items: *mut u8,
    pub len: usize,
}

#[link(name = "zig_tiktoken", kind = "static")]
extern "C" {
    fn zig_tiktoken_open(name_ptr: *const u8, name_len: usize, out_handle: *mut *mut c_void)
        -> i32;
    fn zig_tiktoken_close(handle: *mut c_void);
    fn zig_tiktoken_encode_ordinary(
        handle: *mut c_void,
        text_ptr: *const u8,
        text_len: usize,
        out: *mut ZigTokenBuffer,
    ) -> i32;
    fn zig_tiktoken_encode_piece(
        handle: *mut c_void,
        text_ptr: *const u8,
        text_len: usize,
        out: *mut ZigTokenBuffer,
    ) -> i32;
    fn zig_tiktoken_free_tokens(handle: *mut c_void, buffer: *mut ZigTokenBuffer);
    fn zig_tiktoken_encode_single_token(
        handle: *mut c_void,
        text_ptr: *const u8,
        text_len: usize,
        out_id: *mut u32,
    ) -> i32;
    fn zig_tiktoken_decode_bytes(
        handle: *mut c_void,
        ids_ptr: *const u32,
        ids_len: usize,
        out: *mut ZigByteBuffer,
    ) -> i32;
    fn zig_tiktoken_free_bytes(handle: *mut c_void, buffer: *mut ZigByteBuffer);
    fn zig_tiktoken_special_token_id(
        handle: *mut c_void,
        name_ptr: *const u8,
        name_len: usize,
        out_id: *mut u32,
    ) -> i32;
}

#[derive(Debug)]
pub struct ZigTokenizer {
    handle: NonNull<c_void>,
}

unsafe impl Send for ZigTokenizer {}
unsafe impl Sync for ZigTokenizer {}

impl ZigTokenizer {
    pub fn open(name: &str) -> Result<Arc<Self>, ZigTokenizerError> {
        let mut handle = null_mut();
        let rc = unsafe { zig_tiktoken_open(name.as_ptr(), name.len(), &mut handle) };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let handle = NonNull::new(handle).ok_or(ZigTokenizerError::NullHandle)?;
        Ok(Arc::new(Self { handle }))
    }

    pub fn encode_ordinary(&self, text: &str) -> Result<Vec<ZigTokenSpan>, ZigTokenizerError> {
        let mut buffer = ZigTokenBuffer {
            items: null_mut(),
            len: 0,
        };
        let rc = unsafe {
            zig_tiktoken_encode_ordinary(
                self.handle.as_ptr(),
                text.as_ptr(),
                text.len(),
                &mut buffer,
            )
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let spans = unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() };
        unsafe { zig_tiktoken_free_tokens(self.handle.as_ptr(), &mut buffer) };
        Ok(spans)
    }

    pub fn encode_piece(&self, text: &str) -> Result<Vec<ZigTokenSpan>, ZigTokenizerError> {
        let mut buffer = ZigTokenBuffer {
            items: null_mut(),
            len: 0,
        };
        let rc = unsafe {
            zig_tiktoken_encode_piece(self.handle.as_ptr(), text.as_ptr(), text.len(), &mut buffer)
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let spans = unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() };
        unsafe { zig_tiktoken_free_tokens(self.handle.as_ptr(), &mut buffer) };
        Ok(spans)
    }

    pub fn encode_single_token(&self, text: &str) -> Result<u32, ZigTokenizerError> {
        let mut id = 0u32;
        let rc = unsafe {
            zig_tiktoken_encode_single_token(
                self.handle.as_ptr(),
                text.as_ptr(),
                text.len(),
                &mut id,
            )
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }
        Ok(id)
    }

    pub fn decode_bytes(&self, ids: &[u32]) -> Result<Vec<u8>, ZigTokenizerError> {
        let mut buffer = ZigByteBuffer {
            items: null_mut(),
            len: 0,
        };
        let rc = unsafe {
            zig_tiktoken_decode_bytes(self.handle.as_ptr(), ids.as_ptr(), ids.len(), &mut buffer)
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let bytes = unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() };
        unsafe { zig_tiktoken_free_bytes(self.handle.as_ptr(), &mut buffer) };
        Ok(bytes)
    }

    pub fn special_token_id(&self, name: &str) -> Result<Option<u32>, ZigTokenizerError> {
        let mut id = 0u32;
        let rc = unsafe {
            zig_tiktoken_special_token_id(self.handle.as_ptr(), name.as_ptr(), name.len(), &mut id)
        };
        match rc {
            0 => Ok(Some(id)),
            3 => Ok(None),
            other => Err(ZigTokenizerError::from_code(other)),
        }
    }
}

impl Drop for ZigTokenizer {
    fn drop(&mut self) {
        unsafe { zig_tiktoken_close(self.handle.as_ptr()) };
    }
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ZigTokenizerError {
    #[error("unknown encoding")]
    UnknownEncoding,
    #[error("invalid utf-8")]
    InvalidUtf8,
    #[error("token not found")]
    TokenNotFound,
    #[error("allocation failed")]
    AllocFailed,
    #[error("invalid input")]
    InvalidInput,
    #[error("null handle")]
    NullHandle,
}

impl ZigTokenizerError {
    fn from_code(code: i32) -> Self {
        match code {
            1 => Self::UnknownEncoding,
            2 => Self::InvalidUtf8,
            3 => Self::TokenNotFound,
            4 => Self::AllocFailed,
            _ => Self::InvalidInput,
        }
    }
}

static TOKENIZER_CACHE: OnceLock<Mutex<HashMap<String, Arc<ZigTokenizer>>>> = OnceLock::new();

pub fn tokenizer_for_name(name: &str) -> Result<Arc<ZigTokenizer>, ZigTokenizerError> {
    let cache = TOKENIZER_CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some(tokenizer) = cache.lock().expect("tokenizer cache").get(name).cloned() {
        return Ok(tokenizer);
    }

    let tokenizer = ZigTokenizer::open(name)?;
    cache
        .lock()
        .expect("tokenizer cache")
        .insert(name.to_string(), tokenizer.clone());
    Ok(tokenizer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cl100k() -> Arc<ZigTokenizer> {
        tokenizer_for_name("cl100k_base").expect("cl100k tokenizer")
    }

    #[test]
    fn encode_piece_matches_ordinary_shape() {
        let tok = cl100k();
        let piece = tok.encode_piece("hello").expect("encode_piece");
        let ordinary = tok.encode_ordinary("hello").expect("encode_ordinary");
        assert!(!piece.is_empty());
        assert_eq!(piece.len(), ordinary.len());
        for (p, o) in piece.iter().zip(ordinary.iter()) {
            assert_eq!(p.token_id, o.token_id);
            assert_eq!((p.start, p.end), (o.start, o.end));
        }
    }

    #[test]
    fn encode_single_token_returns_id() {
        let tok = cl100k();
        let spans = tok.encode_ordinary("hello").expect("encode");
        if spans.len() == 1 {
            let id = tok.encode_single_token("hello").expect("single token");
            assert_eq!(id, spans[0].token_id);
        }
    }

    #[test]
    fn decode_bytes_roundtrips() {
        let tok = cl100k();
        let text = "round trip through zig";
        let spans = tok.encode_ordinary(text).expect("encode");
        let ids: Vec<u32> = spans.iter().map(|s| s.token_id).collect();
        let bytes = tok.decode_bytes(&ids).expect("decode");
        assert_eq!(bytes, text.as_bytes());
    }

    #[test]
    fn decode_empty_input_returns_empty() {
        let tok = cl100k();
        assert_eq!(tok.decode_bytes(&[]).expect("decode"), Vec::<u8>::new());
    }

    #[test]
    fn special_token_lookup_hit_and_miss() {
        let tok = cl100k();
        let eot = tok
            .special_token_id("<|endoftext|>")
            .expect("special lookup");
        assert_eq!(eot, Some(100257));
        let missing = tok
            .special_token_id("<|definitely_not_a_token|>")
            .expect("lookup");
        assert_eq!(missing, None);
    }

    #[test]
    fn open_rejects_unknown_encoding() {
        let err =
            ZigTokenizer::open("not_a_real_encoding_name").expect_err("unknown encoding must fail");
        assert_eq!(err, ZigTokenizerError::UnknownEncoding);
    }

    #[test]
    fn error_codes_map_to_variants() {
        assert_eq!(
            ZigTokenizerError::from_code(1),
            ZigTokenizerError::UnknownEncoding
        );
        assert_eq!(
            ZigTokenizerError::from_code(2),
            ZigTokenizerError::InvalidUtf8
        );
        assert_eq!(
            ZigTokenizerError::from_code(3),
            ZigTokenizerError::TokenNotFound
        );
        assert_eq!(
            ZigTokenizerError::from_code(4),
            ZigTokenizerError::AllocFailed
        );
        assert_eq!(
            ZigTokenizerError::from_code(99),
            ZigTokenizerError::InvalidInput
        );
    }

    #[test]
    fn tokenizer_cache_returns_shared_handle() {
        let a = tokenizer_for_name("cl100k_base").expect("first");
        let b = tokenizer_for_name("cl100k_base").expect("second");
        assert!(Arc::ptr_eq(&a, &b));
    }
}
