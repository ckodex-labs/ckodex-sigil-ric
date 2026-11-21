//! Safe wrapper over the Zig tiktoken static library (`zig/tiktoken/src/lib.zig`).
//!
//! This is the only module in `sigil-core` allowed to use `unsafe`. Every block
//! below carries a SAFETY note that names the Zig-side guarantee it relies on.
//! Shared contract, read from `lib.zig`:
//! - `zig_tiktoken_open` writes a heap handle only on return code 0; the handle
//!   is freed exactly once, by `Drop`.
//! - After `open`, every exported function only reads the handle's maps; the
//!   maps are written during `Tokenizer.init` and never again.
//! - Output buffers are allocated from `std.heap.page_allocator` (thread-safe),
//!   are valid for `len` elements on return code 0, and are released through the
//!   matching `zig_tiktoken_free_*` call.
#![allow(
    unsafe_code,
    reason = "FFI boundary to the Zig tokenizer; each unsafe block documents its invariant"
)]

use std::{
    collections::HashMap,
    ffi::c_void,
    ptr::{NonNull, null_mut},
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
unsafe extern "C" {
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

// SAFETY: the handle is an owned heap allocation with no thread affinity, freed
// once by `Drop`; moving it between threads is sound.
unsafe impl Send for ZigTokenizer {}
// SAFETY: after `open` the Zig side only reads the handle (all map writes happen
// in `Tokenizer.init`), and per-call output buffers come from the thread-safe
// `page_allocator`, so concurrent `&self` calls do not race.
unsafe impl Sync for ZigTokenizer {}

impl ZigTokenizer {
    pub fn open(name: &str) -> Result<Arc<Self>, ZigTokenizerError> {
        let mut handle = null_mut();
        // SAFETY: `name` is valid for `name.len()` bytes for the duration of the call;
        // `handle` is a live out-pointer that Zig writes only on success.
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
        // SAFETY: the handle is live (owned by `self`), `text` is valid for
        // `text.len()` bytes, and `buffer` is a live out-pointer.
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

        let spans = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: on return code 0 Zig set `items` to an allocation valid for
            // `len` spans; `len > 0` here, so the pointer is non-null.
            unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() }
        };
        // SAFETY: `buffer` holds the allocation Zig just returned and is freed once.
        unsafe { zig_tiktoken_free_tokens(self.handle.as_ptr(), &mut buffer) };
        Ok(spans)
    }

    pub fn encode_piece(&self, text: &str) -> Result<Vec<ZigTokenSpan>, ZigTokenizerError> {
        let mut buffer = ZigTokenBuffer {
            items: null_mut(),
            len: 0,
        };
        // SAFETY: as in `encode_ordinary`: live handle, valid input slice, live
        // out-pointer.
        let rc = unsafe {
            zig_tiktoken_encode_piece(self.handle.as_ptr(), text.as_ptr(), text.len(), &mut buffer)
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let spans = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: on return code 0 Zig set `items` to an allocation valid for
            // `len` spans; `len > 0` here, so the pointer is non-null.
            unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() }
        };
        // SAFETY: `buffer` holds the allocation Zig just returned and is freed once.
        unsafe { zig_tiktoken_free_tokens(self.handle.as_ptr(), &mut buffer) };
        Ok(spans)
    }

    pub fn encode_single_token(&self, text: &str) -> Result<u32, ZigTokenizerError> {
        let mut id = 0u32;
        // SAFETY: live handle, `text` valid for `text.len()` bytes, `id` is a live
        // out-pointer.
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
        // SAFETY: live handle, `ids` valid for `ids.len()` elements, `buffer` is a
        // live out-pointer.
        let rc = unsafe {
            zig_tiktoken_decode_bytes(self.handle.as_ptr(), ids.as_ptr(), ids.len(), &mut buffer)
        };
        if rc != 0 {
            return Err(ZigTokenizerError::from_code(rc));
        }

        let bytes = if buffer.len == 0 {
            Vec::new()
        } else {
            // SAFETY: on return code 0 Zig set `items` to an allocation valid for
            // `len` bytes; `len > 0` here, so the pointer is non-null.
            unsafe { slice::from_raw_parts(buffer.items, buffer.len).to_vec() }
        };
        // SAFETY: `buffer` holds the allocation Zig just returned and is freed once.
        unsafe { zig_tiktoken_free_bytes(self.handle.as_ptr(), &mut buffer) };
        Ok(bytes)
    }

    pub fn special_token_id(&self, name: &str) -> Result<Option<u32>, ZigTokenizerError> {
        let mut id = 0u32;
        // SAFETY: live handle, `name` valid for `name.len()` bytes, `id` is a live
        // out-pointer.
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
        // SAFETY: the handle came from a successful `open` and `Drop` runs once, so
        // it is closed exactly once and never used afterwards.
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
