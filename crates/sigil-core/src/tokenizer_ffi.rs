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
