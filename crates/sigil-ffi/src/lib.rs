//! `libsigil` — the C ABI shared-library artifact (spec §4 Delivery
//! Artifacts).
//!
//! The public ABI is the `zig_tiktoken_*` surface documented in
//! `bindings/c/sigil_tiktoken.h`: the same symbols the Python `ctypes` and
//! Go `cgo` bindings already load. This crate compiles the Zig tokenizer
//! static library and re-exports its symbols from a Rust-produced cdylib,
//! so consumers get one artifact (`libsigil.{so,dylib,dll}`) built by
//! `cargo build -p sigil-ffi --release` without a separate Zig toolchain
//! invocation.
//!
//! `sigil_ffi_pin` exists only to keep the static-lib members reachable:
//! Rust emits no calls into the ABI surface, so without a reference the
//! linker would dead-strip every `zig_tiktoken_*` object out of the
//! archive. It is never meant to be called and does nothing.
//!
//! The `sigil.wasm` sibling artifact is produced from the same Zig source
//! via `scripts/build_wasm.sh` (wasm32-freestanding reactor module).

use std::ffi::c_char;
use std::os::raw::c_int;

#[repr(C)]
pub struct ZigTokenSpan {
    pub token_id: u32,
    pub start: usize,
    pub end: usize,
}

#[repr(C)]
pub struct ZigTokenBuffer {
    pub items: *mut ZigTokenSpan,
    pub len: usize,
}

#[repr(C)]
pub struct ZigByteBuffer {
    pub items: *mut u8,
    pub len: usize,
}

#[allow(non_camel_case_types)]
pub enum zig_tiktoken_handle {}

extern "C" {
    fn zig_tiktoken_open(
        name_ptr: *const u8,
        name_len: usize,
        out_handle: *mut *mut zig_tiktoken_handle,
    ) -> c_int;
    fn zig_tiktoken_close(handle: *mut zig_tiktoken_handle);
    fn zig_tiktoken_encode_ordinary(
        handle: *mut zig_tiktoken_handle,
        text_ptr: *const u8,
        text_len: usize,
        out: *mut ZigTokenBuffer,
    ) -> c_int;
    fn zig_tiktoken_encode_piece(
        handle: *mut zig_tiktoken_handle,
        text_ptr: *const u8,
        text_len: usize,
        out: *mut ZigTokenBuffer,
    ) -> c_int;
    fn zig_tiktoken_free_tokens(handle: *mut zig_tiktoken_handle, buffer: *mut ZigTokenBuffer);
    fn zig_tiktoken_encode_single_token(
        handle: *mut zig_tiktoken_handle,
        text_ptr: *const u8,
        text_len: usize,
        out_id: *mut u32,
    ) -> c_int;
    fn zig_tiktoken_decode_bytes(
        handle: *mut zig_tiktoken_handle,
        ids_ptr: *const u32,
        ids_len: usize,
        out: *mut ZigByteBuffer,
    ) -> c_int;
    fn zig_tiktoken_free_bytes(handle: *mut zig_tiktoken_handle, buffer: *mut ZigByteBuffer);
    fn zig_tiktoken_special_token_id(
        handle: *mut zig_tiktoken_handle,
        name_ptr: *const u8,
        name_len: usize,
        out_id: *mut u32,
    ) -> c_int;
}

/// Pin every ABI symbol into the cdylib's export table. Referencing each
/// function forces the linker to pull its archive member; the symbols are
/// then re-exported from `libsigil` unchanged.
#[no_mangle]
pub extern "C" fn sigil_ffi_pin() -> usize {
    let fns: [*const (); 9] = [
        zig_tiktoken_open as *const (),
        zig_tiktoken_close as *const (),
        zig_tiktoken_encode_ordinary as *const (),
        zig_tiktoken_encode_piece as *const (),
        zig_tiktoken_free_tokens as *const (),
        zig_tiktoken_encode_single_token as *const (),
        zig_tiktoken_decode_bytes as *const (),
        zig_tiktoken_free_bytes as *const (),
        zig_tiktoken_special_token_id as *const (),
    ];
    // Without black_box, LLVM proves the contents unread and drops the
    // relocations — the archive members are never pulled and nothing is
    // re-exported.
    let keep = std::hint::black_box(fns);
    keep.iter().map(|p| *p as usize).sum()
}

/// Artifact version, NUL-terminated. Lets FFI consumers detect which
/// `libsigil` build they loaded without symbol-versioning machinery.
#[no_mangle]
pub extern "C" fn sigil_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}
