#ifndef SIGIL_TIKTOKEN_H
#define SIGIL_TIKTOKEN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct zig_tiktoken_handle zig_tiktoken_handle;

typedef struct zig_token_span {
    uint32_t token_id;
    size_t start;
    size_t end;
} zig_token_span;

typedef struct zig_token_buffer {
    zig_token_span *items;
    size_t len;
} zig_token_buffer;

typedef struct zig_byte_buffer {
    uint8_t *items;
    size_t len;
} zig_byte_buffer;

enum zig_tiktoken_status {
    ZIG_TIKTOKEN_OK = 0,
    ZIG_TIKTOKEN_UNKNOWN_ENCODING = 1,
    ZIG_TIKTOKEN_INVALID_UTF8 = 2,
    ZIG_TIKTOKEN_TOKEN_NOT_FOUND = 3,
    ZIG_TIKTOKEN_ALLOC_FAILED = 4,
    ZIG_TIKTOKEN_INVALID_INPUT = 5,
};

int zig_tiktoken_open(const uint8_t *name_ptr, size_t name_len, zig_tiktoken_handle **out_handle);
void zig_tiktoken_close(zig_tiktoken_handle *handle);

int zig_tiktoken_encode_ordinary(
    zig_tiktoken_handle *handle,
    const uint8_t *text_ptr,
    size_t text_len,
    zig_token_buffer *out
);

int zig_tiktoken_encode_piece(
    zig_tiktoken_handle *handle,
    const uint8_t *text_ptr,
    size_t text_len,
    zig_token_buffer *out
);

void zig_tiktoken_free_tokens(zig_tiktoken_handle *handle, zig_token_buffer *buffer);

int zig_tiktoken_encode_single_token(
    zig_tiktoken_handle *handle,
    const uint8_t *text_ptr,
    size_t text_len,
    uint32_t *out_id
);

int zig_tiktoken_decode_bytes(
    zig_tiktoken_handle *handle,
    const uint32_t *ids_ptr,
    size_t ids_len,
    zig_byte_buffer *out
);

void zig_tiktoken_free_bytes(zig_tiktoken_handle *handle, zig_byte_buffer *buffer);

int zig_tiktoken_special_token_id(
    zig_tiktoken_handle *handle,
    const uint8_t *name_ptr,
    size_t name_len,
    uint32_t *out_id
);

/* `libsigil` artifact additions (crates/sigil-ffi only — not present in
 * the raw zig/tiktoken build). Callers must tolerate their absence when
 * linking the Zig-produced library directly. */

/* NUL-terminated artifact version string ("x.y.z"). */
const char *sigil_version(void);

/* Internal export-table pin — keeps the zig_tiktoken_* symbols reachable
 * in the cdylib. Not part of the consumer ABI. */
size_t sigil_ffi_pin(void);

#ifdef __cplusplus
}
#endif

#endif
