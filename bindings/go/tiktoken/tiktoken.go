package tiktoken

/*
#cgo CFLAGS: -I${SRCDIR}/../../c
#cgo darwin LDFLAGS: ${SRCDIR}/../../../zig/tiktoken/zig-out/lib/libzig_tiktoken.a
#cgo linux LDFLAGS: ${SRCDIR}/../../../zig/tiktoken/zig-out/lib/libzig_tiktoken.a
#cgo windows LDFLAGS: ${SRCDIR}/../../../zig/tiktoken/zig-out/lib/libzig_tiktoken.a
#include "sigil_tiktoken.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

type TokenSpan struct {
	TokenID uint32
	Start    int
	End      int
}

type Tokenizer struct {
	handle *C.zig_tiktoken_handle
}

func bytesPtr(payload []byte) *C.uint8_t {
	if len(payload) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&payload[0]))
}

func idsPtr(ids []uint32) *C.uint32_t {
	if len(ids) == 0 {
		return nil
	}
	return (*C.uint32_t)(unsafe.Pointer(&ids[0]))
}

func Open(name string) (*Tokenizer, error) {
	cName := []byte(name)
	if len(cName) == 0 {
		return nil, errors.New("empty encoding name")
	}
	var handle *C.zig_tiktoken_handle
	rc := C.zig_tiktoken_open(bytesPtr(cName), C.size_t(len(cName)), &handle)
	if rc != C.ZIG_TIKTOKEN_OK {
		return nil, statusError(int(rc))
	}
	return &Tokenizer{handle: handle}, nil
}

func (t *Tokenizer) Close() {
	if t != nil && t.handle != nil {
		C.zig_tiktoken_close(t.handle)
		t.handle = nil
	}
}

func (t *Tokenizer) Encode(text string) ([]uint32, error) {
	spans, err := t.EncodeSpans(text)
	if err != nil {
		return nil, err
	}
	out := make([]uint32, len(spans))
	for i, span := range spans {
		out[i] = span.TokenID
	}
	return out, nil
}

func (t *Tokenizer) EncodeSpans(text string) ([]TokenSpan, error) {
	cText := []byte(text)
	if len(cText) == 0 {
		return []TokenSpan{}, nil
	}
	var buffer C.zig_token_buffer
	rc := C.zig_tiktoken_encode_ordinary(
		t.handle,
		bytesPtr(cText),
		C.size_t(len(cText)),
		&buffer,
	)
	if rc != C.ZIG_TIKTOKEN_OK {
		return nil, statusError(int(rc))
	}
	defer C.zig_tiktoken_free_tokens(t.handle, &buffer)

	if buffer.items == nil || buffer.len == 0 {
		return []TokenSpan{}, nil
	}
	raw := unsafe.Slice(buffer.items, buffer.len)
	out := make([]TokenSpan, len(raw))
	for i, span := range raw {
		out[i] = TokenSpan{
			TokenID: uint32(span.token_id),
			Start:   int(span.start),
			End:     int(span.end),
		}
	}
	return out, nil
}

func (t *Tokenizer) EncodeSingleToken(token string) (uint32, error) {
	cToken := []byte(token)
	if len(cToken) == 0 {
		return 0, errors.New("empty token")
	}
	var out C.uint32_t
	rc := C.zig_tiktoken_encode_single_token(
		t.handle,
		bytesPtr(cToken),
		C.size_t(len(cToken)),
		&out,
	)
	if rc != C.ZIG_TIKTOKEN_OK {
		return 0, statusError(int(rc))
	}
	return uint32(out), nil
}

func (t *Tokenizer) DecodeBytes(ids []uint32) ([]byte, error) {
	if len(ids) == 0 {
		return []byte{}, nil
	}
	cIDs := make([]uint32, len(ids))
	for i, id := range ids {
		cIDs[i] = id
	}
	var buffer C.zig_byte_buffer
	rc := C.zig_tiktoken_decode_bytes(
		t.handle,
		idsPtr(cIDs),
		C.size_t(len(cIDs)),
		&buffer,
	)
	if rc != C.ZIG_TIKTOKEN_OK {
		return nil, statusError(int(rc))
	}
	defer C.zig_tiktoken_free_bytes(t.handle, &buffer)

	return C.GoBytes(unsafe.Pointer(buffer.items), C.int(buffer.len)), nil
}

func (t *Tokenizer) Decode(ids []uint32) (string, error) {
	bytes, err := t.DecodeBytes(ids)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func (t *Tokenizer) SpecialTokenID(name string) (uint32, bool, error) {
	cName := []byte(name)
	if len(cName) == 0 {
		return 0, false, nil
	}
	var out C.uint32_t
	rc := C.zig_tiktoken_special_token_id(
		t.handle,
		bytesPtr(cName),
		C.size_t(len(cName)),
		&out,
	)
	if rc == C.ZIG_TIKTOKEN_TOKEN_NOT_FOUND {
		return 0, false, nil
	}
	if rc != C.ZIG_TIKTOKEN_OK {
		return 0, false, statusError(int(rc))
	}
	return uint32(out), true, nil
}

func statusError(code int) error {
	msg, ok := map[int]string{
		1: "unknown encoding",
		2: "invalid utf-8",
		3: "token not found",
		4: "allocation failed",
		5: "invalid input",
	}[code]
	if !ok {
		msg = fmt.Sprintf("native error %d", code)
	}
	return errors.New(msg)
}

func (t *Tokenizer) MustEncode(text string) []uint32 {
	out, err := t.Encode(text)
	if err != nil {
		panic(err)
	}
	return out
}

func (t *Tokenizer) MustDecode(ids []uint32) string {
	out, err := t.Decode(ids)
	if err != nil {
		panic(err)
	}
	return out
}

func (t *Tokenizer) String() string {
	return fmt.Sprintf("Tokenizer(handle=%p)", t.handle)
}
