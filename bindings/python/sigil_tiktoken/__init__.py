"""Python bindings for the SIGIL tokenizer."""

from __future__ import annotations

import ctypes
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


class SigilTokenizerError(RuntimeError):
    """Raised when the native tokenizer reports an error."""


@dataclass(frozen=True)
class TokenSpan:
    token_id: int
    start: int
    end: int


class _TokenSpan(ctypes.Structure):
    _fields_ = [
        ("token_id", ctypes.c_uint32),
        ("start", ctypes.c_size_t),
        ("end", ctypes.c_size_t),
    ]


class _TokenBuffer(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(_TokenSpan)),
        ("len", ctypes.c_size_t),
    ]


class _ByteBuffer(ctypes.Structure):
    _fields_ = [
        ("items", ctypes.POINTER(ctypes.c_uint8)),
        ("len", ctypes.c_size_t),
    ]


def _default_library_candidates() -> list[Path]:
    root = Path(__file__).resolve().parents[3]
    candidates = [
        Path(os.environ["SIGIL_TIKTOKEN_LIB"]) if os.environ.get("SIGIL_TIKTOKEN_LIB") else None,
        root / "zig" / "tiktoken" / "zig-out" / "lib" / "libzig_tiktoken.dylib",
        root / "zig" / "tiktoken" / "zig-out" / "lib" / "libzig_tiktoken.so",
        root / "zig" / "tiktoken" / "zig-out" / "lib" / "libzig_tiktoken.dll",
        root / "zig" / "tiktoken" / "zig-out" / "lib" / "zig_tiktoken.dll",
    ]
    return [candidate for candidate in candidates if candidate is not None]


def _load_library(library_path: str | os.PathLike[str] | None = None) -> ctypes.CDLL:
    if library_path is not None:
        return ctypes.CDLL(str(library_path))

    for candidate in _default_library_candidates():
        if candidate.exists():
            return ctypes.CDLL(str(candidate))

    raise SigilTokenizerError(
        "unable to locate libzig_tiktoken; set SIGIL_TIKTOKEN_LIB or build zig/tiktoken as a shared library"
    )


def _check_status(code: int) -> None:
    if code == 0:
        return
    raise SigilTokenizerError(
        {
            1: "unknown encoding",
            2: "invalid utf-8",
            3: "token not found",
            4: "allocation failed",
            5: "invalid input",
        }.get(code, f"native error {code}")
    )


class Tokenizer:
    def __init__(self, name: str, library_path: str | os.PathLike[str] | None = None) -> None:
        self._lib = _load_library(library_path)
        self._configure()
        self._handle = ctypes.c_void_p()
        encoded_name = name.encode("utf-8")
        name_bytes = (ctypes.c_uint8 * len(encoded_name)).from_buffer_copy(encoded_name)
        rc = self._lib.zig_tiktoken_open(name_bytes, len(encoded_name), ctypes.byref(self._handle))
        _check_status(rc)

    @classmethod
    def open(cls, name: str, library_path: str | os.PathLike[str] | None = None) -> "Tokenizer":
        return cls(name, library_path=library_path)

    def close(self) -> None:
        if getattr(self, "_handle", None):
            if self._handle:
                self._lib.zig_tiktoken_close(self._handle)
                self._handle = ctypes.c_void_p()

    def __enter__(self) -> "Tokenizer":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def _configure(self) -> None:
        self._lib.zig_tiktoken_open.argtypes = [
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_void_p),
        ]
        self._lib.zig_tiktoken_open.restype = ctypes.c_int
        self._lib.zig_tiktoken_close.argtypes = [ctypes.c_void_p]
        self._lib.zig_tiktoken_close.restype = None
        self._lib.zig_tiktoken_encode_ordinary.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_TokenBuffer),
        ]
        self._lib.zig_tiktoken_encode_ordinary.restype = ctypes.c_int
        self._lib.zig_tiktoken_encode_piece.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(_TokenBuffer),
        ]
        self._lib.zig_tiktoken_encode_piece.restype = ctypes.c_int
        self._lib.zig_tiktoken_free_tokens.argtypes = [ctypes.c_void_p, ctypes.POINTER(_TokenBuffer)]
        self._lib.zig_tiktoken_free_tokens.restype = None
        self._lib.zig_tiktoken_encode_single_token.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._lib.zig_tiktoken_encode_single_token.restype = ctypes.c_int
        self._lib.zig_tiktoken_decode_bytes.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_size_t,
            ctypes.POINTER(_ByteBuffer),
        ]
        self._lib.zig_tiktoken_decode_bytes.restype = ctypes.c_int
        self._lib.zig_tiktoken_free_bytes.argtypes = [ctypes.c_void_p, ctypes.POINTER(_ByteBuffer)]
        self._lib.zig_tiktoken_free_bytes.restype = None
        self._lib.zig_tiktoken_special_token_id.argtypes = [
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_uint8),
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_uint32),
        ]
        self._lib.zig_tiktoken_special_token_id.restype = ctypes.c_int

    def encode_spans(self, text: str) -> list[TokenSpan]:
        payload = text.encode("utf-8")
        if not payload:
            return []
        buffer = _TokenBuffer()
        rc = self._lib.zig_tiktoken_encode_ordinary(
            self._handle,
            (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload),
            len(payload),
            ctypes.byref(buffer),
        )
        _check_status(rc)
        try:
            if buffer.len == 0 or not buffer.items:
                return []
            return [
                TokenSpan(item.token_id, item.start, item.end)
                for item in ctypes.cast(buffer.items, ctypes.POINTER(_TokenSpan * buffer.len)).contents
            ]
        finally:
            self._lib.zig_tiktoken_free_tokens(self._handle, ctypes.byref(buffer))

    def encode(self, text: str) -> list[int]:
        return [span.token_id for span in self.encode_spans(text)]

    def encode_piece_spans(self, text: str) -> list[TokenSpan]:
        payload = text.encode("utf-8")
        if not payload:
            return []
        buffer = _TokenBuffer()
        rc = self._lib.zig_tiktoken_encode_piece(
            self._handle,
            (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload),
            len(payload),
            ctypes.byref(buffer),
        )
        _check_status(rc)
        try:
            if buffer.len == 0 or not buffer.items:
                return []
            return [
                TokenSpan(item.token_id, item.start, item.end)
                for item in ctypes.cast(buffer.items, ctypes.POINTER(_TokenSpan * buffer.len)).contents
            ]
        finally:
            self._lib.zig_tiktoken_free_tokens(self._handle, ctypes.byref(buffer))

    def encode_single_token(self, token: str | bytes) -> int:
        payload = token.encode("utf-8") if isinstance(token, str) else token
        if not payload:
            raise SigilTokenizerError("empty token")
        out_id = ctypes.c_uint32()
        rc = self._lib.zig_tiktoken_encode_single_token(
            self._handle,
            (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload),
            len(payload),
            ctypes.byref(out_id),
        )
        _check_status(rc)
        return int(out_id.value)

    def decode_bytes(self, token_ids: Sequence[int]) -> bytes:
        if not token_ids:
            return b""
        ids = (ctypes.c_uint32 * len(token_ids))(*[int(item) for item in token_ids])
        buffer = _ByteBuffer()
        rc = self._lib.zig_tiktoken_decode_bytes(
            self._handle,
            ids,
            len(token_ids),
            ctypes.byref(buffer),
        )
        _check_status(rc)
        try:
            return ctypes.string_at(buffer.items, buffer.len)
        finally:
            self._lib.zig_tiktoken_free_bytes(self._handle, ctypes.byref(buffer))

    def decode(self, token_ids: Sequence[int]) -> str:
        return self.decode_bytes(token_ids).decode("utf-8")

    def special_token_id(self, name: str) -> int | None:
        payload = name.encode("utf-8")
        if not payload:
            return None
        out_id = ctypes.c_uint32()
        rc = self._lib.zig_tiktoken_special_token_id(
            self._handle,
            (ctypes.c_uint8 * len(payload)).from_buffer_copy(payload),
            len(payload),
            ctypes.byref(out_id),
        )
        if rc == 3:
            return None
        _check_status(rc)
        return int(out_id.value)


__all__ = ["SigilTokenizerError", "TokenSpan", "Tokenizer"]
