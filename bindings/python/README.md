# Python binding

The Python binding uses `ctypes` and the `sigil_core` Zig ABI.

## Build the native library

```bash
cd zig/tiktoken
zig build-lib -dynamic -O ReleaseSafe -fPIC -fcompiler-rt -fno-stack-check -femit-bin=zig-out/lib/libzig_tiktoken.dylib src/lib.zig
```

On Linux the file will usually be `libzig_tiktoken.so`; on Windows, `zig_tiktoken.dll`.

## Usage

```python
from sigil_tiktoken import Tokenizer

with Tokenizer.open("cl100k_base") as tok:
    ids = tok.encode("hello world")
    text = tok.decode(ids)
```

Set `SIGIL_TIKTOKEN_LIB` to point at a custom library path if the default search path is not correct.
