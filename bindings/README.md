# Language Bindings

The tokenizer core is exposed through a small C ABI in `crates/sigil-core/src/tokenizer_ffi.rs`.

Available bindings:

- `bindings/c/sigil_tiktoken.h` - stable C header for consumers in C-compatible languages
- `bindings/python/sigil_tiktoken` - Python `ctypes` wrapper
- `bindings/go` - Go `cgo` wrapper

Build the Zig library as a shared object before using the runtime bindings:

```bash
cd zig/tiktoken
zig build-lib -dynamic -O ReleaseSafe -fPIC -fcompiler-rt -fno-stack-check -femit-bin=zig-out/lib/libzig_tiktoken.so src/lib.zig
```

On macOS, Zig will typically emit a `.dylib`; on Windows, a `.dll`.

The Go benchmark command also links a static archive:

```bash
zig build-lib -O ReleaseSafe -fPIC -fcompiler-rt -fno-stack-check -femit-bin=zig-out/lib/libzig_tiktoken.a src/lib.zig
```
