# Binding Benchmarks

These benchmarks exercise the language bindings directly on the same tokenizer corpus.

## Python

```bash
export SIGIL_TIKTOKEN_LIB=/absolute/path/to/libzig_tiktoken.dylib
python3 bindings/python/benchmark.py --json
```

## Go

```bash
zig build-lib -O ReleaseSafe -fPIC -fcompiler-rt -fno-stack-check -femit-bin=zig/tiktoken/zig-out/lib/libzig_tiktoken.a zig/tiktoken/src/lib.zig
cd bindings/go
go run ./cmd/sigil-bench --json
```

Both commands default to the checked-in stress corpus in `bench/corpora/stress.json`.
