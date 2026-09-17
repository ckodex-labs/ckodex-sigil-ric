# Go binding

This package wraps the SIGIL tokenizer C ABI through `cgo`.

## Prerequisite

Build the shared Zig library first:

```bash
cd zig/tiktoken
zig build-lib -dynamic -O ReleaseSafe -fPIC -fcompiler-rt -fno-stack-check -femit-bin=zig-out/lib/libzig_tiktoken.so src/lib.zig
```

On macOS the output is typically `libzig_tiktoken.dylib`.

## Example

```go
tok, err := tiktoken.Open("cl100k_base")
if err != nil {
    log.Fatal(err)
}
defer tok.Close()

ids, err := tok.Encode("hello world")
```
