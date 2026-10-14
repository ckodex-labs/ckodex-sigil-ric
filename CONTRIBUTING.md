# Contributing

## The gates a change must pass

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
python3 scripts/check_contracts.py
```

`check_contracts.py` keeps the generated docs in sync with the proof surface. If you add a test file, add its scorecard row or the check fails.

## Structural conventions

- Keep files under 500 lines of code, and functions under 50 lines. Exceeding these limits indicates that decomposition is required.
- Kernel verdicts live in `sigil-core`. Presentation code in `sigil-cli` renders them but never alters or re-evaluates decisions.
- External binaries execute only through pinned adapters like `ExternalOcr`, `ExternalPipe`, or `ExternalTranscript`. The engine records SHA-384 digests as evidence rather than invoking bare system commands.
- Unmodelled behavior degrades to named evidence properties rather than silent pass-throughs.

## Commit flow

Create a feature branch off `develop`, and merge using `--no-ff`.

CI lanes run inside Dagger containers. GitHub Actions functions as a thin invoker. Reproduce any pipeline stage locally:

```sh
dagger run cargo run --manifest-path ci/Cargo.toml -- <stage>
```

Available stages include `all`, `fmt`, `contracts`, `test`, `clippy`, `coverage`, `zig-build`, `bench <preset>`, `bindings`, `conformance`, and `reports`.

The `conformance` lane runs in an isolated container with Rust 1.90 and Zig for ghostty comparison tests. The runtime path never touches this dependency.

For native Zig module execution and containerized Zig builds, the pipeline integrates with [dagger-zig](https://github.com/MChorfa/dagger-zig). This enables containerized compilation and testing of the Zig tokenizer artifacts without requiring local compiler setup.
