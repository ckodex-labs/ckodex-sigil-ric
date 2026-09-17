# Contributing

## The gates a change must pass

```sh
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all
python3 scripts/check_contracts.py
```

`check_contracts.py` keeps the generated docs (QA scorecard, launch
checklist) in sync with the proof surface — if you add a test file, add
its scorecard row or the check fails.

## Structural conventions

- 500 LOC per file, ~50 LOC per function — exceeding is a decomposition
  signal, not a threshold to negotiate.
- Kernel verdicts (`Verdict`, flag/deny reasons) live in `sigil-core`;
  presentation code in `sigil-cli` renders them but never re-decides.
- External binaries are only invoked through pinned adapters
  (`ExternalOcr`/`ExternalPipe`/`ExternalTranscript`) — SHA-384 digest
  recorded as evidence, never a bare `Command::new`.
- Unmodelled behaviour degrades to named evidence properties
  (`*_capped`, `* = failed: ...`), never silence.

## Commit flow

Feature branch off `develop`, merge with `--no-ff`. CI lanes run inside
Dagger via the `ci/` driver crate — GitHub Actions is a thin invoker.
Reproduce any lane locally:

```
dagger run cargo run --manifest-path ci/Cargo.toml -- <stage>
```

Stages: `all` (contracts+fmt+clippy+test+zig), `fmt`, `contracts`,
`test`, `clippy`, `coverage`, `zig-build`, `bench <preset>`,
`bindings`, `conformance`, `reports`. The vt-conformance lane needs
Rust 1.90 + Zig for the libghostty-vt comparison harness — the runtime
path never touches it.
