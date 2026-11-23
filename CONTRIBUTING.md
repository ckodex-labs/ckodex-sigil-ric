# Contributing to SIGIL

Thank you for helping. SIGIL is a security control, so changes are judged
first on whether they keep its guarantees, then on everything else.

## Before you start

- Open an issue for anything beyond a small fix, so the approach is agreed
  before code is written.
- A change to a normative rule (`docs/RIC-SPEC.md`), a signed message, or a
  serialized form needs an ADR (`docs/ADR-*.md`) and a version note.
- Report vulnerabilities privately (`SECURITY.md`), never in an issue.

## Development setup

- Rust 1.88 or later (edition 2024) and Zig 0.15.2 (`sigil-core` builds the
  Zig tokenizer).
- Tesseract and ffmpeg: the perception tests run them for real and fail,
  rather than skip, when they are missing.
- The Qwen2-VL interpreter tests need third-party files SIGIL does not
  redistribute: `scripts/reference/fetch_qwen2vl_assets.sh`.

## The gates

Every pull request must pass the same lane CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
python3 scripts/check_contracts.py
# or all of them, in the CI image:
dagger run cargo run --manifest-path ci/Cargo.toml -- all
```

Enforced by the gates: functions of 50 lines or fewer (`clippy.toml`), no
`unsafe` outside the two documented FFI boundaries, and line coverage of
80 % or more. Checked in review: files under 500 lines, and no `unwrap` or
`expect` outside tests.

## Tests

- New behaviour comes with a test that fails without it. For a security rule,
  break the rule on purpose once and confirm a test catches it.
- No mocks of the thing under test, and no test that compares SIGIL's output
  with a value SIGIL produced itself: reference values come from the real
  reference implementation (`scripts/reference/`, Python only there).
- Conformance vectors are named `cv_ric_NNN_...` and listed in
  `docs/RIC-CONTRACT.md`; `scripts/check_contracts.py` keeps the two in sync.

## Commits and pull requests

- Conventional commits (`feat(scope): ...`, `fix(...)`, `docs(...)`,
  `refactor(...)`, `ci: ...`). The body says why, and how it was verified.
- One logical change per commit. Signed commits are preferred.
- Fill in the pull request template; link the issue and the RIC rule or
  vector the change touches.

## Licence of contributions

Contributions are accepted under the terms in `LICENSE`: Apache-2.0, and
dual-licensed as described there.
