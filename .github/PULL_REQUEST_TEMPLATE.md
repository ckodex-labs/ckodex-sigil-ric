## What and why

<!-- What changes, and which problem or issue it addresses. -->

Closes #

## RIC rules and vectors

<!-- e.g. RIC-R-8, CV-RIC-032. "none" if the change touches no rule. -->

## How it was verified

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace` (count: )
- [ ] `python3 scripts/check_contracts.py`
- [ ] For a security rule: the rule was broken on purpose and a test caught it

## Compatibility

- [ ] No change to a signed message, serialized form or CLI flag, or the
      change is recorded in `CHANGELOG.md` (and an ADR if it is normative)

## Risks and failure modes

<!-- What could go wrong, and what happens if it does (fail closed?). -->
