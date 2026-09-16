# SIGIL QA Scorecard

This scorecard maps the main attack classes to the layer that blocks them and to the regression tests that prove the behavior.

| Attack class | Blocking layer | Proof tests |
| --- | --- | --- |
| Prompt injection and recursive injection | `sigil-core` scan and verdict engine | `crates/sigil-core/tests/attack_proofs.rs`, `crates/sigil-core/tests/property_defense.rs` |
| Unicode controls, bidi, zero-width, homoglyph abuse, Unicode Tags (U+E0000–E007F) smuggling | `sigil-core` intake + scan | `crates/sigil-core/tests/pipeline.rs`, `crates/sigil-core/tests/attack_proofs.rs`, `crates/sigil-core/tests/property_defense.rs`, `crates/sigil-core/tests/conformance_vectors.rs` |
| DLP exfiltration, secrets, emails, SSNs, credit cards, API keys | `sigil-core` DLP detectors and evidence bounds | `crates/sigil-core/tests/attack_proofs.rs`, `crates/sigil-core/tests/security_hardening.rs` |
| Oversized payloads and invalid byte streams | `sigil-core` intake boundary | `crates/sigil-core/tests/attack_proofs.rs`, `crates/sigil-core/tests/pipeline.rs`, `crates/sigil-core/tests/property_defense.rs` |
| Token smuggling and boundary abuse (contiguous encoded payloads) | `sigil-core` merge/scan rules | `crates/sigil-core/tests/attack_proofs.rs`, `crates/sigil-core/tests/pipeline.rs` |
| Cross-provenance merge erosion (suppressed and unsuppressed crossings) | `sigil-core` merge boundary findings | `crates/sigil-core/tests/conformance_vectors.rs` |
| Receipt tampering and unsigned-admission substitution | `sigil-core` receipt signing (ECDSA P-384) | `crates/sigil-core/tests/conformance_vectors.rs` |
| Tokenizer firewall and reserved token smuggling | `sigil-core` tokenizer boundary | `crates/sigil-core/tests/firewall.rs` |
| Representation-integrity conformance (receipts, evidence modes, trust composition, raw-range traceability) | `sigil-core` RIC conformance vectors | `crates/sigil-core/tests/conformance_vectors.rs` |
| Contract boundary invariants and serialization | `sigil-core` / `sigil-s` public contract surface | `crates/sigil-core/tests/contracts.rs` |
| Batch actor consistency and thread safety | `sigil-core` parallel tokenizer actor | `crates/sigil-core/tests/batch_parallel.rs` |
| Cross-tool contamination and schema drift | `sigil-mcp` gate | `crates/sigil-mcp/tests/attack_proofs.rs`, `crates/sigil-mcp/tests/gate.rs` |
| Cross-modal payloads and hidden commands | `sigil-multimodal` composition | `crates/sigil-multimodal/tests/attack_proofs.rs`, `crates/sigil-multimodal/tests/cross_modal.rs` |
| Unsafe fusion boundaries (cross-trust, cross-role, instruction formation, derived-authority escalation) | `sigil-multimodal` fusion-boundary auditor | `crates/sigil-multimodal/src/tests.rs`, `crates/sigil-multimodal/tests/cross_modal.rs` |
| Perception-channel authority fabrication (adapter claiming first-party provenance) | `sigil-multimodal` kernel mapping (type-level RIC-R-7) | `crates/sigil-multimodal/src/perception.rs` unit tests |
| Image-borne instruction injection (OCR channel) | `sigil-perception` image adapter + `sigil-multimodal` kernel scan | `crates/sigil-perception/src/lib.rs` unit tests, `crates/sigil-multimodal/tests/cross_modal.rs` |
| Video-borne instruction injection (painted frames, spoken audio track) | `sigil-perception` video adapter stream extraction (pinned ffmpeg → `AudioAdapter` + per-frame OCR channels) | `crates/sigil-perception/tests/stream_extract.rs`, `crates/sigil-perception/src/video/mod.rs` unit tests |
| Code-borne instruction injection (comments, docstrings, string literals) | `sigil-perception` code adapter lexical surface split | `crates/sigil-perception/src/code.rs` unit tests |
| Camouflaged injection segments (encoded/obfuscated payloads inside prose) | `sigil-core` multiscale perplexity-anomaly detector (`scan.perplexity`, scorer-trait boundary, opt-in) | `crates/sigil-core/src/perplexity/tests.rs`, `crates/sigil-core/src/scan/tests.rs` |
| Terminal-escape injection (clipboard hijack OSC 52, hyperlink smuggling OSC 8, title/notification spoofing, ConEmu automation, rxvt/iTerm2/kitty extension channels, CSI/DCS output forgery, SGR-conceal invisible text, scrollback erase, repaint-overwrite patterns) | `sigil-core` terminal-escape detector (`scan.terminal_escapes`, scanner-trait boundary, opt-in) + `sigil-vt` built-in scanner (owned OSC+CSI tables, bounded virtual-window `repaint_overwrite` detection — per-cell overwrite + per-row pre-erase snapshot divergence, `conformance` feature cross-checks vs `libghostty-vt`) | `crates/sigil-core/src/terminal/tests.rs`, `crates/sigil-core/src/scan/tests.rs`, `crates/sigil-vt/src/tests.rs` |
| Behavioral drift and SHIELD escalation | `sigil-probe` health engine | `crates/sigil-probe/tests/attack_proofs.rs`, `crates/sigil-probe/tests/drift.rs` |
| Sentinel composition not weakening SIGIL denies | `sigil-s` composition layer | `crates/sigil-s/tests/composition.rs` |
| Zig tokenizer parity and ABI stability | `zig/tiktoken` backend plus Rust FFI | `crates/sigil-core/tests/tiktoken_parity.rs` |
| Python binding encode/decode parity | Python `ctypes` wrapper | `bindings/python/benchmark.py`, CI binding smoke job |
| Go binding encode/decode parity | Go `cgo` wrapper | `bindings/go/cmd/sigil-bench`, CI binding smoke job |
| Throughput regression and batch consistency | CLI benchmark harness | `bench/baselines/*`, `crates/sigil-cli/src/cli/benchmark.rs`, CI benchmark job |
| CLI dispatch, keygen → signed scan → verify-receipt → attest → verify-attestation chains, keyless fail-closed | `sigil-cli` binary surface | `crates/sigil-cli/tests/cli_integration.rs` |
| Presentation integrity — human mode carries kernel verdicts unchanged, invisible codepoints rendered visibly, JSON contract preserved under `auto`/`json` | `sigil-cli` output modes | `crates/sigil-cli/src/cli/tests_human.rs`, `crates/sigil-cli/tests/cli_integration.rs` |
| Paper-cut regressions — verdict exit codes (`--fail-on` deny/flag/never), piped + `--input -` stdin, cross-modality flag rejection, decode-error hints, help text, empty-stdin refusal | `sigil-cli` process contract | `crates/sigil-cli/tests/cli_paper_cuts.rs` |

## QA gates

- `cargo test --workspace`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `zig build-lib` verification for both static and shared tokenizer artifacts
- benchmark regression checks for `small`, `medium`, and `stress`
- binding smoke checks for Python and Go

## Status

The repo is currently organized to fail closed on the classes above. Any new attack surface should add a corresponding row here and a regression test in the owning crate.

CI also renders this scorecard into a deterministic artifact on every run so coverage drift is visible without manually rebuilding the report.
