# REPO-MODEL — ckodex-safir-tokenizer

```
repo:      ckodex-safir-tokenizer (SIGIL tokenizer workspace)
commit:    96a40c9 (develop, initial commit)
date:      2026-09-13
adapters:  [ccc (177 files / 1263 chunks semantic index), graft (1392 nodes / 1085 edges call graph)]
coverage:  ~35% of 103 .rs files read or traced; all 9 crates' public surfaces mapped;
           4 flows traced end-to-end via graft; 8 invariants machine-checked
```

## entry_points

| Entry | Path | Notes |
|---|---|---|
| `sigil` CLI binary | `crates/sigil-cli/src/main.rs:3` → `sigil_cli::run()` → `cli/run.rs:run()` | clap derive dispatch over `Commands` |
| `SigilSidecar` library facade | `crates/sigil-server/src/lib.rs:41` | **lib only — no bin, no transport** |
| Go binding + `sigil-bench` | `bindings/go/tiktoken/tiktoken.go`, `bindings/go/cmd/sigil-bench/main.go` | cgo over Zig tokenizer |
| Python binding `sigil_tiktoken` | `bindings/python/sigil_tiktoken/__init__.py:1` | **ctypes, not PyO3** |
| C header | `bindings/c/sigil_tiktoken.h` | header only; no `libsigil` cdylib target |
| Zig tokenizer FFI | `zig/tiktoken/src/lib.zig` via `crates/sigil-core/build.rs` + `tokenizer_ffi.rs` | `zig_tiktoken_open/encode_piece/free_tokens` |
| Contract checker | `scripts/check_contracts.py` | pins public API names per file |

## module_graph

Workspace `Cargo.toml` members = 9 crates, resolver 2, rust-version 1.78.

```
sigil-core (kernel — zero sigil deps, zero network deps)
  ├── sigil-mcp        → core
  ├── sigil-probe      → core
  ├── sigil-multimodal → core
  ├── sigil-s          → core
  ├── sigil-sigstore   → core
  ├── sigil-perception → core + multimodal
  ├── sigil-server     → core, mcp, probe, multimodal, s   (NOT perception, NOT sigstore)
  └── sigil-cli        → all of the above                  (sole consumer of perception + sigstore)
```

Direction rule: leaf crates may depend only on `sigil-core` (+ `sigil-multimodal`
for perception). No crate depends on `sigil-cli` or `sigil-server`.

## flows

### F1 — text admission (kernel pipeline)
`cli/run.rs:run()` → `Sigil::process_text_segments` `engine.rs:48`
→ `intake_text_segment` `intake.rs:39` (grapheme cluster, invisible-strip)
→ `apply_provenance` `taint.rs:5` (restrictive trust composition)
→ `process_graphemes` `engine.rs:85`
→ `run_scan` `scan/run.rs:9` → detectors: `detect_injection` `detectors.rs:8`,
`detect_unicode_abuse` :67, `detect_entropy` :113, `detect_smuggling` :166,
`detect_tokenizer_firewall` :199, `detect_dlp` `dlp.rs:8`,
`detect_rare_patterns` `lfdd.rs:66`
→ `security_aware_merge` `merge.rs:29` (cross-boundary findings)
→ `emit_output` `emit.rs:12` → `decide_verdict` `emit.rs:83`
→ `build_evidence` `evidence.rs:8` → `receipt_message` `signing.rs:68`
→ optional `ReceiptSigner::sign`.

### F2 — MCP response gate
`McpSession::inspect_response` `sigil-mcp/src/session.rs:43`
→ `validate_schema` `helpers.rs:80` → `truncate_output` `helpers.rs:7`
→ kernel `process_text_segments` (provenance = `McpTool`)
→ `compose_verdict` `helpers.rs:23` → `combine_taint` `session.rs:142`
→ `update_history` `session.rs:127` → `McpInspection`.

### F3 — multimodal fusion
`MultimodalEngine::analyze` `sigil-multimodal/src/engine.rs:39`
→ per-modality `detect_{vision,audio,video,code,document}` `detect.rs`
→ kernel `process_text_segments` per channel content
→ `audit_fusion` `fusion.rs:6` (fusion-boundary audit)
→ `compose_modality_verdict` / `compose_cross_modal_verdict` /
`fold_verdicts` / `authority_ceiling` `verdict.rs`
→ `MultimodalAssessment`. Adapters feed channels via
`channels_to_modal_inputs` `perception.rs` — verdicts stay in the kernel side.

### F4 — Sigstore bundle verification
`verify_bundle_with_trust` `sigil-sigstore/src/trust/verify.rs:7`
→ `verify_bundle` `bundle_ops.rs:94` (signature→leaf-cert binding)
→ `parse_cert` `fetch.rs:6` → `validate_chain` `chain.rs:8`
→ `check_san_identity` `chain.rs:85` → `check_validity_at` `chain.rs:122`
→ `verify_rekor_set` `rekor.rs:9` → `verify_inclusion_proof` `rekor.rs:45`
(RFC 6962 domain-separated hashing) → `verify_rekor_entry_binding`
`rekor.rs:122` (canonicalizedBody vs artifact digest + signature —
GHSA-whqx-f9j3-ch6m class fix D-15).

### F5 — error propagation
Zig FFI `TokenizerError` → `sigil_core::error::Result` (thiserror typed)
→ `anyhow::Result` at `cli/run.rs` boundary → `main.rs` exits 1.
Library crates never use `anyhow`; CLI never exposes typed errors to callers.

## patterns

- Façade `lib.rs`/`mod.rs` re-exports only; implementation in sibling modules;
  cross-module internals are `pub(crate)`, never `pub`.
- Tests live in module-local `tests.rs` (`#[cfg(test)]`) plus `tests/` dirs for
  attack proofs; no `#[cfg(test)]` blocks inside logic files.
- Evidence path is uniform: `ScanReport` → `build_evidence` → optional
  `ReceiptSigner` trait object (`sigil-core/src/signing.rs`) — Sigstore signer
  is one implementation, not a special case.
- Perception adapters produce `ExtractedChannel`s + `derived_from` lineage;
  they never construct `Verdict`.

## invariants

| ID | Claim | Check | Status |
|---|---|---|---|
| INV-M1 | zero `.unwrap()` outside tests | `! grep -rn '\.unwrap()' crates/*/src --include='*.rs' \| grep -vE 'tests?\.rs\|tests?_'` | verified |
| INV-M2 | every .rs file ≤ 500 LOC | `find crates -name '*.rs' \| xargs wc -l \| awk '$1>500'` empty | verified |
| INV-M3 | kernel imports no network/async deps | `! grep -E 'reqwest\|ureq\|tokio\|hyper' crates/sigil-core/Cargo.toml` | verified |
| INV-M4 | perception adapters emit no Verdict | `! grep -rn 'Verdict::' crates/sigil-perception/src/` | verified |
| INV-M5 | Critical severity → Deny verdict | `grep -A2 'Severity::Critical' crates/sigil-core/src/emit.rs` shows `Verdict::Deny` | verified |
| INV-M6 | nothing depends on cli/server crates | `grep -l 'sigil-cli\|sigil-server' crates/*/Cargo.toml` = none | verified |
| INV-M7 | contract docs ↔ scorecard sync | `python3 scripts/check_contracts.py` exits 0 | verified |
| INV-M8 | extracted channels carry `derived_from` | `grep -rn derived_from crates/sigil-multimodal/src/perception.rs` non-empty | verified |
| INV-M9 | same input+policy → same findings order (determinism) | `manual` — `detect_rare_patterns` sorts by `byte_range` + dedups before return (`lfdd.rs:100`) | manual |

## discrepancies

| ID | Claimed | Actual | Evidence | Severity | Disposition |
|---|---|---|---|---|---|
| D-A | `sigil-server` = "gRPC/HTTP microservice + MCP proxy" | lib-only `SigilSidecar` facade, no bin, no transport deps | `SIGIL-SPEC.md:346` vs `crates/sigil-server/src/lib.rs:41`; `Cargo.toml` has no `[[bin]]` or tonic/axum | medium | fix-docs (mark transport planned) |
| D-B | `pysigil` = "Python bindings (PyO3)" | ctypes over the Zig shared library | `SIGIL-SPEC.md:345` vs `bindings/python/sigil_tiktoken/__init__.py` (`import ctypes`) | low | fix-docs |
| D-C | `sigil.wasm` deliverable | no wasm target, feature, or build config anywhere | `SIGIL-SPEC.md:344` vs `grep -rn wasm Cargo.toml crates/*/Cargo.toml` empty | low | fix-docs (mark planned) |
| D-D | `libsigil` C ABI shared library | only `bindings/c/sigil_tiktoken.h` (header for the Zig tokenizer); no cdylib `crate-type` | `SIGIL-SPEC.md:343` vs `bindings/c/` listing | low | fix-docs (mark planned) |
| D-E | README crate list covers workspace | omits `sigil-perception` and `sigil-sigstore` | `README.md` list vs `Cargo.toml` members (9 crates) | low | fix-docs |
| D-F | `verify_bundle_with_trust` documented 6-step verification | doc comment orphaned in old `trust.rs`, lost in split — `trust/verify.rs:7` is undocumented | `crates/sigil-sigstore/src/trust/verify.rs:1-7` | low | fix-code (restore doc) |
| D-G | `.gitignore` covers ccc index | `.gitignore` has `.ccc/`; tool actually writes `.cocoindex_code/` (14MB sqlite DBs) | `.gitignore` vs `ls .cocoindex_code/` | low | fix-code |
| D-H | TRAJECTORY references live paths | refs `audio.rs`, `spectral.rs`, `trust.rs`, `vocab.rs` — all replaced by module dirs in the split | `docs/TRAJECTORY.md:105-111` | low | fix-docs |

## do_not_touch

- `zig/tiktoken/` + `crates/sigil-core/src/tokenizer_ffi.rs` + `build.rs` —
  unsafe C ABI + Zig build coupling; changes need both sides coordinated.
- `crates/sigil-sigstore/src/trust/rekor.rs` — RFC 6962 domain-separated
  hashing (0x00 leaf / 0x01 node prefixes); a silent change breaks proof
  verification against the real Rekor log.
- `crates/sigil-core/src/scan/helpers.rs` — `luhn_valid`, `looks_like_base64`
  thresholds are tuned security gates, not utilities.
- `crates/sigil-core/src/merge.rs` — merge-boundary suppression is a security
  invariant (INV-006 family); reordering changes verdicts.
- `bench/` corpora + manifests + baselines — pin regression thresholds;
  editing a baseline changes the meaning of `BENCHMARK_MAX_REGRESSION_PCT`.

## open_questions

- Is `sigil-server` transport (gRPC/HTTP/MCP proxy) planned or descoped?
  Spec §4 table and §module map disagree (346 vs 906).
- TUF trust root is an embedded snapshot (`tuf.rs`); is online refresh wired
  or intentionally static?
- Coverage target ≥80% has no configured tool (no tarpaulin/llvm-cov config
  found) — how is it measured?
- Spec: "every MCP evidence record MUST eventually be persisted" — where does
  `McpEvidenceRecord` persistence land? Currently in-memory session history.
- Python binding is ctypes; is PyO3 a planned migration or a stale spec claim?
