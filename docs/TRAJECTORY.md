# SIGIL Engineering Trajectory

**Maintained:** yes — update this document at the end of every work increment.
**Last consolidated:** 2026-09-11
**Verification at time of writing:** `cargo test --workspace` → **85 passed, 0 failed** (fresh run, this session).

This is the canonical trajectory of the RIC/SIGIL representation-integrity work in
this repository. It consolidates the session arc, the current verified state, and
the open work queue. Companion documents are indexed in the map at the end.

---

## 1. Arc of the work

The session began from a design conversation (RIC — Representation Integrity
Contract; SIGIL as its enforcement engine; multimodal fusion as the next
primitive) and proceeded through five increments:

| # | Increment | Outcome | Proof |
|---|---|---|---|
| 0 | Recon + critique + gap analysis of the RIC/SIGIL proposal vs. repo | 6 defects found (D-1..D-6), 16 gap items classified, 3 conversation claims corrected | [RIC-DELTA-ANALYSIS.md](./RIC-DELTA-ANALYSIS.md) |
| 1 | RIC delta implementation | Trust composition fixed, Unicode Tags detected, strip policy real, merge-boundary findings, SHA-256 receipts, fusion-boundary auditor + authority ceilings | 58→73 tests green |
| 2 | Conformance vectors materialized | CV-RIC-001..006 executable; caught D-7 (mid-character byte ranges) that unit tests missed | `tests/conformance_vectors.rs` |
| 3 | CLI fusion audit un-starved (D-8) | `--system` flag + per-modality provenance; full fusion chain verified through the binary | smoke matrix |
| 4 | Always-on evidence mode (DEV-1) | `emit.evidence_mode = non-allow \| always`; clean admissions attestable | CV-RIC-007 + binary smoke |
| 5 | Base64 heuristic retuned (D-9) | Contiguity gate replaces vacuous shape check; entropy-gate design evaluated and **rejected** by the attack_proofs regression | 3 scan tests + regression |
| 6 | Receipt signing (DEV-3) | `ReceiptSigner` port + **ECDSA P-384** adapter (mandated), RFC 6979 deterministic nonces | CV-RIC-008 |
| 7 | Communication package | 11-slide deck + LinkedIn post rebuilt locally | `comms/` |

## 2. Current verified state

**Workspace:** 9 crates, builds clean, **164 tests / 0 failures** (2026-09-11).
**Dependencies added this trajectory:** `sha2 0.10.9`, `p384 0.13.1`, `hound 3.5.1`, `sigstore-trust-root 0.11`, `realfft 3.5.0`, `rustfft 6.4.1`, `mp4parse 0.17.0`, `lopdf 0.36.0` (all long-published). `ed25519-dalek` added then removed on the P-384 mandate.

**Maintenance log:**
- 2026-09-11 (consolidation sweep): D-4 actually resolved (evidence id FNV-1a → SHA-256; earlier note claiming supersession was an overclaim — the bundle id was still FNV). Spec §9 project structure aligned with the real workspace (removed phantom `sigil-ffi`/`sigil-wasm`/`sigil-bench`/`sigil.toml` entries, fixed conformance-vector location, added planned-crates note). CV range references corrected to 001..008 in spec header, formal/README, and analysis doc.
- 2026-09-11 (residue audit): spec §4.1 CLI examples rewritten against the real binary
  (`sigil-cli`, JSON output, actual subcommands — removed phantom `dlp` subcommand and
  `--emit` flag); spec §4.2 Rust API example corrected (`sigil_core` crate name,
  `process_text_segments` instead of nonexistent `tokenize_with_provenance`) and verified
  to compile and run verbatim via a temporary test. CONTRACTS.md canonical-type list
  extended (receipt, signature, signer, fusion, authority ceiling) and enforced by
  `scripts/check_contracts.py`; QA-SCORECARD rows added for merge erosion, receipt
  tampering, fusion boundaries, and RIC conformance. All three documented gates now
  verified green: 85 tests / 0 failures, clippy `-D warnings` clean (3 warnings fixed:
  needless borrow, derivable impl, useless format), contract sync in sync.
- 2026-09-11 (RIC introduction): `docs/RIC-SPEC.md` minted as the versioned standalone
  specification (RIC v0.1.0 DRAFT) — system-agnostic rules, per-boundary conformance
  definitions (model-input implemented; tool/retrieval/A2A/human-approval specified),
  receipt schema v1, authority model, standards crosswalk, implementation-status matrix,
  versioning policy. New `sigil-cli verify-receipt` subcommand: third parties verify an
  admission receipt against a pinned ECDSA P-384 key without producer code — accepts a
  bare receipt or a full SigilOutput envelope; verified end-to-end through the binary
  (signed → valid, tampered token_count → Mismatch, unsigned → explicit error). Three
  CLI unit tests cover envelope/tamper/unsigned paths. Comms refreshed: deck title and
  demo slides now state implemented status (RIC v0.1 · SIGIL v0.3 · 88 tests · signed
  receipts); LinkedIn post gained a status paragraph. Gates: 88/0, clippy -D warnings
  clean, contract sync in sync.
- 2026-09-11 (key lifecycle): `sigil-cli keygen` (P-384 pair, PKCS#8 + SPKI PEM, private
  mode 600) and global `--signing-key` flag wired into tokenize/scan/sentinel/multimodal
  (`MultimodalEngine::with_receipt_signer` added). Full generate → sign → verify loop
  proven through the binary; OpenSSL interop validated both directions (SIGIL keys parse
  in openssl, OpenSSL-generated keys sign in SIGIL). `verify-receipt` fixed to unwrap the
  CLI `result` envelope. Two CLI tests added (loop, unwritable-path error). Gates: 93/0,
  clippy clean, contract sync green.
- 2026-09-11 (digest decision): receipt digests moved SHA-256 → **SHA-384** (strength-
  aligned with the ECDSA P-384 mandate; CNSA 2.0 pairs P-384 with SHA-384). Receipt
  gained a signed, self-describing `digest_algorithm` field; signing message bumped to
  `sigil-receipt-v2` (structure change per RIC-SPEC §9 versioning policy). Evidence
  correlation id hash also moved to SHA-384 (still truncated, still non-security).
  Verified through the binary: 96-hex digests, digest_algorithm=sha384, verification
  green. Gates: 93/0, clippy clean, contract sync green.
- 2026-09-11 (both-ecosystems decision + perception exploration): in-toto/DSSE
  attestation layer implemented in sigil-core (`attestation.rs`): Statement v1 payload
  with the receipt as predicate, subject = admitted representation (canonical SHA-384),
  DSSE PAE signing over the existing P-384 port, envelope in ecosystem camelCase
  (`payloadType`/`keyid`/`sig`). New CLI commands `attest` and `verify-attestation`,
  verified through the binary (valid → true; tampered payload → Mismatch). Sigstore
  keyless designed against the same port (OIDC → Fulcio → Rekor; feature-gated adapter;
  four decision points recorded in docs/PERCEPTION-ADAPTERS.md §5). Perception-adapter
  exploration delivered as docs/PERCEPTION-ADAPTERS.md: Option B (adapter crates behind
  a kernel `PerceptionAdapter` port; adapters produce channels, kernel judges), phased
  plan (image → audio → video → document), adapter conformance rules, Phase-1 target =
  image adapter with external-command OCR. Gates: 96/0, clippy clean, contract sync
  green (checker now enforces DsseEnvelope + AttestationVerificationOutcome).
- 2026-09-11 (limitation audit + defect correction, wave 2): Five defects corrected
  after deep online documentation review. **D-10** `audit_fusion` `.unwrap()` panic on
  empty records → guarded with `is_empty()` early return. **D-11** `r2c.process().ok()?`
  silent mid-loop abort in `analyze_spectrum` → skip-and-continue on FFT failure.
  **D-12** `ModalInput<'a>` borrowed `&'a str` forced `Box::leak` memory leak in
  `channels_to_modal_inputs` and all CLI constructions → `ModalInput` now owns `String`,
  eliminating the leak and the `'static` lifetime constraint. **D-13** audio adapter
  `filter_map(Result::ok)` silently dropped corrupted samples without evidence →
  explicit `dropped_samples` counter, spectral channel `truncated` flag, and
  `.dropped_samples` property. **D-14** (critical) audio adapter only read `i16` samples
  — `hound` returns `Err` for every sample on `Float` WAVs and `bits_per_sample > 16`,
  silently bypassing spectral analysis → sample-type dispatch on `spec.sample_format`
  (Float→`f32`, Int≤16→`i16`, Int>16→`i32`) + `normalization_factor()` for bit-depth-
  correct scaling + `f32` downmix variants. **D-15** (critical, GHSA-whqx-f9j3-ch6m)
  `verify_bundle_with_trust` verified Rekor SET + inclusion proof but never compared
  `canonicalizedBody` against the artifact being verified — a bundle could contain a
  valid Rekor entry for a different artifact → `verify_rekor_entry_binding` compares
  `spec.data.hash.value` against `SHA-256(message)` and `spec.signature.content`
  against the bundle's signature. 5 new tests (float WAV, truncated WAV, Rekor binding
  accept/reject×2). Oversized files decomposed: `audio.rs` → `audio/` (mod + sampling
  + transcript + tests), `spectral.rs` → `spectral/` (mod + downmix + tests),
  `trust.rs` → `trust/` (chain + fetch + rekor + types + verify + tests) — all now
  under the 500-line governance limit.

| Capability | State | Where |
|---|---|---|
| Raw↔canonical digest binding (RIC-R-1..R-4) | done | `RepresentationReceipt` on every `SigilOutput` |
| Per-cluster normalization, raw-accurate ranges (INV-007) | done | `intake.rs`, `vocab/encode.rs` remap |
| Unicode Tags U+E0000–E007F + extended invisible detection | done | `intake.rs` predicates, both scan detectors |
| Strip policy (grapheme-level, evidence-preserving) | done | `intake.rs` |
| Merge-boundary findings + `suppress_cross_boundary` policy | done | `merge.rs`, `engine.rs` |
| Fusion-boundary auditor + `AuthorityCeiling` (RIC-R-6..R-8) | done | `sigil-multimodal` |
| Evidence modes: lazy (INV-006) / always-on | done | `emit.evidence_mode` |
| Receipt signing: ECDSA P-384, SHA-384, RFC 6979 | done | `signing.rs` |
| Third-party receipt verification (no producer code) | done | `sigil-cli verify-receipt` |
| Key lifecycle via CLI (keygen, PKCS#8/SPKI PEM, `--signing-key`) | done | `sigil-cli keygen`, `--signing-key` |
| RIC as versioned standalone specification | done (v0.1.0 DRAFT) | `docs/RIC-SPEC.md` |
| CLI: per-modality provenance + `--system` fusion audit | done | `sigil-cli` |
| Perception port (RIC-R-7 type-level) + image adapter + `perceive` CLI | done | `sigil-multimodal::perception`, `crates/sigil-perception` |
| Sigstore keyless signer (OIDC → Fulcio, ephemeral P-384) | done | `crates/sigil-sigstore`, `--sigstore-keyless` |
| Restrictive trust composition (anti-elevation) | done | `taint.rs` |

## 3. Ledgers

**Defects D-1..D-15 — all RESOLVED.** Full history with locations and resolutions:
[RIC-DELTA-ANALYSIS.md](./RIC-DELTA-ANALYSIS.md) Part 1 §1.3 (D-1..D-9). Wave-2 defects
corrected in this session (D-10..D-15): `audit_fusion` `.unwrap()` panic on empty
records (D-10), `r2c.process().ok()?` silent mid-loop abort (D-11), `ModalInput`
`Box::leak` memory leak (D-12), audio adapter `filter_map(Result::ok)` silent sample
drop (D-13), audio adapter `i16`-only sample reading bypassing spectral analysis on
Float/>16-bit WAVs (D-14, critical), `verify_bundle_with_trust` missing Rekor
`canonicalizedBody` artifact binding (D-15, critical — GHSA-whqx-f9j3-ch6m class).

**Deviations DEV-1..4:** DEV-1 (evidence mode) and DEV-2 (raw ranges) closed;
DEV-3 partially closed (ECDSA P-384 done; Sigstore/in-toto + CLI key files remain);
DEV-4 open (perception layer). Ledger: [RIC-CONTRACT.md](./RIC-CONTRACT.md) §3.

**Conformance vectors** (`crates/sigil-core/tests/conformance_vectors.rs`):
CV-RIC-001/001b Tags detection · 002 strip+raw digest · 003/003b merge boundaries ·
004 receipt determinism · 005 raw-range traceability · 006 restrictive trust ·
007 evidence modes · 008 signed receipts.

## 4. Open work queue (recommended order)

### 4.1 Next phases (post-modularization, from REPO-MODEL)

Phases ordered by risk: trust-path correctness first, then spec-MUST gaps,
then measurement, then detection depth, then packaging. Each item is a
`feature/*` branch off `develop`.

| Phase | Item | Evidence / driver | Status |
|---|---|---|---|
| **A. Trust-path hardening** | | | |
| A1 | SAN identity: replace substring match with proper `GeneralNames` ASN.1 parse — substring was spoofable (`alice@x.com.evil.com` contains `alice@x.com`) | `trust/chain.rs` `check_san_identity` — now exact-matches `Rfc822Name`/`DnsName`/`UniformResourceIdentifier` GeneralNames (RFC 5280 §4.2.1.6); 3 regression tests | **done** |
| A2 | Rekor log binding: `entry.log_id` vs `trust.rekor_log_id` | already wired — `trust/verify.rs` step 5 returns `LogIdMismatch` (repomodel open question was stale) | **done** (pre-existing) |
| A3 | TUF trust-root freshness: **decided — embedded snapshot only**. Online TUF refresh (`sigstore-trust-root` `tuf` feature) rejected: a network-fetchable trust root turns the verification boundary into a live-update surface dependent on transport + metadata freshness at verify time. Freshness arrives via `sigstore-trust-root` version bumps (reviewable, signable, bisectable). Rationale now documented in `tuf.rs` module header | `tuf.rs:13-24` | **done** (decided) |
| A5 | **Embedded SCT verification (RFC 6962 §3.5)** — the known gap: `signedCertificateEmbeddedSct` from Fulcio was accepted but never verified, so a cert chaining to the Fulcio root that was never CT-logged passed `verify_bundle_with_trust`. New `trust/sct.rs`: parses the embedded SCT-list extension (OID 1.3.6.1.4.1.11129.2.4.2), rebuilds the precert TBS (SCT ext stripped), verifies ECDSA P-256 over the §3.5 precert input. CT keys come from `sigstore-trust-root`'s `ctfe_keys_with_ids` — no hand-maintained key set. `TrustRoot.ctfe_keys` populated in `tuf.rs`; `validate_chain` now returns the parsed chain so the leaf's issuer (`full_chain[1]`) feeds `issuer_key_hash`. New orchestrator step 3 (chain → SCT → SAN → …, 9 steps total). Policy: SCT required iff the trust root provisions CT keys (embedded prod root always does). 3 rejection tests (missing SCT, rogue-key signature, untrusted log_id); happy path now carries a real embedded SCT | `trust/sct.rs`, `trust/verify.rs:57-62`, `trust/e2e_tests.rs` | **done** |
| A6 | **Upstream bundle interop (hybrid parse-only decision)** — local `SigstoreBundle` predates `tlogEntries` and could not parse cosign-produced bundles at all. New `bundle_convert.rs` delegates wire-format parsing to `sigstore-types` (already in-tree via `sigstore-trust-root` — zero new dep families): `parse_upstream_bundle` converts `sigstore_types::bundle::Bundle` → local `(SigstoreBundle, RekorEntry)`; `verify_upstream_bundle` runs the full 9-step path on the converted pair. Rejects DSSE envelopes, public-key material, missing `tlogEntries`, missing `messageDigest`; normalizes the `+json;version=0.3` alias; multi-tlog-entry bundles take the first entry (Rekor v1 model). 5 interop tests incl. a full e2e verify of a cosign-shaped bundle | `bundle_convert.rs`, `trust/interop_tests.rs`, `trust/verify.rs:98-107` | **done** |
| A4 | **Found while closing C1's `verify.rs` 0% gap:** `verify_cert_signature` parsed cert signatures with `GenericArray::from_slice` — panics on the ~71-byte DER ECDSA-Sig-Value real Fulcio certs carry (and any malformed input). Same panic shape in `verify_rekor_set`. Fixed: DER-first/fixed-fallback parse for certs, `from_slice` for SET. Added `trust/e2e_tests.rs`: synthetic-but-valid trust root (P-256 self-signed CA → DER-signed P-384 leaf + P-256 Rekor key + single-leaf RFC 6962 proof) exercises `verify_bundle_with_trust` happy path + 5 rejection branches. `verify.rs` coverage 0%→82% lines | `trust/chain.rs`, `trust/rekor.rs`, `trust/e2e_tests.rs` | **done** |
| **B. Evidence persistence** | | | |
| B1 | MCP evidence records persist to a sink — spec MUST ("every MCP evidence record MUST eventually be persisted") vs current in-memory `update_history` | `sigil-mcp/src/sink.rs` (`EvidenceSink` trait + `JsonlEvidenceSink` append-only backend); `session.rs` `with_evidence_sink` persists before returning, fail-closed on sink error; `--evidence-log` CLI flag; 2 new tests | **done** |
| B2 | Same sink surface for scan/evidence records beyond MCP | `sigil-core/src/sink.rs` — `EvidenceSink<R>`/`JsonlEvidenceSink` moved to core, generic over `Serialize`; `sigil-mcp::sink` re-exports for API stability; `Sigil::with_evidence_sink` persists `EvidenceBundle` fail-closed; global `--evidence-log` shares one JSONL stream between scan bundles and MCP records. **Found+fixed:** `EvidenceBundle.persisted` was hardcoded `true` at build (`evidence.rs`) — now `false` until a sink confirms the write | **done** |
| **C. Measurement gates** | | | |
| C1 | Coverage: `cargo-llvm-cov` wired in CI with `--fail-under-lines 70` no-regression floor + lcov artifact. **Baseline 74.01% → 80.54% lines / 81.78% regions / 76.66% fns — the 80% governance target is now met; CI floor ratcheted 70→80.** Closed gaps: `verify.rs` 0%→82%, `sigil-server` 0%→96%, `csr.rs` 25%→48% (`decode_chain_certs` extracted into a tested helper), `video.rs` 43%→98% (ffmpeg `tiny_av.mp4` fixture), `tokenizer_ffi.rs` 66%→97%, `downmix.rs` 72%→98% (ITU-R BS.775 LFE-exclusion tests), `audio/transcript.rs` 85%→94% (`/bin/cat`-style subprocess fixtures), `vocab/encode.rs` — 11 tests over specials/grapheme-remap/batch paths. Remaining gaps: `cli/run.rs`+`commands.rs` dispatch plumbing closed via `crates/sigil-cli/tests/cli_integration.rs` — 13 `CARGO_BIN_EXE` binary-level tests (keygen→sign→verify-receipt→attest→verify-attestation chains, wrong-key fail-closed, keyless-without-OIDC fail-closed, `--evidence-log` JSONL side effect, mcp/multimodal/sentinel/perceive dispatch); `run.rs` ~46%, `commands.rs` ~60%, workspace **84.23% lines / 85.41% regions**. Still open: sigstore network paths (not offline-testable). Gap-closure round 2: `document.rs` 80%→92.94% (metadata-fallback on unparseable PDF, page-by-page salvage helper exercised directly — lopdf tolerates missing-Contents/bad-Resources corruption so the batch-failure path is practically unreachable through its public API; helper tested in isolation), `cli/helpers.rs` 59%→77.48% (8 file-input integration tests: `--input` mutual exclusion, JSON-array batch inputs, `--schema`, `--samples`), `dlp.rs` 73.6%→76.44% (`email_verdict` refactor removed unreachable-by-construction `Off` arms; disabled-detector test covers flag-off paths; residual misses are monomorphized iterator/drop regions, not logical branches). Workspace **85.49% lines / 86.55% regions** | `.github/workflows/ci.yml` Coverage gate; `cargo llvm-cov --workspace --summary-only` | **done** |
| C2 | Extend `check_contracts.py` to discover module trees automatically (currently hand-maintained path map) | `scripts/check_contracts.py` `module_tree_files` — each pin resolves to its module tree (`foo.rs`→`foo.rs`+`foo/**`, `mod.rs`/`lib.rs`→whole subtree, missing `foo.rs`→`foo/` fallback); survives `file→dir` splits without pin edits | **done** |
| **D. Detection depth** | | | |
| D1 | Audio steganalysis gen-2: per-frequency narrowband detection (Goertzel-equivalent — the windowed FFT already yields per-bin magnitudes, so no second pass needed) | `spectral/mod.rs`: `stego_peak_fraction` (single-bin >2% of window energy flags `narrowband_high_freq_peak`), `stego_hop_min_bins` (≥3 distinct peak bins → `frequency_hopping`); 3 tests incl. broadband-noise negative | **done** |
| D2 | Injection detection gen-2: multiscale perplexity — implemented in full behind a scorer-trait boundary (no model code in kernel). `SurprisalScorer` supplies per-unit surprisal; `detect_perplexity_anomalies` computes windowed mean surprisal at `window_sizes` scales, flags robust-z (median/MAD) outliers, and emits `PerplexityAnomaly` findings only when a cluster corroborates across `min_scales` scales. Built-in `SelfSurprisalScorer` (order-k char n-gram fit to the input itself — deterministic, offline, zero deps); external LM scorers plug via `Sigil::with_surprisal_scorer` / `run_scan_with_scorer`. Policy-gated (`scan.perplexity.enabled`, default off — noisy on short inputs, opt-in); cost bound `max_windows`; scorer errors → `PerplexityStatus::Failed` evidence, never silent and never a self-decided deny (Medium → Flag, Strict → Deny per kernel mapping). Honest scope: flags segments breaking the document's own char statistics (encoded blobs, obfuscated payloads); same-style English instructions need an LM scorer — documented, not invented. Known artifact: document head can flag (cold-start, no context). 14 tests incl. injected-scorer failure semantics + e2e blob-in-prose via `Sigil` | `crates/sigil-core/src/perplexity.rs`; `policy.rs::PerplexityPolicy`; `scan/run.rs`; `emit.rs` (`FlagReason::PerplexityAnomaly`); `InputAssessment.perplexity` | **done** |
| **E. Deliverables** | | | |
| E1 | `sigil-server` transport: **decided — descoped, façade stays library-only**. Spec §4 claimed "gRPC/HTTP transport planned"; no consumer ever demanded it. The validated deployment surfaces are the CLI stdio-JSON contract (MCP's native transport — the transparent-proxy model is stdio framing), `libsigil` cdylib, `sigil.wasm`, and the `SigilSidecar` façade itself. A network listener on a security boundary needs TLS/authn-z/rate-limit/DoS surface the project has no consumer to justify — speculative attack surface against its own threat model. A transport crate can wrap `SigilSidecar` later without redesign. Spec table + REPO-MODEL D-A updated; stale discrepancy rows D-B..D-H closed in the same pass | `sigil-server/src/lib.rs:41`; `SIGIL-SPEC.md:369`; `REPO-MODEL.md` D-A..D-H | **done** (decided) |
| E2 | `libsigil` cdylib + `sigil.wasm` targets | `crates/sigil-ffi` (cdylib re-exports `zig_tiktoken_*` via `black_box` pin + per-OS `link-arg-cdylib` re-export flags; `sigil_version` added), `scripts/build_wasm.sh` (wasm32-freestanding reactor via `zig build-exe -fno-entry -rdynamic` — stable shape, no `__wasm_apply_data_relocs`). **Validated**: `libsigil.dylib` round-trips `hello world` through the Python ctypes binding; `sigil.wasm` instantiated in Node — `open` rc 0, encode `[15339,1917]`, decode `"hello world"`; wasmtime-py hits a host memory-reservation limit at `Instance` (host config, not module). CI: `libsigil`+`sigil.wasm` build step + python smoke against `libsigil.so` | **done** |
| E3 | Python binding: **decided — keep ctypes**. The binding surface is encode/decode/batch over the `libsigil` C ABI; ctypes needs no Rust-side pyo3 build chain, no per-interpreter wheels, and matches the boundary style of the Go `cgo` binding. PyO3 buys nothing at this ABI width; revisit if the Python surface grows object-level APIs | `bindings/python/` | **done** (decided) |
| F1 | CLI presentation layer (UX/DX): `--format auto|json|human` + `--color auto|always|never` (`NO_COLOR` honored; `auto` = human on TTY, JSON piped — existing JSON consumers and all integration tests unaffected). `tokenize`/`scan --explain` renders the INTAKE → SCAN → MERGE → EMIT pipeline with stage narration; human views show verdict banner, per-token id/span/provenance/threat, findings with highlighted source spans, receipt + evidence status. Invisible/control codepoints render as `\u{…}` escapes — the human view cannot launder the representation it explains. Presentation renders the kernel's `SigilOutput`; it never recomputes verdicts (footer states this). `completions <shell>` via `clap_complete`. `bench --format` renamed `--report-format` (global `--format` owns the presentation contract; bench flag was a report serializer). Bounded output: token table caps at 40 rows. 11 unit + 7 binary tests | `sigil-cli/src/cli/output.rs` (`Printer`), `human.rs` (pipeline view), `human_reports.rs` (secondary commands), `types.rs` (`--explain`, `completions`) | **done** |
| F2 | Terminal-escape detection (`scan.terminal_escapes`, opt-in) — VT/ANSI control sequences in admitted text flagged at the boundary: OSC 52 clipboard hijack, OSC 8 hyperlink display/target smuggling, title/notification spoofing, ConEmu `9;N` automation, rxvt/iTerm2/kitty extension channels, CSI/DCS output forgery. Port boundary mirrors `perplexity.rs`: `TerminalSequenceScanner` trait in `sigil-core` (extraction/classification only); `sigil-vt` supplies `VtScanner` — a purpose-built span lexer (CSI/DCS/OSC/ESC framing, byte ranges) + an owned OSC-selector table mirroring ghostty's `osc.zig` taxonomy (pinned commit `a887df4`, reviewed against source incl. ConEmu subcodes and `9;12`→semantic_prompt). Kernel owns severity (clipboard-write/ConEmu automation/extension-channel → `High`; hyperlink/title/notification/cwd-report/mode/file-drop → `Medium`; unclassified/unknown → `Low` — a control sequence is reportable regardless of nameability), evidence text, `FlagReason::TerminalEscape`. Enabled-without-scanner → `Skipped`; scanner error → `Failed`. `InputAssessment.terminal` + human status line. **Dependency history**: first shipped over `libghostty-vt` (rust ≥1.90 + zig 0.15.2 + ghostty fetch) behind a `vt` cargo feature; **untangled** — the FFI bought naming precision, not detection coverage, so the runtime path is now a ~40-line owned table (better adversarial posture: unparseable/malformed OSC → `unclassified` finding, not parser-reject) and `libghostty-vt` survives only as an optional `conformance` feature cross-checking the table against the fuzzed upstream parser (CI `vt-conformance` lane, rust 1.90 + zig 0.15.2). No feature gates, no `--exclude` flags, workspace MSRV 1.78 holds. 14 core + 11 scanner + 4 wiring tests; e2e `sigil-cli scan` (OSC 52 → `Flag{TerminalEscape}`, span 11..31, `sigil-vt osc-table` named in evidence) | `crates/sigil-core/src/terminal.rs`, `crates/sigil-vt`, `policy.rs::TerminalEscapesPolicy`, `scan/run.rs::run_scan_with_engines`, `emit.rs`, CI `vt-conformance` job | **done** |
| F3 | CSI semantics + repaint-pattern detection — the stated F2 follow-up done without re-tangling: instead of dragging the full `Terminal`/`Screen` emulator (and its FFI) into the runtime path, `VtScanner` decodes CSI operation names from an authored ECMA-48/xterm table (`erase_line`/`erase_scrollback`/`sgr_conceal`/`alt_screen`/cursor/scroll/mode ops) and synthesizes a cross-sequence `Pattern` finding — `repaint_overwrite`: an erase/rewind CSI followed by printable text before the next vertical advance (LF/VT/FF/NEL clear; CR deliberately does not — `erase+CR+rewrite` is the canonical idiom). `TerminalSequenceKind` gains `Csi { command }` (was unit) + `Pattern { name }`. Kernel severity: conceal/scrollback-erase/alt-screen/repaint → `Medium` (display-vs-stream divergence, evidence evasion); other CSI → `Low`. E2E: `apt install\x1b[2K\x1b[Gran: rm -rf /` → Medium repaint finding spanning the erase..forged-text window. 12 terminal + 4 wiring core tests; 14 scanner tests | `terminal.rs` (`Pattern` kind + CSI arms), `sigil-vt/src/lib.rs` (`csi_command`, `is_repaint_trigger`, pending-window state in `scan`) | **done** |
| F4 | Virtual sliding window — F3's syntactic trigger heuristic replaced by a bounded screen model (`sigil-vt/src/window.rs`, 200×48 cell grid + per-row pre-erase snapshots, ~490 LOC): the byte stream is replayed against cells, and `repaint_overwrite` fires on *semantic divergence*, not sequence syntax. Two detection paths: per-cell overwrites (a byte lands on a cell showing a different byte — catches `abc\x1b[3DXY` cursor-back rewrites and `\x08` overstrike with no erase op at all) and per-row snapshots (an erase records the row's prior text; if the row ends non-blank and different — erase+rewrite, erase+displaced-write — it diverged; identical rewrites and blank-after-erase stay silent). Rows are evaluated at scroll eviction so divergence survives the slide; cursor save/restore, IL/DL/DCH/ICH shifts, and `?1049` alt-screen swap are modeled. Evidence now carries both representations (`repaint: "run: apt install" → "ran: rm -rf /"`). Limits documented in the module header: byte-granular cells (not glyph-exact), no scrollback, raw-stream semantics (LF ≠ CR+LF), first-snapshot-per-row. Still no emulator/FFI — kernel severity unchanged. 19 scanner tests; e2e: cursor-back forge and identical-rewrite suppression both validated through `sigil-cli scan` | `crates/sigil-vt/src/window.rs`, `lib.rs` (`csi_span`/`esc_dispatch`/`feed_plain` dispatch) | **done** |
| F5 | Window conformance vs `libghostty-vt` `Terminal` — the self-authored window model was the last detection surface with no upstream check; the `conformance` lane now replays every modeled op through both Ghostty's real `Terminal` (`vt_write` → active-screen cells) and `VirtualWindow`, asserting per-cell parity. The lane caught and fixed five divergences: CNL clamps at the bottom (was scrolling); pending-wrap is a real state (erase/shift/cursor ops clear it, scroll preserves it — was a `col==COLS` sentinel LF broke); IL/DL move the cursor to the left margin; alt-screen is per-mode (`?47` swap-only, `?1047` erases on exit, `?1049` saves/restores cursor + erases on entry — cursor copies in, not resets to 0,0); `ESC D/E/M` and `ESC 7/8` now feed the window (raw C1 bytes confirmed glyph-rendered in ghostty, deliberately not controls). Snapshot vectors shift with displaced lines to prevent stale-snapshot false positives. Split: `window/findings.rs` (events, snapshots, synthesis) vs `window.rs` (state/ops); `tests/ghostty_conformance.rs` holds the lane. 26 conformance + 19 unit tests green | `crates/sigil-vt/src/window.rs`, `window/findings.rs`, `lib.rs` (`run()`), `tests/ghostty_conformance.rs` | **done** |
| F6 | Window limits enforced as findings — the model's documented limits are now quarantined, not silent: any display-affecting op outside the modeled set emits `window_unmodeled` (origin mode, DECLRMM margins, LNM, 132-col, unknown CSI finals, ESC intermediates like charset selects — Medium, kernel-owned). Rows written with bytes ≥0x80 flag `nonascii` (byte-cell vs glyph-cell desync); a later overwrite/erase there emits `window_degraded` instead of precise-but-wrong evidence, and the row re-enters precise tracking once blanked. Per-epoch erase evaluation closes the `A → erase → B → erase → A` evasion the first-snapshot model missed. Findings are capped at 128; the first dropped range reports as a `window_degraded` marker — suppression is never silent. Model extended where cheap: DECSTBM scroll regions (LF/RI scroll inside margins only; IL/DL confined; CUU/CUD/CNL/CPL clamp at margins), IRM insert mode, DECAWM-off (overstrikes last cell; pending-wrap kept-but-inert), RIS. New seeded differential fuzz in the conformance lane (40 streams × 300 ops, per-op cursor + per-stream grid vs ghostty `Terminal`) caught three real bugs on first run: RI underflow at row 0 inside a region, vertical moves ignoring region clamps, `?1049h/l` not being unconditional (saves/restores even without a screen change). ESC intermediates no longer leak final bytes into display state. Split: `window/ops.rs` (CSI dispatch), `osc.rs` (OSC classification); `is_modeled` names the quarantine boundary. 27 unit + 35 conformance tests; e2e `?6h` → `window_unmodeled` and non-ASCII overstrike → `window_degraded` verified through `sigil-cli scan`. Stated limits stand: byte-granular cells, no scrollback, no left/right margins (DECLRMM quarantined), final-grid conformance only | `window.rs` (region/modes/RIS/RowState), `window/ops.rs`, `window/findings.rs` (kind-named findings, cap, degraded path), `lib.rs` (`is_modeled`, `unmodeled`, `esc_single`/`esc_intermediates`), `osc.rs`, `terminal.rs` (severity arms), `tests/ghostty_conformance.rs` (fuzz + new-op cases) | **done** |
| F7 | Mode-state semantics — the F6 quarantine flags were *names* only; the online spec review (xterm `ctlseqs`, DEC STD 070, ghostty `stream_terminal.zig`) showed mode bits change what later ops mean, so flags are now tracked state: `?69h` (DECLRMM) redefines `CSI s` as DECSLRM — `effective_op` renames it `declrmm_margins` so it stays quarantined instead of being misapplied as SCOSC (ghostty's `left_and_right_margin_ambiguous` dispatch confirms); `?6h` (DECOM) makes CUP/HVP/VPA region-relative — gated to `origin_cup`/`origin_vpa` so absolute addressing isn't silently applied. DECOM set/reset homes the cursor to the new origin (region top-left under decom — xterm charproc.c behavior ghostty mirrors via `setCursorPos(1,1)`), modeled via `home()`. Saved cursors upgraded to `Saved{row,col,wrap,decom}` matching ghostty's `SavedCursor.{pending_wrap,origin}` — DECSC/DECRC and `?1049` preserve/restore all four. The conformance lane caught the missing DECOM-home semantic on first run. `tests/quarantine.rs` holds the mode-gate battery (extracted under the 500-LOC cap); e2e `?69h` + `CSI s` → `declrmm_margins` quarantine + `repaint: "A" → "B"` through `sigil-cli scan`. 30 unit + 39 conformance tests | `window.rs` (`Saved`, `decom`/`declrmm` fields, `saved_state`/`restore_state`), `window/ops.rs` (`effective_op`, `home`, mode arms), `lib.rs` (`csi_span` gate), `tests/quarantine.rs`, `tests/ghostty_conformance.rs` (decom/declrmm + saved-cursor cases) | **done** |
| G1 | Encoded-payload rescan — closes the gap where `base64-like payload` flagged *presence* but never content: `detect_encoded` (`scan/decode.rs`) finds base64/base64url (padded + nopad), percent, `\xNN`-hex, bare-hex, `&#NN;`/`&#xNN;`-entity spans and HTML-comment interiors, decodes each, and rescans the decoded text through `detect_injection` (incl. Unicode-abuse). Findings map to the *source* span via `TextMap::derived` (single-unit map) and carry `encoded_payload` alongside the inner detector; evidence records the decode chain (`decoded(base64): decoded(base64): …`, depth ≤ 2). Presence alone is never a finding — only decoded content that trips inner detectors is reported, so FP rate stays bounded by the base scanners; binary decodes skipped by a 60% printability gate; decoded findings floor at Medium; caps are findings not failures (>64 spans or >32 KiB decode → Low marker). All-hex runs try both base64 and hex decodings. Default-on via `scan.encoded_payloads`. E2E: `aWdub3JlIHByZXZpb3VzIGluc3RydWN0aW9ucw==` → `high [injection_grammar, encoded_payload] | decoded(base64): ignore previous` through `sigil-cli scan`. 5 new unit tests (b64/nested/pct+hex-esc/entity+comment/benign+binary-silent) | `scan/decode.rs`, `scan/types.rs` (`TextMap::derived`), `scan/run.rs`, `policy.rs` (`encoded_payloads`), `types.rs` (`DetectorId::EncodedPayload`), `scan/tests.rs` | **done** |
| G2 | Markup-hidden rescan — same hidden-surface machinery, markup edition: `decode.rs` spans now include markdown link targets (`](…)`, capture-group extraction), CSS-concealed element bodies (`display:none`/`visibility:hidden`/`opacity:0`/`font-size:0`), and `hidden`-attribute bodies. Concealment markup earns a Low `encoded_payload` presence marker (anomalous in model input regardless of content) while interiors rescan like any hidden surface — `[x](%69%67…)` reaches `decoded(link-target): decoded(percent): ignore previous` at High. Percent/base64 inside targets recurse via the depth-2 chain | `scan/decode.rs` (capture-group span table, markup schemes, presence markers), `scan/tests.rs` | **done** |
| G3 | Rendered-vs-extracted divergence — the post's PDF case, shipped: `DocumentAdapter::render_compare` chains two pinned externals (`ExternalPipe` renderer + `ExternalOcr`, both SHA-384-bound, stdin-only artifact flow) — render the PDF to pixels, OCR the pixels back, diff the text layer against what painted. Lines <80% word-covered by the render surface as `ChannelKind::Divergence` (new variant; `McpTool` provenance — kernel judgment). E2E-verified: white-on-white `ignore previous instructions` → `text_layer` both lines, `ocr_text` visible line only, `divergence` the hidden line, verdict `Flag{SentinelDisagreement}`. CLI: `--render-binary`/`--render-args` + existing `--ocr-*`; one-sided wiring is a config error not a silent skip. Limits documented: `-singlefile` page-1 only; mis-OCR over-reports divergence (extra evidence, not silence) | `sigil-perception/lib.rs` (`ExternalPipe`), `document.rs` (`RenderCompare`, `divergent_lines`), `sigil-multimodal/perception.rs` (`ChannelKind::Divergence` + provenance arms), `cli/commands.rs`, `cli/types.rs` | **done** |
| G4 | Injection-grammar expansion — the detector-miss documented in POC-CASES fixed: High adds `ignore all prior`, `ignore prior`, `ignore the above`, `disregard all`, `forget all previous`, `forget prior`; Medium adds `previous/prior instructions`, `from now on`, `do anything now`, `new persona`, `pretend to be/you are`. The post's own phrase ("Ignore all prior instructions") now hits High | `scan/detectors.rs` pattern table, `scan/tests.rs` | **done** |
| G5 | Video stream extraction — `VideoAdapter` was metadata-only: an instruction painted in frames or spoken in audio never reached the modality adapters. `StreamExtract::pin` demuxes through pinned `ffmpeg` pipes: audio track → mono 16 kHz WAV → `AudioAdapter` (spectral + optional ASR), video track → 1 fps `image2pipe` PNG stream → `split_png_stream` (IEND-marked) → per-frame `frame-ocr[i]` OCR channels with pinned identity. `wav_patch_streamed_sizes` repairs ffmpeg's streamed RIFF/`data` `0xFFFFFFFF` headers for hound. Failures degrade to named properties (`stream.audio = failed:`), frames >12 → `stream.frames_capped` — evidence, not silence. CLI `--ffmpeg-binary` (+ `--ocr-binary`, `--transcript-binary`); missing ffmpeg with downstream flags is a config error. E2E-verified: painted `IGNORE PREVIOUS INSTRUCTIONS` → `frame-ocr[0]` → `Flag{SentinelDisagreement}` | `video.rs` (`StreamExtract`, `FrameOcr`, `extract_streams`, `wav_patch_streamed_sizes`, `split_png_stream`), `tests/stream_extract.rs`, `cli/commands.rs`, `cli/types.rs` | **done** |
| G6 | Subtitle extraction + magic routing — the mp4parse "permanent limitation" removed via a third pinned pipe (`-map 0:s:0? -f srt` → `ChannelKind::Caption`); `mov_text` tracks land in `TrackType::Unknown` so a caption the inventory never counted surfaces `stream.subtitle_beyond_inventory` (parser-vs-demux divergence as evidence). `sniff_modality` (PNG/JPEG/GIF, RIFF-WAVE/fLaC, `ftyp`, `%PDF`) turns `--modality` into a real hint: a contradicting hint routes to the sniffed adapter and records `sigil.modality_routed`, rather than decode-failing on the wrong adapter. E2E: subtitle-bearing MP4 → `caption` channel `ignore all prior instructions`; `--modality image` on MP4 → routed to video with override evidence | `video.rs` (`SUBTITLE_ARGS`, subtitles pipe arm), `cli/commands.rs` (`sniff_modality`, routing), `cli/types.rs` | **done** |
| G7 | Code adapter — the last declared modality wired: `CodeAdapter` splits a source artifact into executable-vs-inert surfaces via a lexer state machine (`//`, `/* */`, `#` gated to line-start/after-space, `"""`/`'''`, `"`/`'`/backtick with escapes and Rust-lifetime guard). `code/comments` + `code/strings` `text_layer` channels + `structure` counts; each channel rescanned — an instruction in a comment or literal reaches the model but never the compiler. E2E: `.py` carrying `# ignore all prior instructions` + `PAYLOAD = "ignore previous instructions"` → instruction in both channels → `Flag{SentinelDisagreement}` | `sigil-perception/code.rs` (state machine, `hash_opens_comment`, `quote_opens_literal`), `cli/commands.rs` (`code` arm), `cli/types.rs` | **done** |

### 4.2 Completed queue (history)

| # | Item | Class | Notes |
|---|---|---|---|
| 1a | in-toto/DSSE attestation layer | **done** | `attestation.rs`, `sigil-cli attest` / `verify-attestation` |
| 1b | Sigstore keyless adapter | **done** | `crates/sigil-sigstore`: Fulcio exchange, Rekor upload, bundle v0.3 emission, offline signature verification, chain-of-trust validation (RFC 5280 §6 + SAN + validity + SET + RFC 6962 inclusion proof), TUF root distribution (`sigstore-trust-root` embedded `trusted_root.json`); live integration testing remains |
| 2 | CLI key-file handling (`--signing-key`) | **done** | `sigil-cli keygen` (P-384 PKCS#8/SPKI PEM, mode 600), `--signing-key` loads PKCS#8 PEM, `verify-receipt` verifies P-384 signatures |
| 3 | Perception-adapter layer, Phase 0+1 (port + image adapter) | **done** | `sigil-multimodal::perception`, `crates/sigil-perception`, `sigil-cli perceive` |
| 3b | Perception Phase 2 (audio) | **done** | `sigil-perception::audio::AudioAdapter`: WAV decode via `hound`, format facts, metadata channel, optional pinned ASR transcript. 5 tests |
| 3c | Perception Phase 2+ (video, document adapters) | **done** | `sigil-perception::video::VideoAdapter` (MP4 via `mp4parse`), `sigil-perception::document::DocumentAdapter` (plain text, markdown, PDF text extraction). 8 tests |
| 3d | Low-frequency deception detection | **done** | `sigil-perception::spectral` (subliminal audio + steganography via FFT), `sigil-core::lfdd` (rare pattern + slow-rate cross-input). 17 tests |
| 4 | Digest-algorithm decision | **decided: SHA-384** | Implemented with self-describing `digest_algorithm` field; message bumped to `sigil-receipt-v2` |
| 5 | Refresh deck claims | comms | "signed receipt" slide is now implemented fact, not aspiration |

## 5. Document map

| Document | Holds |
|---|---|
| `SIGIL-SPEC.md` | Normative specification (pipeline, policy, invariants, receipt schema) |
| `docs/RIC-SPEC.md` | Versioned standalone RIC specification (v0.1.0) for ecosystem adoption |
| `docs/PERCEPTION-ADAPTERS.md` | Perception-adapter exploration (Option B, phased plan) + Sigstore keyless design |
| `crates/sigil-sigstore` | Sigstore keyless adapter (Fulcio exchange, Rekor upload) |
| `docs/RIC-CONTRACT.md` | RIC rules RIC-R-1..8 mapped to implementations + deviation ledger |
| `docs/RIC-DELTA-ANALYSIS.md` | Critique of the source design conversation + defect ledger D-1..D-9 + gap table G-1..G-16 |
| `docs/POC-CASES.md` | The three hypothesis cases with exact commands + observed outputs |
| `docs/TRAJECTORY.md` | This document — maintained trajectory and work queue |
| `formal/*.tla` | TLA+ invariants (INV-001..007, MCP, taint algebra, liveness) |
| `crates/sigil-core/tests/conformance_vectors.rs` | Executable conformance vectors CV-RIC-001..008 |
| `comms/` | Management deck (PPTX) + LinkedIn post |
