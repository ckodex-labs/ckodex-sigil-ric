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
| A3 | TUF trust-root freshness: embedded snapshot is documented design; decide online refresh (`sigstore-trust-root` `tuf` feature) vs static-by-design | `tuf.rs:15-40` | decision needed |
| **B. Evidence persistence** | | | |
| B1 | MCP evidence records persist to a sink — spec MUST ("every MCP evidence record MUST eventually be persisted") vs current in-memory `update_history` | `sigil-mcp/src/session.rs:127`; `SIGIL-SPEC.md:1327` | open |
| B2 | Same sink surface for scan/evidence records beyond MCP | `sigil-core/src/evidence.rs` | design |
| **C. Measurement gates** | | | |
| C1 | Coverage: wire `cargo-llvm-cov` (or tarpaulin), enforce ≥80% in `ci.yml` — target exists, no tool configured | `.github/workflows/ci.yml`; governance hard limits | open |
| C2 | Extend `check_contracts.py` to discover module trees automatically (currently hand-maintained path map) | `scripts/check_contracts.py` | open |
| **D. Detection depth** | | | |
| D1 | Audio steganalysis gen-2: Goertzel per-frequency bins (cheap, catches weak frequency-hopping that band-energy misses) | `spectral/mod.rs`; research: MDPI AS 14/14/6000 | open |
| D2 | Injection detection gen-2: multiscale perplexity needs a model — either document as out-of-scope or integrate a perplexity signal via `sigil-probe` | `lfdd.rs`; research: arXiv:2311.11509 | design |
| **E. Deliverables** | | | |
| E1 | `sigil-server` transport: gRPC/HTTP + MCP proxy — spec §4 table vs §module map disagreed; decide planned vs descoped | `sigil-server/src/lib.rs:41` (facade only) | decision needed |
| E2 | `libsigil` cdylib + `sigil.wasm` targets | `SIGIL-SPEC.md:342-343` | planned |
| E3 | Python binding: PyO3 vs ctypes decision | `bindings/python/` is ctypes today | decision needed |

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
| `docs/TRAJECTORY.md` | This document — maintained trajectory and work queue |
| `formal/*.tla` | TLA+ invariants (INV-001..007, MCP, taint algebra, liveness) |
| `crates/sigil-core/tests/conformance_vectors.rs` | Executable conformance vectors CV-RIC-001..008 |
| `comms/` | Management deck (PPTX) + LinkedIn post |
