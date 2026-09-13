# RIC / SIGIL — Critique and Gap Analysis

**Scope:** Reconciliation of the RIC (Representation Integrity Contract) + multimodal SIGIL
design conversation against SIGIL-SPEC v0.3.0 and the implemented Rust workspace.
**Date:** 2026-09-11
**Evidence grades:** `proved` (ran it) · `validated` (verified against source) · `scanned` (read it) · `claimed` (asserted, unverified)

---

## Part 1 — Critique of the RIC/SIGIL design conversation

The conversation proposes RIC as a constitutional contract ("admit what is interpreted,
execute what was admitted, prove the two are the same") and SIGIL as its enforcement
engine, extended to multimodal fusion. Overall verdict: **adopt the framing, reject
several specifics, and correct three claims that do not survive contact with the repo.**

### 1.1 What holds up

| Claim | Grade | Notes |
|---|---|---|
| Representation-differential is the right threat abstraction (human view ≠ scanner view ≠ tokenizer view ≠ model view) | validated | Matches SIGIL-SPEC §1.1 "structural gap" and the Microsoft ASCII-smuggling finding cited in the conversation. |
| Classification before transformation | validated | SIGIL-SPEC Stage 2 (TAINT) already mandates provenance before SCAN/MERGE; the conversation's `CLASSIFY` stage is a re-discovery of TAINT, not a new stage. |
| Fusion-boundary as a distinct primitive from merge-boundary | validated | Nothing in SIGIL-SPEC v0.3.0 covers cross-source composition semantics; INV-002/INV-MCP-003 cover taint *accumulation* but not instruction *formation* across sources. |
| Authority degradation instead of binary safe/unsafe | validated | Consistent with CKODEX vector-state doctrine; SIGIL currently has only Allow/Flag/Deny. |
| Derived modalities never inherit greater authority than their source | validated | Direct generalization of INV-MCP-002 (trust monotonicity). |

### 1.2 What needs correction

**C-1. "CLASSIFY must be inserted between INTAKE and NORMALIZE."** — CONTRADICTED for this repo.
SIGIL's pipeline is INTAKE → TAINT → SCAN → MERGE → EMIT; provenance tagging (the
classification) already precedes normalization-dependent scanning and is supplied
per-segment by the caller (`TextSegment.provenance`, engine.rs:32-43). Adding a stage
would violate INV-001 (stage ordering, machine-checked in TLA+). The correct move is to
*enrich* TAINT, not to add a stage.

**C-2. Three-Split crate layout (`sigil-kernel/validation/transport/evidence/conformance`).** — REJECTED as a refactor target.
The workspace already separates concerns differently and defensibly: `sigil-core`
(kernel, no I/O), `sigil-mcp`/`sigil-multimodal`/`sigil-probe` (domain adapters),
`sigil-server`/`sigil-cli` (transport), `formal/` + `tests/` (conformance). Renaming
crates to match a conversation artifact is churn with no invariant gain. The Three-Split
*discipline* (pure kernel, shared validation once, transport as mapping) is already
satisfied in substance; adopt it as a rule for future crates, not as a migration.

**C-3. The receipt schema (`RepresentationAdmissionReceipt`) as specified.** — PARTIALLY ADOPTED.
The current `EvidenceBundle` (types.rs:308-318) carries an FNV-1a-derived id, a summary
string, and no digests, lineage, or signature. FNV-1a is not collision-resistant and is
unsuitable as evidence identity. The RIC receipt direction is right, but the protobuf
envelope with 13 message types is over-scoped for a v0.3 library. A minimal
cryptographically-honest receipt (SHA-256 raw + canonical digests, normalization
profile, tokenizer identity, verdict) is the correct first increment.

**C-4. Multimodal claims in the conversation vs. the multimodal crate.** — The conversation
describes `RepresentationGraph`, spatial/temporal spans, OCR/ASR divergence checks. The
implemented `sigil-multimodal` crate (lib.rs, 464 lines) accepts `content: &str` for
*every* modality and "detects" image/audio/video threats by ASCII-lowercase substring
matching (`content.contains("text in image")`). There are no pixels, waveforms, or
frames anywhere in the type signatures. Any multimodal claim beyond text-channel taint
propagation is currently `claimed`, not implemented. The honest delta is a
provenance-based fusion auditor over *text-extracted* modality channels — which is what
this repo can actually attest today.

**C-5. Standards citations.** — The conversation cites UAX #15, UTS #39, UAX #31, UAX #9,
UTS #55, OWASP LLM01, MITRE ATLAS AML.T0068, NIST SP 800-53 SI-10. These are the right
anchors and consistent with SIGIL-SPEC §8.1's positioning table. Grade: `scanned`
(cited plausibly; individual clause texts not re-verified in this session).

### 1.3 New defects found in the repo during this analysis (not in the conversation)

| ID | Defect | Location | Grade |
|---|---|---|---|
| D-1 | `combine_trust` returns the **maximum** trust of two inputs. Under `TrustLevel` ordering (`Untrusted < Bounded < Trusted < Privileged`), composition can *raise* trust — violating the anti-dilution doctrine (INV-002 analog for trust). Currently dead code, so it is a latent trap, not an active bug. | crates/sigil-core/src/taint.rs:32-38 | validated |
| D-2 | Unicode Tags block **U+E0000–U+E007F** is absent from both invisible-char detection (`detect_unicode_abuse`) and smuggling detection (`is_smuggling_char`), although SIGIL-SPEC §3.1 Stage 1 explicitly claims "tag characters (U+E0001–U+E007F)" are inventoried. This is precisely the block implicated in ASCII-smuggling research. | crates/sigil-core/src/scan/mod.rs:228-231, 540-554 | validated |
| D-3 | `InvisibleCharPolicy::Strip` is a no-op. The policy variant exists and only lowers scan severity; no code path ever strips a character. Spec §3.1 Stage 1 promises "Invisible character stripping — configurable policy (strip, flag, deny)". | crates/sigil-core/src/policy.rs:35, scan/mod.rs:237 | validated |
| D-4 | Evidence identity uses FNV-1a (non-cryptographic). | crates/sigil-core/src/evidence.rs | validated — **RESOLVED** (evidence id now SHA-256-derived; documented as a correlation handle, not a security anchor — cryptographic digests live on the receipt) |
| D-5 | Merge suppression is silent: when `security_aware_merge` splits encoding at a provenance boundary, no finding is emitted, so downstream consumers cannot distinguish "clean input" from "input whose boundary-crossing merges were suppressed". The conversation's core differentiator (unsafe-merge *detection*) is therefore absent even though suppression exists. | crates/sigil-core/src/merge.rs:18-43 | validated — **RESOLVED** (boundary findings emitted; `suppress_cross_boundary` wired; unsuppressed crossings flagged High) |
| D-6 | Byte ranges are computed against the **normalized** text, not the raw input (normalization can change byte length). INV-007 says tokens map to "the original input". Latent spec deviation; fix requires an offset map through normalization. | crates/sigil-core/src/intake.rs:46-65 | validated — **RESOLVED** (per-cluster normalization on raw text + token-range remap; pinned by CV-RIC-005) |
| D-7 | Token byte ranges in `vocab.rs` were computed in normalized cluster space but offset by the raw base offset, producing ranges that slice mid-character whenever normalization changed length. Found by conformance vector CV-RIC-005, not by unit tests. | crates/sigil-core/src/vocab.rs (`try_encode_graphemes`) | validated — **RESOLVED** (remap onto raw cluster ranges) |
| D-8 | The CLI `multimodal` command hard-coded `Provenance::User` for every channel, starving the fusion auditor: cross-trust, cross-role, and instruction-formation rules could never fire through the binary. | crates/sigil-cli/src/lib.rs (`Commands::Multimodal`) | validated — **RESOLVED** (per-modality provenance defaults: document→Retrieval, media→McpTool, code→User; new `--system` flag feeds the authority-bearing channel so the full fusion audit is exercisable end-to-end) |
| D-9 | The base64-like payload heuristic (`looks_like_base64`) is shape-based only: any natural-language run of 32+ base64-alphabet characters (e.g. a long lowercase English sentence with no digits or symbols) is flagged `token_smuggling` at Medium. Lacks an entropy check, so precision degrades on ordinary prose. | crates/sigil-core/src/scan/mod.rs (`looks_like_base64`) | validated — **RESOLVED** (contiguity gate: the discriminator is uninterrupted runs, not entropy — prose breaks at every space, payloads do not; `-`/`_` break runs so hyphenated prose stays clean; measured-entropy gating was evaluated and rejected, see scan/mod.rs doc comment; pinned by 3 scan tests + attack_proofs regression) |

---

## Part 2 — Gap analysis: conversation proposal vs. repo state

Legend: EXISTS (implemented) · PARTIAL (exists but weaker than proposed) · MISSING · CONTRA (proposal conflicts with repo invariants)

| # | Conversation proposal | Repo state | Class | Action taken in this delta |
|---|---|---|---|---|
| G-1 | Classification precedes transformation | TAINT stage; per-segment provenance | EXISTS | none (documented) |
| G-2 | Provenance survives transformation | `TokenAnnotation.provenance`, byte ranges | EXISTS | none |
| G-3 | Unsafe merge-boundary *detection* (finding, not just suppression) | Suppression only, silent | PARTIAL | **implemented** — `MergeBoundary` findings emitted on suppression |
| G-4 | Unicode Tags (U+E0000–E007F) detection | Missing | MISSING | **implemented** in both detectors |
| G-5 | Soft hyphen / interlinear annotation / invisible-operator coverage (U+00AD, U+FFF9–FFFB, U+2061–2064, U+180E) | Missing | MISSING | **implemented** |
| G-6 | `strip` policy actually strips | No-op | PARTIAL | **implemented** at grapheme level |
| G-7 | Trust composition is restrictive (min) | `combine_trust` = max (dead code) | CONTRA | **fixed** to min + test |
| G-8 | Cryptographic receipt (raw/canonical digests, profile, tokenizer identity) | FNV-1a summary id | PARTIAL | **implemented** — SHA-256 `raw_digest`/`canonical_digest`, normalization profile, vocab identity on `EvidenceBundle` |
| G-9 | Fusion-boundary auditor (cross-trust, cross-role, instruction formation, derived escalation) | Keyword stubs on strings | MISSING | **implemented** — `FusionBoundaryAuditor` in sigil-multimodal with provenance-based rules |
| G-10 | Authority ceiling vector (act/draft/observe/escalate) | Allow/Flag/Deny only | MISSING | **implemented** — `AuthorityCeiling` derived from verdict + fusion events |
| G-11 | RIC normative contract doc | Absent | MISSING | **implemented** — docs/RIC-CONTRACT.md |
| G-12 | RepresentationGraph with spatial/temporal spans, OCR/ASR engines | Not implementable for `&str` channels | MISSING | deferred (would require real media decoding; out of scope for a text-attestation library) |
| G-13 | Three-Split crate migration | Different but sound layout | CONTRA | rejected (documented rationale in §1.2 C-2) |
| G-14 | Protobuf envelope + gRPC daemon | TOML/JSON/serde stack | CONTRA (for now) | deferred; JSON receipts via serde are the current evidence plane |
| G-15 | Tokenizer compatibility manifest (model/tokenizer digest binding) | Vocab carries name; no digest binding in output | PARTIAL | **implemented** — vocab identity recorded in receipt (digest-level binding deferred) |
| G-16 | Signed receipts (Sigstore/in-toto) | Absent | MISSING | deferred (key management is a deployment concern; digests are the prerequisite) |

## Part 2b — DEV-3 increment (receipt signing)

| Item | State | Evidence |
|---|---|---|
| `ReceiptSigner` port in sigil-core (key material outside `Policy`) | done | `crates/sigil-core/src/signing.rs` |
| ECDSA P-384 reference adapter (NIST P-384/secp384r1, SHA-384, RFC 6979 deterministic nonces, no RNG dep) | done | `EcdsaP384Signer` (`p384` 0.13) |
| Versioned signed message (`sigil-receipt-v1|raw|canonical|norm|vocab|tokens`) | done | `receipt_message` |
| Signature on every receipt when a signer is attached | done | `RepresentationReceipt.signature` |
| Standalone verification with pinned hex verification key | done | `verify_receipt_signature` |
| Conformance vector: sign/verify, tamper detection, unsigned default | done | CV-RIC-008 |
| Sigstore keyless / in-toto / HSM adapters | future | same port |
| Algorithm mandate: ECDSA P-384 (not Ed25519) | enforced | `EcdsaP384Signer.algorithm()` = `ecdsa-p384-sha384`; verifier rejects other algorithms |
| CLI key-file handling | future | deliberate scope exclusion |

## Part 3 — What was intentionally NOT done

- No crate restructuring (G-13 rationale).
- No new external dependencies beyond `sha2` (receipt digests). The conversation's
  OPA/WASM/Sigstore/C2PA integrations are architecture-future, not v0.3 scope.
- No media decoding in sigil-multimodal. The fusion auditor operates on declared
  modality channels with provenance and derivation metadata — the only claims this
  codebase can honestly attest.
- ~~Normalization offset-map fix (D-6)~~ **resolved in the follow-up increment**: per-cluster
  normalization on raw text plus token-range remapping in `try_encode_graphemes`, pinned by
  conformance vectors CV-RIC-001..008 (`crates/sigil-core/tests/conformance_vectors.rs`).
