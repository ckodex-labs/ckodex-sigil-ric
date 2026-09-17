# SIGIL Contract Boundaries

This document defines the stable interfaces and fail-closed boundaries for the SIGIL workspace.

## Layer responsibilities

| Layer | Responsibility | What it must not do |
| --- | --- | --- |
| `sigil-core` | Intake, normalization, scan, merge, emit, evidence, receipts, receipt signing, tokenization, tokenizer firewall | IO, network, hidden fallbacks, mutable shared policy state, key material in `Policy` |
| `sigil-mcp` | Inspect tool responses, enforce schema and token budgets, accumulate cross-tool taint | Trust tool output without inspection, widen trust silently |
| `sigil-probe` | Score drift and health, surface SHIELD trigger evidence | Execute model routing, modify core decisions |
| `sigil-multimodal` | Fold modality-specific findings into a single assessment; audit fusion boundaries and derive the authority ceiling; own the `PerceptionAdapter` port and map channels to derived provenance | Let a weaker modality override a stronger one; let derived channels claim first-party authority; let adapters choose provenance |
| `sigil-perception` | Decompose artifacts into text channels (image decode, EXIF inventory, pinned external OCR) | Emit provenance, severities, or verdicts; fetch network resources; execute model calls |
| `sigil-sigstore` | Sigstore keyless signing: OIDC → Fulcio exchange → ephemeral P-384 signatures; optional Rekor upload; offline chain-of-trust + SCT + Rekor verification; upstream bundle interop | Sign without an OIDC identity; widen trust silently; accept a bundle without Rekor tlog evidence |
| `sigil-s` | Produce a parallel semantic verdict and training signal | Downgrade a core deny into allow |
| `sigil-ffi` | Produce `libsigil` (shared artifact) — re-export the `zig_tiktoken_*` C ABI from a Rust-built artifact | Add new ABI surface; change token semantics; thin Rust-side wrappers |
| Bindings | Expose the tokenizer ABI to other languages | Reimplement policy logic or change token semantics |

## Canonical public contracts

The primary public contracts are versioned Rust types and their serialized forms:

- `Policy`
- `SigilOutput`
- `InputAssessment`
- `Verdict`
- `EvidenceBundle`
- `RepresentationReceipt`
- `ReceiptSignature`
- `ReceiptSigner` / `EcdsaP384Signer`
- `ReceiptVerificationOutcome`
- `KeygenOutcome`
- `DsseEnvelope` (in-toto Statement v1 / DSSE)
- `SigstoreKeylessSigner` / `RekorUploadReceipt` (producer upload receipt) / `trust::RekorEntry` (verifier record) / `SigstoreBundle` (sigil-sigstore)
- `TrustRoot` / `verify_bundle_with_trust` / `verify_upstream_bundle` / `verify_inclusion_proof` (sigil-sigstore::trust)
- `trust_root_from_embedded` (sigil-sigstore::tuf)
- `parse_upstream_bundle` (sigil-sigstore — hybrid boundary: `sigstore-types` wire parse → local verify inputs)
- `AudioAdapter` / `ExternalTranscript` (sigil-perception::audio)
- `VideoAdapter` (sigil-perception::video)
- `DocumentAdapter` (sigil-perception::document)
- `SpectralReport` / `analyze_spectrum` (sigil-perception::spectral)
- `detect_rare_patterns` / `detect_slow_rate` (sigil-core::lfdd)
- `SurprisalScorer` / `SelfSurprisalScorer` / `detect_perplexity_anomalies` / `PerplexityReport` / `PerplexityPolicy` (sigil-core::perplexity — scorer supplies signal, kernel policy owns verdict; `Sigil::with_surprisal_scorer`, `run_scan_with_scorer` are the injection points)
- `AttestationVerificationOutcome`
- `McpScanConfig`
- `ServerTrustProfile`
- `McpInspection`
- `McpEvidenceRecord`
- `EvidenceSink` / `JsonlEvidenceSink` (sigil-core::sink, re-exported by sigil-mcp)
- `ProbeConfig`
- `HealthReport`
- `HealthAction`
- `DriftAssessment`
- `MultimodalAssessment`
- `ModalityAssessment`
- `CrossModalAssessment`
- `FusionAssessment` / `FusionRiskKind`
- `AuthorityCeiling`
- `PerceptionAdapter` / `PerceptionReport` / `ExtractedChannel`
- `PerceptionOutcome` (sigil-perception)
- `SentinelVerdict`
- `CompositeVerdict`
- `zig_tiktoken_*` C ABI
- `libsigil` shared-library artifact (`crates/sigil-ffi` shared artifact: same `zig_tiktoken_*` exports + `sigil_version`)
- `sigil.wasm` artifact (`scripts/build_wasm.sh` — wasm32-freestanding reactor, `memory` + `zig_tiktoken_*` exports)

## Contract rules

- Inputs are explicit and immutable by default.
- Outputs are serializable, bounded, and deterministic for a given input and policy.
- Failures must be fail-closed, not silently degraded.
- Evidence must be redacted and bounded.
- A stronger verdict is terminal unless the owning layer explicitly documents a composition rule.
- Compatibility changes are additive unless a safety hazard requires a breaking change.

## Invariants

- Core verdicts are deterministic under repeated runs.
- Invalid UTF-8 is rejected in strict paths and only losslessly contained in monitor-mode byte intake.
- Provenance never collapses across boundaries.
- Sentinel composition cannot weaken a `Deny`.
- MCP and multimodal layers cannot silently broaden trust.
- Reserved tokenizer sentinels and special-token boundary abuse are fail-closed at the tokenizer firewall.
- Python and Go wrappers must preserve token IDs and byte-for-byte decode behavior.
- Zig ABI entrypoints must keep the existing open/encode/decode/special-token contract.

## Verification

The contract is enforced by:

- crate-level attack and property tests
- tokenizer firewall tests for reserved special-token smuggling
- ABI and binding smoke checks
- benchmark regressions
- CI gates for Rust, Zig, Python, and Go surfaces
- the repository contract sync check in `scripts/check_contracts.py`
