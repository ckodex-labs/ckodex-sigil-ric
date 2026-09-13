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
| `sigil-sigstore` | Sigstore keyless signing: OIDC → Fulcio exchange → ephemeral P-384 signatures; optional Rekor upload | Sign without an OIDC identity; widen trust silently; verify offline (planned increment) |
| `sigil-s` | Produce a parallel semantic verdict and training signal | Downgrade a core deny into allow |
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
- `SigstoreKeylessSigner` / `RekorEntry` / `SigstoreBundle` (sigil-sigstore)
- `TrustRoot` / `verify_bundle_with_trust` / `verify_inclusion_proof` (sigil-sigstore::trust)
- `trust_root_from_embedded` (sigil-sigstore::tuf)
- `AudioAdapter` / `ExternalTranscript` (sigil-perception::audio)
- `VideoAdapter` (sigil-perception::video)
- `DocumentAdapter` (sigil-perception::document)
- `SpectralReport` / `analyze_spectrum` (sigil-perception::spectral)
- `detect_rare_patterns` / `detect_slow_rate` (sigil-core::lfdd)
- `AttestationVerificationOutcome`
- `McpScanConfig`
- `ServerTrustProfile`
- `McpInspection`
- `McpEvidenceRecord`
- `EvidenceSink` / `JsonlEvidenceSink` (sigil-mcp::sink)
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
