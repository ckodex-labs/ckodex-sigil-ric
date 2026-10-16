# Representation integrity contract for SIGIL

**Status:** Normative for SIGIL v0.3.x
**Relation:** RIC defines what representation integrity means; SIGIL enforces it at the lexical boundary. Companion analysis: [RIC-DELTA-ANALYSIS.md](./RIC-DELTA-ANALYSIS.md).
**Date:** 2026-09-11

---

## 1. Constitutional invariant

> **RIC-INV-001.** No authority-bearing consumer shall interpret, authorize, or execute a representation that has not itself passed representation admission.

An approval of representation `R1` does not confer authority over representation `R2` unless a deterministic, evidenced transformation proves the permitted relationship between them.

## 2. Normative rules implemented in this workspace

| Rule | Statement | Implementation |
|---|---|---|
| **RIC-R-1** | Raw input is hashed as received, before any normalization. | `RepresentationReceipt.raw_digest`: SHA-384 over concatenated raw segment bytes in engine.rs. |
| **RIC-R-2** | The canonical stream actually tokenized is hashed as consumed. | `RepresentationReceipt.canonical_digest`: SHA-384 over the normalized grapheme stream. |
| **RIC-R-3** | The transformation between raw and canonical is named and versioned. | `RepresentationReceipt.normalization`: normalization profile id `nfc`, `nfkc`, or `none`. |
| **RIC-R-4** | The tokenizer identity is bound to the admission decision. | `RepresentationReceipt.vocab`: vocabulary identity the canonical stream was encoded against. |
| **RIC-R-5** | Tokenization must not merge across provenance boundaries; every suppression is recorded. | `security_aware_merge` splits encoding groups at provenance changes and emits `DetectorId::MergeBoundary` findings with the boundary provenance and trust pair. |
| **RIC-R-6** | Fusion of multiple channels is itself audited: cross-trust and cross-role composition are security events even when each artifact is individually clean. | `audit_fusion` in sigil-multimodal: `CrossTrustFusion`, `CrossRoleFusion`, `CrossSourceInstructionFormation`. |
| **RIC-R-7** | A derived channel such as OCR, ASR, or transcript never inherits first-party authority. | `ModalInput.derived_from` plus `DerivedAuthorityEscalation` event when a derived channel claims `User` or `System` provenance. |
| **RIC-R-8** | Representation uncertainty degrades authority; it never raises it. | `AuthorityCeiling` with lattice `Escalate < Observe < Draft < Act` derived from verdict plus fusion events; trust composition is restrictive with `combine_trust` equal to minimum. |
| **RIC-R-9** | Autonomous delegation leases must strictly attenuate granted capabilities. | `sigil_core::delegation::is_attenuated` checks that every child capability is covered by a parent grant. |
| **RIC-R-10** | Delegated authority ceilings must decrease or maintain standing. | `AuthorityCeiling::permits` enforces child ceiling is less than or equal to parent ceiling. |
| **RIC-R-11** | Delegation depth and validity windows are strictly bounded. | `validate_chain` enforces child depth does not exceed max depth and child expiration does not exceed parent expiration. |
| **RIC-R-12** | Agent task envelopes bind the active capability lease to the admitted representation receipt. | `validate_envelope` enforces exact match between lease representation digest and receipt canonical digest. |

## 3. Known deviations tracked and open

| ID | Deviation | Reason | Tracking |
|---|---|---|---|
| DEV-1 | EvidenceBundle remains lazy for non-Allow verdicts only. Resolved: `emit.evidence_mode` is policy-gated to `non-allow` as default or `always` to attest every admission bound to the same receipt. Pinned by CV-RIC-007. | Closed. | Resolved. |
| DEV-2 | Byte ranges reference the normalized segment text, not raw bytes. Resolved: intake segments raw text per cluster and normalizes each cluster individually; token ranges are remapped onto raw cluster ranges in `try_encode_graphemes`. Pinned by CV-RIC-005. | Closed. | Resolved. |
| DEV-3 | Receipts are signed via the `ReceiptSigner` port with the ECDSA P-384 reference adapter using NIST P-384, SHA-384, RFC 6979 deterministic nonces; signed message is the versioned canonical receipt content. Remaining work: Sigstore keyless in-toto integration and CLI key-file handling are future adapters of the same port. | Key management is a deployment concern; the port keeps it out of `Policy`. | ECDSA P-384 done in CV-RIC-008; Sigstore and in-toto tracked to milestone M7. |
| DEV-4 | Multimodal channels are text-extracted with `content: &str`; no raw pixel or waveform decoding. | SIGIL attests text-extracted channels honestly; media decoding is handled by dedicated perception adapters. | Resolved in `sigil-perception` crate. |

## 4. Consumer obligations

A consumer that forwards SIGIL output to a model must:

1. Carry the `RepresentationReceipt` alongside the token stream as part of `SigilOutput` serialized with it.
2. Treat `AuthorityCeiling::Escalate` as a hard human gate with no tool execution.
3. Treat `AuthorityCeiling::Observe` as read-only for any authority-bearing action.
4. Never reconstruct model input from sources other than the admitted canonical stream without a new admission pass.
