# RIC — Representation Integrity Contract (for SIGIL)

**Status:** Normative for SIGIL v0.3.x
**Relation:** RIC defines *what* representation integrity means; SIGIL enforces it at the
lexical boundary. Companion analysis: [RIC-DELTA-ANALYSIS.md](./RIC-DELTA-ANALYSIS.md).
**Date:** 2026-09-11

---

## 1. Constitutional invariant

> **RIC-INV-001.** No authority-bearing consumer shall interpret, authorize, or execute a
> representation that has not itself passed representation admission.

An approval of representation `R1` does not confer authority over representation `R2`
unless a deterministic, evidenced transformation proves the permitted relationship
between them.

## 2. Normative rules (implemented in this workspace)

| Rule | Statement | Implementation |
|---|---|---|
| **RIC-R-1** | Raw input is hashed as received, before any normalization. | `RepresentationReceipt.raw_digest` — SHA-384 over concatenated raw segment bytes (engine.rs). |
| **RIC-R-2** | The canonical stream actually tokenized is hashed as consumed. | `RepresentationReceipt.canonical_digest` — SHA-384 over the normalized grapheme stream. |
| **RIC-R-3** | The transformation between raw and canonical is named and versioned. | `RepresentationReceipt.normalization` — normalization profile id (`nfc`/`nfkc`/`none`). |
| **RIC-R-4** | The tokenizer identity is bound to the admission decision. | `RepresentationReceipt.vocab` — vocabulary identity the canonical stream was encoded against. |
| **RIC-R-5** | Tokenization must not merge across provenance boundaries; every suppression is recorded. | `security_aware_merge` splits encoding groups at provenance changes and emits `DetectorId::MergeBoundary` findings with the boundary provenance/trust pair. |
| **RIC-R-6** | Fusion of multiple channels is itself audited: cross-trust and cross-role composition are security events even when each artifact is individually clean. | `audit_fusion` in sigil-multimodal — `CrossTrustFusion`, `CrossRoleFusion`, `CrossSourceInstructionFormation`. |
| **RIC-R-7** | A derived channel (OCR/ASR/transcript) never inherits first-party authority. | `ModalInput.derived_from` + `DerivedAuthorityEscalation` event when a derived channel claims `User`/`System` provenance. |
| **RIC-R-8** | Representation uncertainty degrades authority; it never raises it. | `AuthorityCeiling` (`Act < Draft < Observe < Escalate`) derived from verdict + fusion events; trust composition is restrictive (`combine_trust` = min). |

## 3. Known deviations (tracked, not hidden)

| ID | Deviation | Reason | Tracking |
|---|---|---|---|
| ~~DEV-1~~ | ~~EvidenceBundle remains lazy (non-`Allow` verdicts only)~~ **RESOLVED**: `emit.evidence_mode` is now policy-gated — `non-allow` (default, preserves INV-006 laziness) or `always` (attests every admission, including Allow, bound to the same receipt). Pinned by CV-RIC-007. | — | Closed. |
| ~~DEV-2~~ | ~~Byte ranges reference the normalized segment text, not the raw bytes~~ **RESOLVED**: intake segments raw text per cluster and normalizes each cluster individually; token ranges are remapped onto raw cluster ranges (`try_encode_graphemes`). Pinned by CV-RIC-005. | — | Closed. |
| DEV-3 | Receipts are signed via the `ReceiptSigner` port with the **ECDSA P-384** reference adapter (NIST P-384/secp384r1, SHA-384, RFC 6979 deterministic nonces; signed message is the versioned canonical receipt content). **Remaining:** Sigstore keyless / in-toto integration and CLI key-file handling are future adapters of the same port. | Key management is a deployment concern; the port keeps it out of `Policy`. | ECDSA P-384 done (CV-RIC-008); Sigstore/in-toto tracked to milestone M7. |
| DEV-4 | Multimodal channels are text-extracted (`content: &str`); no pixel/waveform decoding. | SIGIL attests text-extracted channels honestly; media decoding is out of scope for a lexical security library. | Deferred to a perception-adapter layer. |

## 4. Consumer obligations

A consumer that forwards SIGIL output to a model must:

1. Carry the `RepresentationReceipt` alongside the token stream (it is part of
   `SigilOutput`, serialized with it).
2. Treat `AuthorityCeiling::Escalate` as a hard human gate — no tool execution.
3. Treat `AuthorityCeiling::Observe` as read-only for any authority-bearing action.
4. Never reconstruct model input from sources other than the admitted canonical stream
   without a new admission pass.
