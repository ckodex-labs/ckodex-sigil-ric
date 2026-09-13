# RIC — Representation Integrity Specification

**Version:** 0.1.0 (DRAFT)
**Status:** Normative for SIGIL v0.3.x · proposed as a CKODEX-wide admission primitive
**Reference implementation:** SIGIL (`crates/sigil-core`, conformance vectors CV-RIC-001..008)
**Companion documents:** [RIC-CONTRACT.md](./RIC-CONTRACT.md) (SIGIL mapping) · [TRAJECTORY.md](./TRAJECTORY.md) (state)
**Date:** 2026-09-11

---

## 1. Problem statement

A modern AI system rarely consumes what a human or a security control inspected.
Between ingestion and inference, content is decoded, normalized, extracted,
chunked, tokenized, embedded, and fused. Each transformation is performed by a
different interpreter, and none of them is obliged to preserve what the previous
one saw.

The result is a **representation differential**: the representation a policy
approved, the representation a scanner analyzed, and the representation a model
actually consumed can diverge — invisibly. Unicode tag smuggling, OCR-borne
instructions, merge-boundary erosion, and cross-modal instruction formation are
instances of one failure class:

> **An authority decision made over representation R₁ is silently applied to
> representation R₂.**

## 2. Constitutional invariant

> **RIC-INV-001.** No authority-bearing consumer shall interpret, authorize, or
> execute a representation that has not itself passed representation admission.

An approval of representation `R₁` does not confer authority over representation
`R₂` unless a deterministic, evidenced transformation proves the permitted
relationship between them.

## 3. Normative rules

A RIC-conformant system satisfies all eight rules. The right-hand column maps
each rule to its SIGIL enforcement point (the reference implementation).

| Rule | Normative statement (system-agnostic) | SIGIL enforcement |
|---|---|---|
| **RIC-R-1** | Raw input is hashed exactly as received, before any transformation. | `RepresentationReceipt.raw_digest` (SHA-256 over raw segment bytes) |
| **RIC-R-2** | The canonical representation actually consumed is hashed as consumed. | `RepresentationReceipt.canonical_digest` (SHA-256 over the normalized stream) |
| **RIC-R-3** | Every transformation between raw and canonical is named and versioned. | `RepresentationReceipt.normalization` (profile id); per-cluster normalization in intake |
| **RIC-R-4** | The interpreter identity is bound to the admission decision. | `RepresentationReceipt.vocab` (tokenizer identity) |
| **RIC-R-5** | Composition must not merge across provenance boundaries; every crossing or suppression is recorded. | `security_aware_merge` + `MergeBoundary` findings (High when crossings are policy-permitted) |
| **RIC-R-6** | Fusing multiple sources is itself a security event: cross-trust and cross-role composition is audited even when each artifact is individually clean. | `audit_fusion` — `CrossTrustFusion`, `CrossRoleFusion`, `CrossSourceInstructionFormation` |
| **RIC-R-7** | A derived artifact never inherits more authority than its source. | `derived_from` lineage + `DerivedAuthorityEscalation` |
| **RIC-R-8** | Representation uncertainty degrades authority; it never raises it. | `AuthorityCeiling` (`Act < Draft < Observe < Escalate`); restrictive trust composition |

## 4. What conformance means, per boundary

RIC is boundary-scoped. A system is conformant when each boundary below either
enforces the rules or honestly declares non-coverage.

### 4.1 Model-input boundary (implemented in SIGIL)

- Every model-bound token stream carries a receipt binding raw input, canonical
  stream, transformation profile, and interpreter identity.
- Receipts are signed when a signer is attached; verifiers pin the signer's
  verification key.
- Byte-range annotations trace to raw input (no mid-character ranges).

### 4.2 Tool-boundary (specified, not implemented here)

- Tool arguments are admitted as representations in their own right; an
  argument whose bytes differ from the approved representation is denied.
- Human approval binds an immutable intent digest, not conversational prose.

### 4.3 Retrieval boundary (specified, not implemented here)

- Retrieved chunks carry source lineage and representation state; retrieval
  never upgrades source authority.

### 4.4 Agent-to-agent boundary (specified, not implemented here)

- Agent messages are typed envelopes carrying representation state and
  delegation scope; trust does not cross an agent boundary implicitly.

### 4.5 Human-approval boundary (specified, not implemented here)

- The human approves the same semantic object that executes; approval binds a
  digest, and the pre-execution check re-derives and compares it.

## 5. Receipt schema (v1, implemented)

```json
{
  "raw_digest":       "<hex SHA-384 over raw input bytes as received>",
  "canonical_digest": "<hex SHA-384 over the canonical stream as consumed>",
  "digest_algorithm": "sha384",
  "normalization":    "<profile id, e.g. nfc>",
  "vocab":            "<interpreter identity>",
  "token_count":      <usize>,
  "signature": {
    "algorithm":  "ecdsa-p384-sha384",
    "key_id":     "<hex, derived from the verification key>",
    "signature":  "<hex r||s, 96 bytes>"
  }
}
```

Digest mandate: **SHA-384** (aligned with the ECDSA P-384 signature mandate at
192-bit security strength). The `digest_algorithm` field is self-describing and
**signed** — a verifier can recompute digests without assumptions, and a
mislabeled receipt fails signature verification.

Signing message (versioned, deterministic):

```
sigil-receipt-v2|raw=<raw_digest>|canonical=<canonical_digest>|digest=<digest_algorithm>|norm=<normalization>|vocab=<vocab>|tokens=<token_count>
```

Signature algorithm mandate: **ECDSA P-384** (NIST P-384/secp384r1) with
SHA-384 and RFC 6979 deterministic nonces. Verifiers reject any other
algorithm identifier. Verification requires only the receipt, the pinned
hex-encoded verification key (uncompressed SEC1 point), and the message
construction above — no dependency on the producer's code.

**Sigstore keyless:** `--sigstore-keyless` exchanges the ambient OIDC token
(`SIGSTORE_ID_TOKEN`) at Fulcio for a short-lived P-384 certificate; receipts are signed
with the ephemeral key and the certificate chain travels with the signer
(`ReceiptSigner::certificate_chain`). Rekor upload is opt-in. Offline verification of the
Fulcio chain and Rekor inclusion proofs is implemented in
`sigil-sigstore::trust::verify_bundle_with_trust` (RFC 5280 §6 chain validation,
SAN identity, validity window at Rekor integratedTime, Rekor SET, RFC 6962
inclusion proof). TUF root distribution is implemented in
`sigil-sigstore::tuf::trust_root_from_embedded` (loads the production
`trusted_root.json` from `sigstore-trust-root`'s embedded snapshot). Live
integration testing remains.

**Low-frequency deception detection** is implemented in
`sigil-perception::spectral` (subliminal audio + steganography via FFT) and
`sigil-core::lfdd` (rare pattern + cross-input slow-rate detection). The
multimodal kernel's `detect_audio` parses spectral JSON and emits
`SubliminalAudio` / `AudioSteganography` findings. The scan stage's
`run_scan_with_history` integrates cross-input slow-rate detection.
**Key lifecycle:** `sigil-cli keygen` generates a P-384 pair (PKCS#8 private —
OpenSSL-interoperable, written mode 600 — and SPKI public) and reports the key id and
hex verification key to pin. `--signing-key <pem>` attaches the signer to any engine
command, so the generate → sign → verify loop is fully CLI-operable.
**Reference verifier:** `sigil-cli verify-receipt --receipt <json> --key <hex>`
accepts either a bare receipt or a full `SigilOutput` envelope and emits a
structured verdict (`valid`, `algorithm`, `key_id`, and on failure the
verification error). This is the canonical way for third parties to check an
admission receipt without depending on producer code.

## 6. Authority degradation model

| Condition | Maximum authority |
|---|---|
| Clean admission, no fusion events | `Act` |
| Clean admission, fusion events present | `Draft` |
| Flagged input | `Observe` |
| Denied input | `Escalate` (human gate) |

Policy may lower a ceiling; it may never raise one. Derived channels inherit
`min(source authority)`.

## 7. Standards crosswalk

| RIC capability | Anchor |
|---|---|
| Input representation admission | NIST SP 800-53 SI-10 |
| Unicode security / confusables | UTS #39 |
| Normalization forms | UAX #15 |
| Identifier security | UAX #31 |
| Bidirectional text | UAX #9 |
| Source-code spoofing | UTS #55 |
| Prompt injection (incl. invisible content) | OWASP LLM01 |
| Prompt obfuscation (incl. image/metadata channels) | MITRE ATLAS AML.T0068 |

## 8. Implementation status

| Area | Status |
|---|---|
| §4.1 model-input boundary (receipts, signing, boundary findings, fusion audit, authority ceilings) | **implemented** — SIGIL v0.3.x, CV-RIC-001..008 |
| §4.2 tool boundary | specified |
| §4.3 retrieval boundary | specified |
| §4.4 agent-to-agent boundary | specified |
| §4.5 human-approval boundary | specified |
| Multimodal perception (pixels, waveforms, temporal spans) | not implemented — text-extracted channels only |

## 9. Versioning policy

- The receipt schema and signing message are versioned (`sigil-receipt-v1`).
- Additive fields are compatible; changing or removing fields requires a major
  version bump of this specification and a new message version string.
- Conformance is claimable only against the executable vectors; a system that
  cannot run CV-RIC-001..008 (or their equivalents) may not claim RIC
  conformance.
