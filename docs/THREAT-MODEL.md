# SIGIL threat model

Repo-grounded model of the security boundary itself — what it admits,
who can attack it, and which controls answer which abuse paths. Pairs
with `THREAT-MAPPING.md` (detector → MITRE refs); this document is the
top-down view, that one is bottom-up.

## Scope and deployment assumptions

In scope: `sigil-core` (intake/scan/verdict kernel), `sigil-cli`
(operator/CI surface), `sigil-perception` (media adapters), `sigil-vt`
(terminal sequences), `sigil-mcp` (tool-call gate), `sigil-multimodal`
(fusion), the signing/evidence plane (`sigil-sigstore`, receipts,
attestation), `sigil-server` (sidecar façade).

Deployment models covered: CLI gate, embedded library, sidecar.

Stated assumptions (correct if wrong):

- **A1** — the attacker controls input bytes only. Policy files,
  signing keys, and the operator environment are trusted. A hostile
  policy (`scan.* = off`) is governance failure, not an attack SIGIL
  detects on itself.
- **A2** — external extractors (ffmpeg, tesseract, pdftoppm, ASR) are
  identity-pinned by SHA-384 but run on hostile bytes. Their own CVEs
  are out of scope for detection; sandboxing them is a recommended
  deployment control, not a shipped one.
- **A3** — the model/tool consumer honours the verdict. SIGIL emits
  `Deny`; enforcement at the consumer is contractual, not technical.

## Trust boundaries

| # | Edge | Crosses |
|---|------|---------|
| B1 | untrusted input → intake | text/stdin/files/MCP payloads/media artifacts enter the pipeline |
| B2 | kernel verdict → consumer | the admitted-representation invariant: *no authority-bearing consumer receives a representation that was not itself admitted* |
| B3 | CLI → pinned external extractors | hostile bytes reach third-party parsers; identity pinned, code unpinned |
| B4 | signing key → receipt → verifier | receipt forgery/substitution path |
| B5 | policy file → detector configuration | operator config shapes what "admitted" means |
| B6 | terminal writer → display/consumer | escape sequences reach a rendering surface |

## Assets

Admitted representations, verdict integrity, signing key material,
evidence-log integrity, downstream model/tool safety, availability of
the scan path itself.

## Attacker capabilities

Arbitrary control over any input surface: text, piped stdin, batch JSON,
MCP tool calls, and media artifacts of any declared modality. Can
compose payloads across channels, encode recursively, and target the
seam between representations (what a human sees vs what the machine
tokenizes). **Non-capabilities** (per A1): cannot modify policy, sign
receipts, or alter the binary at runtime.

## Abuse paths

| # | Path | Detects at | Techniques | Existing controls | Residual / priority |
|---|------|-----------|------------|-------------------|---------------------|
| T1 | Direct injection in text | `injection_grammar`, `perplexity_anomaly` | AML.T0051.000, AML.T0054 | Flag at High; `--fail-on` gates | Novel phrasing evades the phrase table — Medium residual; **high** |
| T2 | Encoded payload (base64/hex/entities, nested ≤2) | `encoded_payload` decode+rescan | AML.T0068, T1027, T1140 | Source-span attribution; quarantine caps (>64 spans / >32 KiB → Low marker) | Encodings beyond the table (rot13 variants, custom alphabets) — **high** |
| T3 | Markup-hidden content (CSS, comments, link targets) | decode surfaces G2 | AML.T0068 | Interior rescan + presence marker | Renderer-faithful hidden content needs a real layout engine — **medium** |
| T4 | Invisible/confusable Unicode | `unicode_control`, `confusable` | AML.T0068, T1027 | Visible rendering in human mode; severity per class | New Unicode blocks drift — **medium** |
| T5 | Indirect injection via media (OCR/audio/subtitle/doc/code channels) | `cross_modal`, per-adapter channels | AML.T0051.001 | Every derived channel is kernel-rescanned, `McpTool` provenance | ASR/OCR mistranscription can hide phrasing — **high** (core thesis) |
| T6 | Render-vs-extract divergence (white-on-white etc.) | `Divergence` channel | AML.T0068 | Word-coverage diff per page, ≤12 pages | OCR quality bounds; capped pages leave >12 unrendered — **medium** |
| T7 | Declared-vs-actual type masquerade | `sniff_modality` routing | T1036 | `sigil.modality_routed` evidence | Unknown magic falls to declared hint — **low** |
| T8 | Terminal escape smuggling | `terminal_escape` | AML.T0068, T1059 | Owned OSC table; unmodelled ops → findings | Unmodelled-sequence findings rely on operator review — **medium** |
| T9 | Split-across-channels composition | fusion `BehavioralCompromise` | AML.T0051.001 | Deny at composition time | Requires each fragment to look benign alone — by design the detector's job — **high** |
| T10 | Swapped tokenizer/vocab/component | `fingerprint_mismatch`, `consistency_shift` | AML.T0010, T1553 | Receipts bind identity | Covers drift, not a malicious-but-consistent component — **medium** |
| T11 | Receipt/evidence forgery | `verify-receipt`, attestation chain | T1553 | ECDSA P-384, Sigstore keyless, evidence JSONL | Unsigned mode has no integrity — by design, documented — **medium** |
| T12 | PII/credential exfil through model channel | `dlp_*` | AML.T0024 | Kind-tagged findings, redact action | Coverage bounded by pattern table — **medium** |
| T13 | Resource exhaustion (huge inputs, decode bombs) | quarantine caps, page/frame caps | — | Bounded decode, MAX_RENDER_PAGES=12, 12-frame cap | No overall input-size cap — a 10 GB file still reads fully; recommended: `--max-input-bytes` — **medium** |
| T14 | Hostile extractor bytes → pinned tool CVE | B3 edge | — | SHA-384 pin proves identity, not safety | Residual: run extractors under sandboxing (seccomp/Seatbelt) — **medium**, conditional on A2 |
| T15 | Policy tampering / detector disable | B5 edge | — | none in-kernel | Operator trust per A1; recommended: policy signing or audit event on load — **low** |

## Control map (mitigations realised)

| ATLAS mitigation | Where it lives |
|---|---|
| AML.M0015 Adversarial Input Detection | every detector — the kernel *is* this control |
| AML.M0020 Generative AI Guardrails | verdict gate between input and consumer (`--fail-on`, `Deny`) |
| AML.M0009 Use Multi-Modal Sensors | `cross_modal` findings + `sigil-multimodal` fusion — multiple modality channels integrated so no single channel is the failure point |
| AML.M0014 Verify AI Artifacts | `fingerprint_mismatch`, `consistency_shift`; receipt-bound identity |
| AML.M0013 Code Signing | ECDSA P-384 receipts, Sigstore keyless, attestation chain |
| AML.M0024 AI Telemetry Logging | `--evidence-log` JSONL, `telemetry` command, `slow_rate_injection` correlation |
| AML.M0029 Human In-the-Loop for AI Agent Actions | `Flag` = admit-with-evidence posture: flagged content gets human review rather than a silent block |
| AML.M0030 Restrict AI Agent Tool Invocation on Untrusted Data | `sigil-mcp` gate — tool calls on untrusted input are inspected before invocation |
| AML.M0033 Input/Output Validation for AI Agent Components | `sigil-mcp` argument validation + derived-channel rescanning |

Emitted per-scan in JSON as `mitigations` (union over fired detectors)
alongside `techniques`.

## Recommended (not shipped)

- **R1** — `--max-input-bytes` cap for T13 (bounded decode exists;
  intake itself is unbounded).
- **R2** — extractor sandboxing guidance/wrappers for T14 (identity is
  pinned; the pinned binary may still have CVEs).
- **R3** — signed/audited policy loads for T15.
- **R4** — `verify-receipt` in the CI gate path: receipts verify, but a
  pipeline that skips verification is trusting an unsigned verdict.
