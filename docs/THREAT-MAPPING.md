# Threat mapping — MITRE ATLAS + ATT&CK

Each SIGIL detector maps to the adversary techniques its findings
represent. **Source of truth is code**: `DetectorId::techniques()` in
`crates/sigil-core/src/types.rs`; this table is the human-readable copy —
keep them in sync.

`scan`/`tokenize` JSON output carries the deduplicated union of fired
detectors' references in a top-level `techniques` array, so a SIEM or
reviewer can consume the verdict without re-deriving the mapping.

## Detector → technique

| Detector | ATLAS | ATT&CK | Why |
|---|---|---|---|
| `injection_grammar` | AML.T0051, AML.T0054 | — | Instruction-override phrasing ("ignore previous instructions") is verbatim prompt injection; ATLAS splits jailbreak (safety-alignment bypass) from injection, so the grammar table carries both. |
| `unicode_control` | AML.T0068 | T1027 | Invisible/bidi code points hide content from human review while the machine sees it — T0068 names this exactly. |
| `confusable` | AML.T0068 | T1027 | Lookalike glyphs — the human-visible and machine-consumed sequences diverge. |
| `dlp_*` | AML.T0024 | — | PII/credential material leaving through the inference channel. |
| `entropy_spike` | AML.T0068 | T1027 | High-entropy windows mark likely encoded/encrypted payloads. |
| `token_smuggling` | AML.T0068 | T1027 | Subword-boundary evasion of pattern filters. |
| `merge_boundary` | AML.T0068 | T1027 | Token-merge seams hide split payloads. |
| `cross_modal` | AML.T0051.001 | — | An instruction arriving via a second channel is *indirect* injection by definition. |
| `schema_violation` | — | — | Malformed input shape; integrity finding, no clean technique fit. |
| `fingerprint_mismatch`, `consistency_shift` | AML.T0048 | T1553 | A swapped tokenizer/model/component behaving differently is the supply-chain surface; receipts exist to defeat trust-control subversion. |
| `subliminal_audio`, `audio_steganography` | AML.T0068 | T1027 | Instructions hidden in the signal itself — T0068 covers "in the pixels/data". |
| `rare_pattern` | AML.T0068 | T1027 | Rare-token sequences as carrier signals. |
| `slow_rate_injection` | AML.T0051 | — | Low-and-slow injection spread across a session. |
| `perplexity_anomaly` | AML.T0054 | — | Perplexity-outlier text is the jailbreak-prompt signal. |
| `terminal_escape` | AML.T0068 | T1059 | Control sequences are command-level constructs smuggled through a text channel. |
| `encoded_payload` | AML.T0068 | T1027, T1140 | Base64/hex/entity-encoded payloads — T0068 names "encoding scheme such as base64" verbatim; T1140 covers the decode step the payload relies on. |

## Surface → technique (cross-cutting)

| Surface | Techniques | PoC case |
|---|---|---|
| Multimodal composition (`Deny{BehavioralCompromise}`) | AML.T0051.001 | POC-CASES case 3 — instruction split across channels, benign individually |
| Render-vs-extract divergence (`ChannelKind::Divergence`) | AML.T0068 | case 4 — white-on-white PDF instruction invisible to the render |
| Declared-vs-magic modality routing | T1036 | `--modality image` on an MP4 routes to video + `sigil.modality_routed` evidence |
| Subtitle/caption tracks | AML.T0051.001, AML.T0068 | G6 — a caption the container inventory never counted |
| Frame-painted instructions | AML.T0068 | case 5 — instruction exists only in video pixels |
| Comment/string channels in code | AML.T0051.001 | case 6 — reaches the model, never the compiler |
| Receipts/attestation signing | defeats T1553 | keygen → signed scan → verify-receipt |

## Notes

- ATLAS sub-techniques used: `AML.T0051.001` (Indirect) — `.000` Direct
  and `.002` Triggered are subsumed under the parent in the table above.
- `AML.T0048` (ML supply chain compromise), not `AML.T0040` (inference
  API access), is the correct supply-chain ID.
- A finding tagged with a technique means "the adversary's technique
  that would produce this artefact" — the mapping describes the attack,
  not the control.
