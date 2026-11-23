# Receipt fixtures

Signed by the `sigil-cli` binary, never written by hand. Each throwaway
ECDSA P-384 key was generated with `sigil-cli keygen` in a scratch directory
and discarded after signing. Only the public halves are kept, as hex SEC1
points (the repo ignores `*.pem`). A key id is the first 8 bytes of SHA-256
over that point.

| Key file | Key id | Signed |
|---|---|---|
| `v2_signer.pub.hex` | `030e2a50f70a468f` | `v2_tokenize.json` |
| `signer.pub.hex` | `5e0130e860604ae5` | `v4_tokenize.json`, `v4_perceive_qwen.json` |

| File | Version | Produced by | Command |
|---|---|---|---|
| `v2_tokenize.json` | 2 | `sigil-cli` at 52dbd81 (before receipt v4) | `tokenize --text "Q3 revenue by region"` |
| `v4_tokenize.json` | 4 | `sigil-cli` with receipt v4 and the WP6 interpreter field | same |
| `v4_perceive_qwen.json` | 4 | same | `perceive --input tests/fixtures/multimodal/attack_source.png --profile qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow --vlm-assets .ref-models/qwen2-vl-2b --delivery engine-processed --analyze --ocr-binary tesseract --ocr-args "stdin - --psm 6"`, the vision receipt |

All commands ran with `--format json --signing-key <key>`. The perceive
receipt's `consumed.extractor` is the identity digest of the Tesseract 5.5.4
binary on the machine that made it. It is recorded, not recomputed, so the
fixture verifies anywhere.

The v4 fixtures were regenerated in RIC-MM-001 WP6, when `consumed` gained
`interpreter`, and again on 2026-11-23, when it gained `delivery` (decision
O-5), with a new throwaway key. Receipt v4 had not left the mission branch.

There is no v3 fixture. Receipt v3 belongs to the remediation line
(remediation/2026-11-21), which is not in this repository.
