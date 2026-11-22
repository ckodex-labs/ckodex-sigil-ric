# Receipt fixtures

Signed by the `sigil-cli` binary, never written by hand. One throwaway
ECDSA P-384 key signed all three. Only its public half is kept, in
`signer.pub.hex` as a hex SEC1 point (the repo ignores `*.pem`). Its key id,
the first 8 bytes of SHA-256 over that point, is `030e2a50f70a468f`. The
private key was generated with `sigil-cli keygen` in a scratch directory and
discarded.

| File | Version | Produced by | Command |
|---|---|---|---|
| `v2_tokenize.json` | 2 | `sigil-cli` at 52dbd81 (before receipt v4) | `tokenize --text "Q3 revenue by region"` |
| `v4_tokenize.json` | 4 | `sigil-cli` with receipt v4 (RIC-MM-001 WP5) | same |
| `v4_perceive_qwen.json` | 4 | same | `perceive --input tests/fixtures/multimodal/attack_source.png --profile qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow --analyze --ocr-binary tesseract --ocr-args "stdin - --psm 6"`, the vision receipt |

All commands ran with `--format json --signing-key <key>`. The perceive
receipt's `consumed.extractor` is the identity digest of the Tesseract 5.5.4
binary on the machine that made it. It is recorded, not recomputed, so the
fixture verifies anywhere.

There is no v3 fixture. Receipt v3 belongs to the remediation line
(remediation/2026-11-21), which is not in this repository.
