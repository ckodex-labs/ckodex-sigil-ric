# Qwen2-VL-2B reference files

SIGIL's Qwen2-VL interpreter (RIC-MM-001 WP6, `crates/sigil-perception/src/vlm`)
reads a tokenizer, chat template, processor config and model config to emit the
exact Qwen2-VL request ID stream. We used these files from
[`mlx-community/Qwen2-VL-2B-4bit`](https://huggingface.co/mlx-community/Qwen2-VL-2B-4bit/tree/949a35dce2ee94a3337551e02051ab00dde3e3b4)
to conduct our tests. SIGIL does not redistribute them: neither the repository
nor any release contains them, and no weights are used at all.

To run the tests, fetch them from the original repository at the pinned
revision:

    scripts/reference/fetch_qwen2vl_assets.sh        # into .ref-models/qwen2-vl-2b (gitignored)

or point `SIGIL_QWEN2VL_ASSETS` at a directory that holds them. To use the
interpreter, pass that directory to `sigil-cli perceive --vlm-assets` or
`sigil-cli vlm-request --vlm-assets`.

| Field | Value |
|---|---|
| Source | `https://huggingface.co/mlx-community/Qwen2-VL-2B-4bit` |
| Revision | `949a35dce2ee94a3337551e02051ab00dde3e3b4` |
| Fetched | 2026-11-21, by the repository owner with `hf download` (huggingface_hub 1.19.0) |
| Upstream | `Qwen/Qwen2-VL-2B` (base model, not Instruct), converted with mlx-vlm 0.0.13, per the model card |
| Licence | Apache-2.0, per the model card's front matter. The files stay under their own licence and are fetched from the original repository by whoever runs the tests; SIGIL does not redistribute them. |

| File | SHA-384 | Pinned in code |
|---|---|---|
| `tokenizer.json` | `30aedba44ef99e56dd9ed1b3d87639bcf53a3b340f1141ce31c7f8b8614f19c38a0b4012f05cd95d0f4e10178d5bb876` | yes |
| `chat_template.json` | `f5a8f61b5506abec91df2b22d5ce7831ecb3839a6dc8295cc05b33f60f04f6db696b4aaaeec0228ffb356f3609579237` | yes |
| `preprocessor_config.json` | `4ec0b01c8eeb212bca1510da729737625a3ee0374ac0ad3ba4f384f5351997b67a464853625cfe3678ef55612530c082` | yes |
| `config.json` | `997410891ba417414080c97d7a11394c2424dbb37e501786c951000d5d6c3c5a40e8ac4820074ae0352369bb694d122f` | yes |
| `README.md` (model card) | `3cf9f08d4c58c337d41e02687ba824ee20065d51bcbda557e7c8fa7774f19ed3a2b1e257cd36d395fb35b604967b8140` | no (licence record only) |

The pins live in `QWEN2_VL_2B` (`crates/sigil-perception/src/vlm/qwen2vl.rs`).
A file whose digest differs does not load.

What the files declare, and SIGIL checks:

- `preprocessor_config.json`: `Qwen2VLImageProcessor`, patch 14, temporal
  patch 2, merge 2, min_pixels 3136, max_pixels 12845056, bicubic (3), the
  CLIP mean and std. These equal the
  `qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow` profile, which
  was set from `Qwen/Qwen2-VL-7B-Instruct`'s config.
- `config.json`: vision_start 151652, vision_end 151653, image_pad 151655,
  which equal the tokenizer's added tokens.
- `chat_template.json`: the base-model template. It has no roles: an image
  renders `<|vision_start|><|image_pad|><|vision_end|>`, and text renders
  as itself.
