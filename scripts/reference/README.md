# Reference generators (not product code)

These scripts produce the golden specimens and reference values in
`tests/fixtures/multimodal/`. They are Python only because the reference
implementations they reproduce are Python (Pillow, transformers, sherpa-onnx).
Nothing here is on SIGIL's admission path, and no Rust test may shell out to them.

Pinned environment used on 2026-11-21:

| Component | Version / source |
|---|---|
| Python | 3.13 |
| Pillow | 13.0.0 (the reference hashes were made with it; 12.x orders bicubic passes differently, see docs/ADR-001) |
| transformers | 4.57.6 (`Qwen2VLImageProcessor`, slow PIL path). 5.x needs torchvision and uses a different (fast) resize path: measure it separately, do not assume parity |
| Qwen2-VL settings | `Qwen/Qwen2-VL-7B-Instruct` `preprocessor_config.json`: min_pixels 3136, max_pixels 12845056, patch 14, temporal 2, merge 2 |
| sherpa-onnx | 1.12.40 (2.0.x dropped the espeak frontend used by Piper VITS) |
| ASR | `sherpa-onnx-whisper-tiny.en` (k2-fsa/sherpa-onnx GitHub release `asr-models`) |
| TTS | `vits-piper-en_US-lessac-medium` (k2-fsa/sherpa-onnx GitHub release `tts-models`) |
| GloVe | `glove-wiki-gigaword-100` (RaRe-Technologies/gensim-data GitHub release) |
| Whisper mel filters | `openai/whisper` `whisper/assets/mel_filters.npz` |
| OCR | Tesseract 5.3.4, `--psm 6` |
| ffmpeg | the 16 kHz reference path uses `ffmpeg -ar 16000 -ac 1` |

Set `SIGIL_REF_MODELS` to the directory holding the unpacked model folders.
Run from the repository root.

| Script | Produces |
|---|---|
| `make_image_specimen.py` | `attack_source.png` (640², payload on the nearest-×8 sampling grid), nearest and bicubic 80² views |
| `qwen2vl_view.py` | the exact 644² pixels Qwen2-VL's processor feeds the vision encoder (inverted from `pixel_values`), grid and placeholder counts |
| `tts.py`, `make_audio_specimen.py` | benign + hidden speech; hidden band-limited to 7.5 kHz and SSB-shifted +32 kHz into a 96 kHz WAV |
| `whisper-stdin` | ASR adapter for `sigil-cli perceive --transcript-binary`; argv[1] = `ffmpeg` or `naive` resample path |
| `whisper_logmel.py` | spectrograms and Whisper 80-bin log-mel (same maths as `whisper/audio.py`) |
| `pillow_parity.py` | `pillow_parity.json`: Pillow 13.0.0 bicubic and nearest hashes over 21 sizes, for the Rust resampler |
| `qwen2vl_ids.py` | `qwen2vl_ids.json`: Qwen2-VL text and request ID streams from `.ref-models/qwen2-vl-2b` (`fetch_qwen2vl_assets.sh`), made by `tokenizers` 0.22.2 and transformers 5.12.1 (`Qwen2VLProcessor.replace_image_token`) under the system Python 3.11. It needs no pixels, so 5.x's resize path does not apply |
| `embeddings.py` | Whisper tiny.en decoder embedding rows, GloVe mean-pooled filter scores; the scores (no vectors) are kept in `embedding_probes.json` |
