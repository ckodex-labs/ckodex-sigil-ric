# RIC-MM-001 open items

The single list of what is not done, who can close it, and what closes it.
Reports say what changed here; they do not restate it. Updated 2026-11-22.

Status: **open** (work remains), **blocked** (needs something outside this
repository), **decision** (needs a human choice), **accepted** (a stated
limit by design, kept visible), **closed** (with the commit that closed it).

## Needs a file or a decision from the owner

| ID | Item | Status | What closes it |
|---|---|---|---|
| O-1 | Transcript divergence (CV-RIC-030, second half) is untested: no ASR runs here. | blocked | sherpa-onnx and `sherpa-onnx-whisper-tiny.en` installed, with `SIGIL_REF_MODELS` set (`scripts/reference/README.md`). Then run the audio specimen under both audio profiles with `scripts/reference/whisper-stdin` as the transcript binary. |
| O-2 | The GloVe scores in RIC §4.3 (0.757 vs 0.768) are cited, not reproduced. | blocked | `glove-wiki-gigaword-100` in `SIGIL_REF_MODELS`; then add the GloVe probes to a reference fixture via `scripts/reference/embeddings.py`. |
| O-3 | Benign rates on real media are unmeasured (D5): divergence and caps on real photos, screenshots and charts, including downscaled views. | blocked | A licensed set of benign images and audio. Six Quick Look renders of repo documents gave no divergence, but at near-source size. |
| O-4 | Document inputs are not capped (ADR-001 derogation). | decision | Approve the derogation, or cap documents like images. Recommendation: cap them; a PDF rendered for a vision model reaches it as pixels. |
| O-5 | Parity label when SIGIL itself produces the consumed representation (D6). | decision | Choose one of the three options in ADR-001. |
| O-6 | Qwen2-VL upstream licence text not read: Apache-2.0 per the model card only (`assets/qwen2-vl-2b/PROVENANCE.md`). | blocked | Read `Qwen/Qwen2-VL-2B`'s licence, or approve fetching it. |
| O-7 | M4 moves public contracts (kernel I/O behind adapters; sigil-tokenizer extraction). | decision | Approve an ADR before work starts. |
| O-8 | The `whisper/16k-filtered` view is approximate: the specimen's ffmpeg hash (`631d7c57…`) is not reproduced by ffmpeg 9.0.2. | blocked | The ffmpeg version that produced the specimen. If it reproduces with that version, pin it and mark the profile reference-matched. |

## Outside this repository

| ID | Item | Status | What closes it |
|---|---|---|---|
| O-9 | Receipt v3 compatibility is untested; RIC-SPEC 0.3.0 is reserved. The remediation line (`remediation/2026-11-21`, a34e8cf) is not in the repository or on origin. | blocked | The branch. Then add its v3 message to `crates/sigil-core/src/receipt.rs` and a v3 fixture signed by its binary. |
| O-10 | The Pillow 13 bicubic pass-order rule was observed on 360 sizes, not read from Pillow's source. Where neither order is known, the view is approximate. | blocked | Approval to fetch Pillow 13's `Resample.c`. |

## Work for the implementer

| ID | Item | Status | What closes it |
|---|---|---|---|
| O-11 | 51 functions exceed 50 lines (M3). Largest: `cli::run::dispatch` 384, `MultimodalEngine::analyze` 139 (it grew in WP5 and WP7), `detect_dlp` 136, `detect_perplexity_anomalies` 133, `ProbeEngine::analyze` 129. | open | Decompose, behaviour checked against captured output, as `perceive_command` was in 9c5eb09. |

## Accepted limits

| ID | Item | Why it stays |
|---|---|---|
| A-1 | Retrieved chunks sent over the API cannot carry a retrieval assessment, so they always cap at observe. | A caller cannot prove SIGIL assessed a chunk; accepting the claim would let the wire raise authority (RIC-RET-3). |
| A-2 | Media inputs sent over the API cannot carry parity, so they always cap at observe. | Same reason, RIC-R-8. |
| A-3 | A payload printed visibly with its words together in the source does not raise divergence. | A human then sees it, and the source OCR channel carries it to the scan. |

## Verified this round

The full Dagger verify lane (`dagger run cargo run --manifest-path
ci/Cargo.toml -- all`) passed on 2026-11-22 at a676e62: contracts, fmt,
Zig build, clippy then `cargo test --workspace` in `rust:1.88-bookworm`,
coverage, and reports. Workspace line coverage: 89.40 % (16,620 of 18,590
lines, `cargo llvm-cov`, gate 80 %).

## Closed in this round

| Item | Commit |
|---|---|
| `commands.rs` (928 lines) and `types.rs` (620) over the file limit; `perceive_command` a 326-line function | 9c5eb09, a7afabf |
| `whisper/16k-filtered` had no implementation | f9f39b1 |
| DEV-5: media receipts could not be attested | 0d584d4 |
| The full Qwen2-VL request ID stream was library-only | 8a4bb31 |
| Word-coverage divergence could be suppressed by scattering the payload's words | 332bacd |
| The divergence window check cost O(lines x source words) (security review of 332bacd) | 8ad98ba |
| The CI image lacked Tesseract and ffmpeg; the Dagger test lane now passes with both (rust:1.88-bookworm) | a676e62 |
