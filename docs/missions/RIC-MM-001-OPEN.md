# RIC-MM-001 open items

The single list of what is not done, who can close it, and what closes it.
Reports say what changed here; they do not restate it. Updated 2026-11-23,
at the mission's close-out for release 0.4.0.

Status: **open** (work remains), **blocked** (needs something outside this
repository), **decision** (needs a human choice), **accepted** (a stated
limit by design, kept visible), **closed** (with the commit that closed it).

Every item the previous version listed is now closed or accepted. Nothing is
open.

## Items

| ID | Item | Status | How it closed |
|---|---|---|---|
| O-1 | Transcript divergence (CV-RIC-030, second half) untested: no ASR | closed, a0f4af1 | Run with sherpa-onnx 1.12.40 and whisper tiny.en: the hidden instruction appears only in the decimated view's transcript and is a HIGH divergence; the filtered view's transcript is benign (`specimens.json`, `after`) |
| O-2 | GloVe scores in RIC §4.3 cited, not reproduced | closed, 8e5e580 | `embeddings.py` with the published vectors gives 0.757 and 0.768; `embedding_probes.json` (scores and the vectors' SHA-384, no vectors) |
| O-3 | Benign rates on real media unmeasured (D5) | closed, 3685897, fc7b916 | 24 Kodak photographs and 3 LibriSpeech clips, `docs/measurements/BENIGN-2026-11.md`. The run exposed three false-positive sources, all fixed: the baseline-free n-gram detector (now opt-in), the legacy audio detectors (5 % energy floor), and the spectral report lexed as language (now a facts channel). One limit remains, A-4 |
| O-4 | Document inputs not capped | closed, bd11864 | Owner decision: capped like images (RIC-R-8) |
| O-5 | Parity label when SIGIL produces the consumed representation (D6) | closed, bd11864 | Owner decision: a separate signed `delivery` field in receipt v4; it never raises authority |
| O-6 | Qwen2-VL files redistributed under an unread licence | closed, bc903a6 | Owner decision: not redistributed. Removed from the unpushed history; fetched from the original repository at the pinned revision for tests (`docs/reference-models/QWEN2-VL-2B.md`) |
| O-7 | M4 moves public contracts | closed (decided), dcc5526 | Owner decision: ADR now, code in 0.5. ADR-002 is proposed |
| O-8 | `whisper/16k-filtered` approximate; specimen ffmpeg hash not reproduced | accepted, A-5 | 15 ffmpeg builds (4.2.7 to 9.0.2) give two outputs, neither the specimen's (`docs/reference-models/FFMPEG-16K.md`, da85db3) |
| O-9 | Receipt v3 untested; remediation line absent | accepted, A-6 | No local repository or remote holds a34e8cf or the branch (searched 2026-11-23). v3 stays reserved and is rejected as `UnsupportedVersion(3)` |
| O-10 | Pillow 13 pass order observed, not read | closed, 0d902e2 | Read from Pillow 13.0.0's `Resample.c`; checked on both sides of the boundary. Bicubic views keep their parity for every size |
| O-11 | 51 functions over 50 lines (M3) | closed, 4c52a00, 2c1f216, 340846b, 4667f44, 1c78cea | All split, behaviour checked by differential capture per crate; clippy `too_many_lines` is now denied at 50 |

## Accepted limits

| ID | Item | Why it stays |
|---|---|---|
| A-1 | Retrieved chunks sent over the API cannot carry a retrieval assessment, so they always cap at observe. | A caller cannot prove SIGIL assessed a chunk; accepting the claim would let the wire raise authority (RIC-RET-3). |
| A-2 | Media inputs sent over the API cannot carry parity, so they always cap at observe. | Same reason, RIC-R-8. |
| A-3 | A payload printed visibly with its words together in the source does not raise divergence. | A human then sees it, and the source OCR channel carries it to the scan. |
| A-4 | OCR noise on photographs is a LOW divergence: 22 of 24 benign photographs flagged under the Qwen2-VL view, 18 under nearest-80. | Fails closed. Owner decision: ship 0.4.0 and fix in 0.4.1 by gating OCR lines on Tesseract word confidence, calibrated on a larger set. |
| A-5 | `whisper/16k-filtered` stays approximate. | ffmpeg's output is version-specific and the transform tag binds the binary; reference-matched needs a parity vector against Whisper's `load_audio` with the same binary (0.5). |
| A-6 | No receipt v3. | The line that defined it does not exist anywhere reachable. |

## Mission close-out (definition of done, RIC-MM-001.md §4)

- `specimens.json` has an `after` block produced by the binary (a0f4af1,
  `scripts/specimens_after.sh`).
- RIC-SPEC §8 states what is implemented and what is not (a0f4af1).
- The QA scorecard and the contract check pass.
- The ledger entry the mission asks for in `docs/REMEDIATION-2026-11-21.md`
  is this file: that document belongs to the remediation line, which is not
  in this repository (A-6).

## Also fixed during close-out

| Item | Commit |
|---|---|
| A pinned tool's spawn failed on `ETXTBSY` when a sibling test thread forked mid-write (one Dagger run in five) | 0c4e755 |
| The Qwen2-VL fetch script was committed without its executable bit; both Dagger test lanes failed before running | 97f20cd |
| Releases were notes-only; now signed archives, SBOM, SLSA provenance, Sigstore bundles | cdce4d1, 02fcbe7 |
| README, security and contribution policies, issue and PR templates | 9c3431c |

## Closed in the previous round

| Item | Commit |
|---|---|
| `commands.rs` (928 lines) and `types.rs` (620) over the file limit; `perceive_command` a 326-line function | 4aa6f9a, 781c83d |
| `whisper/16k-filtered` had no implementation | d1dbffb |
| DEV-5: media receipts could not be attested | b549243 |
| The full Qwen2-VL request ID stream was library-only | 51e92ef |
| Word-coverage divergence could be suppressed by scattering the payload's words | bc847ec |
| The divergence window check cost O(lines x source words) | 5b147d4 |
| The CI image lacked Tesseract and ffmpeg | faffb13 |
