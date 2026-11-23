# ffmpeg's 16 kHz path and the `whisper/16k-filtered` view (O-8)

`whisper/16k-filtered` reproduces Whisper's `load_audio`: ffmpeg resamples
the input to 16 kHz mono int16. SIGIL runs a digest-pinned ffmpeg with the fixed
command `-loglevel error -i pipe:0 -f s16le -ac 1 -ar 16000 pipe:1` and binds
the binary's digest in the view's transform tag (`ffmpeg-s16le:<sha384>`).

The audio specimen (`tests/fixtures/multimodal/specimens.json`,
`audio.waveform_16k_sha384.ffmpeg`) records `631d7c57…` as the reference
digest. Its generating code is not in the repository, and no ffmpeg build
tested reproduces it.

## Sweep (2026-11-23, `scripts/reference/ffmpeg_16k_sweep.sh`, linux/arm64 under Dagger, plus the host)

The specimen `attack_96k.wav` through the fixed command, 136,077 samples each.
Each output was hashed as int16 bytes, as float32 (`x / 32768`, Whisper's
conversion) and as float64; none of the three equals `631d7c57…`.

| ffmpeg | Builds | SHA-384 of the s16le output |
|---|---|---|
| 4.2.7, 4.4.2, 5.0.3, 5.1.9, 6.0, 6.0.1 | Ubuntu 20.04 and 22.04, Alpine 3.16 and 3.18, Debian 12, static 6.0 | `076c24aa9193453283702f2560fcfaac6d222a33aae9fdc82b2bbd04f0d0a57d4e484de3ab74e1de2fc24d32af20eb23` |
| 6.1.1, 6.1.2, 7.0.2, 7.1, 7.1.5, 8.0, 9.0.2 | Ubuntu 24.04, Alpine 3.20 and 3.22, Debian 13, static 6.1.1 to 8.0, Homebrew 9.0.2 (macOS arm64) | `0ed91da603c8dc07fcd2c927cd20a3a9e31da2e51fd429bb4971041e7caf4c8835b099927f9668c451ee75887676ce96` |

Debian 11 (ffmpeg 4.3) did not install in the sweep and is not covered.

## What follows

- ffmpeg's own output changes between 6.0 and 6.1, so "the reference" is
  version-specific. A digest pinned to one ffmpeg family is the only sound
  reference, and SIGIL's transform tag already binds the binary that made the
  view.
- The specimen's `631d7c57…` is not ffmpeg's s16le output of this file under
  this command in any build tested (4.2 to 9.0.2). It stays recorded as made,
  but nothing is pinned to it.
- The profile stays `approximate`, so the ceiling stays capped at `observe`.
  Marking it reference-matched needs a parity vector against Whisper's own
  `load_audio` run with the same pinned ffmpeg binary; that is a 0.5 item, not
  a missing input.
- `crates/sigil-perception/tests/resampled_view.rs` checks that SIGIL's view
  equals the pinned ffmpeg's direct output on whichever build runs the tests
  (CI: Debian 12, ffmpeg 5.1; the maintainer's host: ffmpeg 9.0.2).
