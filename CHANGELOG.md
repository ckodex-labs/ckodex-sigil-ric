# Changelog

All notable changes to SIGIL. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); before 1.0, a minor
version may change behaviour. Each section names the RIC rule or mission item
it implements; `docs/RIC-SPEC.md` §10 has the specification's own changelog.

## [Unreleased]

## [0.4.0] - 2026-11-24

Representation integrity for pixels, sound and vectors (mission RIC-MM-001).
SIGIL now judges the representation a model actually consumes, not only the
file it was given, and signs which one it judged.

### Changed: behaviour you will notice

- **Media and documents cap at `observe` unless SIGIL produced the model's
  view under a reference-matched profile** (RIC-R-8). An image, audio, video
  or document input with no `--profile`, an approximate profile, or a view no
  extractor read, gives an authority ceiling of `observe` where 0.3.x gave
  `act`. Documents are capped like images: a PDF rendered for a
  vision-language model reaches it as pixels.
- **Retrieved content without a signed retrieval assessment caps at
  `observe`** (RIC-RET-3). Retrieval never raises trust or the ceiling above
  the source's.
- **A configured custom DLP pattern file that is missing or malformed is an
  error**, not an empty pattern set.
- **Media inputs and retrieved chunks sent over the API cannot carry parity or
  a retrieval assessment**, so they always cap at `observe`: a caller cannot
  prove SIGIL assessed them.

### Added

- **Receipt v4.** A `consumed` block binds the representation the model
  receives: profile and its digest, the consumed bytes' digest, parity, the
  extractor that read it, the Qwen2-VL placeholder count and stream digest,
  the model interpreter's identity, and how the engine obtained the bytes
  (`delivery`: `engine-processed` or `sigil-supplied`). The signing message
  is length-prefixed and domain-separated (RIC-SPEC §5.1). v2 receipts still
  verify; a v2 receipt carrying `consumed` is rejected; v3 is reserved.
- **Preprocessor profiles** (`perceive --profile`):
  `qwen2-vl/smart-resize-bicubic@transformers-4.57.6-slow` and
  `thumbnail/nearest-80` for images, `audio/16k-decimate` and
  `whisper/16k-filtered` (via a digest-pinned ffmpeg, `--resampler-binary`)
  for audio. SIGIL produces the model's view, scans it, and reports view
  lines the source does not carry as a divergence finding.
- **The exact Qwen2-VL request ID stream** from digest-pinned tokenizer,
  chat template and processor files (`perceive --vlm-assets`,
  `sigil-cli vlm-request`), equal to Hugging Face's own output on the tested
  texts, files and requests. SIGIL does not redistribute those files; see
  `docs/reference-models/QWEN2-VL-2B.md`.
- **The retrieval boundary** (RIC-SPEC §4.3, RIC-RET-1 to 3): a signed
  `sigil-retrieval-v1` receipt binds the embedding model and the input it
  scored.
- **in-toto predicate v4** (`https://sigil.dev/ric/receipt/v4`) for receipts
  with a consumed block, with the consumed representation as a second
  subject. Receipts without one keep the v2 statement byte for byte.
- **Audio spectral facts**: inaudible-band energy and resampler-alias
  prediction, judged per reported slice.
- **Scanning of Unicode tag characters** and the instruction-override grammar
  class.
- **Extractor identity v2**, which binds an external tool's arguments and
  model weights as well as its binary.
- **Signed releases**: Linux x86_64 and aarch64 archives with SHA-384 sums,
  a CycloneDX SBOM, SLSA build provenance and Sigstore signatures
  (`docs/RELEASE-VERIFICATION.md`).

### Fixed

- Spectral judgment: three bypasses, structure judged per reported slice, and
  slice and region rules combined rather than substituted.
- A negation only cancels an override it directly modifies.
- The divergence check no longer accepts a view line whose words are
  scattered across the source, and its cost is bounded (a line beyond the
  budget counts as divergent).

### Build

- Rust edition 2024, MSRV 1.88. `unsafe` is denied workspace-wide outside
  the two documented FFI boundaries. `thiserror` 2, `std::sync::LazyLock`.
- Functions are held to 50 lines by clippy's `too_many_lines` lint.
- The Dagger CI image installs Tesseract and ffmpeg, which the perception
  vectors run for real.

### Known limits

Tracked in `docs/missions/RIC-MM-001-OPEN.md`: the `whisper/16k-filtered`
view stays approximate (`docs/reference-models/FFMPEG-16K.md`), and receipt
v3 compatibility cannot be tested because the line that defined it is not
available.

## [0.3.2] - 2026-10-16

RIC v0.2 recursive delegation leases and security hardening. See the
[release notes](https://github.com/ckodex-labs/ckodex-sigil-ric/releases/tag/v0.3.2).

## [0.3.1] - 2026-10-14

The representation integrity engine. See the
[release notes](https://github.com/ckodex-labs/ckodex-sigil-ric/releases/tag/v0.3.1).

[Unreleased]: https://github.com/ckodex-labs/ckodex-sigil-ric/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/ckodex-labs/ckodex-sigil-ric/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/ckodex-labs/ckodex-sigil-ric/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/ckodex-labs/ckodex-sigil-ric/releases/tag/v0.3.1
