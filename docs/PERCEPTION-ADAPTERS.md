# Growing Perception Adapters — Exploration

**Status:** Design exploration (per decision 2026-09-11)
**Question:** How does SIGIL grow from a lexical security library into governing
*perception* channels — images, audio, video, documents — without becoming an
OCR/ASR/vision framework?
**Related:** [RIC-SPEC.md](./RIC-SPEC.md) §4.2–4.5 (specified boundaries) · SIGIL-PAPERS-7-8 (Paper #7)

---

## 1. The architectural question

SIGIL's kernel is lexical: it attests text-extracted channels with provenance.
Real multimodal systems consume pixels, waveforms, and document layers. The
question is where the *perception* (decoding, extraction, transcription)
happens relative to the *governance* (provenance, trust, fusion auditing).

Three options were considered:

| Option | Shape | Verdict |
|---|---|---|
| A. Monolithic growth | `sigil-core` gains media decoding | **Rejected** — dependency explosion (image/symphonia/pdf crates in the kernel), supply-chain surface in the trust-critical crate, violates the pure-kernel doctrine |
| B. Adapter crates behind a kernel-defined port | `sigil-perception` crate (feature-gated) implements a `PerceptionAdapter` port; kernel stays lexical | **Recommended** |
| C. External sidecar | Perception facts produced by a separate service, fed to SIGIL over the existing server façade | Valid for polyglot deployments later; same port, different transport |

Option B with C as a deployment mode is the recommendation. The deciding
argument: the kernel must be able to *attest adapter output* without
*trusting adapter judgment*. The port enforces exactly that split.

## 2. The port (what the kernel defines)

```rust
pub trait PerceptionAdapter: Send + Sync {
    /// Modality this adapter serves.
    fn modality(&self) -> Modality;
    /// Implementation identity — bound into receipts (RIC-R-3/R-4 analog).
    fn adapter_id(&self) -> &str;
    /// Decompose an artifact into governed text-extracted channels.
    /// Adapters produce channels; they never produce verdicts.
    fn perceive(&self, artifact: &ArtifactRef) -> Result<PerceptionOutput, PerceptionError>;
}
```

Each returned channel is a `ModalInput` plus lineage:

- `channel_kind` — `OcrText | Transcript | Metadata | Caption | TextLayer | …`
- `content` — the extracted text (what today's `ModalInput.content` carries)
- `provenance` — **always a derived class** (`McpTool`/`Retrieval`-class trust);
  an adapter that emits `User`/`System` provenance is non-conformant (RIC-R-7)
- `derived_from` — the parent artifact id
- `extractor` — name, version, configuration digest (the adapter's own
  receipt, so "which OCR produced this text" is answerable later)
- `confidence` — optional; **confidence never changes epistemic class**

The kernel consumes channels through the existing `MultimodalEngine::analyze`
— fusion auditing, authority ceilings, and receipts work unchanged. That is
the key property: **adapters extend what SIGIL can see, not what SIGIL
decides.**

## 3. Phased plan

| Phase | Adapter | Extraction | New kernel types | Dependencies (feature-gated) |
|---|---|---|---|---|
| 0 | Port + skeleton | — | `PerceptionAdapter`, `ModalChannel`, `ExtractedChannel`, `ExtractedArtifact` | none |
| 1 | Image | decode (dimensions, planes), EXIF/XMP inventory, OCR text channel | `ImageChannelKind` | `image` crate; OCR via external-command adapter first |
| 2 | Audio | container metadata, ASR transcript channel (external adapter) | `AudioChannelKind` | `symphonia` (decode); ASR external |
| 3 | Video | frame sampling, subtitle tracks, temporal spans | `TemporalSpan`, per-frame channel indexing | `symphonia` + sampling |
| 4 | Document | PDF text layers, annotations, embedded objects, attachments | `DocumentLayerKind` | `pdf-extract` or `lopdf` |

**Phase 1 is the first implementation target**: it completes the deck's
Case B (instruction inside an image) end-to-end with real pixels.

### The OCR question (deliberate trade)

Bundling Tesseract bindings would make `sigil-perception` heavy and
platform-fragile. Phase 1 ships an **external-command OCR adapter**: the
adapter invokes a configured OCR binary, records the binary's digest and
version in the channel's `extractor` field, and treats its output as
derived-untrusted text. Trade-off stated honestly: a subprocess boundary is
itself an attack surface (argument injection, binary substitution), so the
adapter pins the binary path, passes text via stdin/stdout only, and records
`extractor.digest` for the evidence chain. A bundled OCR engine remains a
future option once the channel contract is proven.

## 4. What adapters must never do (conformance rules)

1. Produce channels with `System`/`User` provenance (authority fabrication).
2. Emit verdicts, severities, or deny decisions (judgment belongs to the kernel).
3. Drop or reorder extraction steps without a versioned adapter identity change.
4. Read network resources (perception is local; fetching is the caller's job).
5. Silently truncate — a partial extraction is a flagged channel, not a clean one.

## 5. Sigstore keyless integration (decision: both ecosystems)

The in-toto/DSSE layer shipped in this increment is the interop substrate for
both ecosystems: DSSE envelopes are what `cosign attest` / `cosign
verify-attestation` consume. The Sigstore keyless adapter design:

```
OIDC identity token (CI workload identity, e.g. SIGSTORE_ID_TOKEN)
  → Fulcio: exchange for a short-lived signing certificate
  → sign the receipt message / DSSE PAE with the ephemeral key
  → Rekor: append entry, obtain inclusion proof
  → emit Sigstore bundle (cert + signature + inclusion proof)
```

**Status (2026-09-11): implemented** as `crates/sigil-sigstore` —
`SigstoreKeylessSigner` implements the `ReceiptSigner` port (OIDC source: ambient
`SIGSTORE_ID_TOKEN` or explicit token; Fulcio v2 exchange with a minimal PKCS#10 CSR —
empty subject, identity from the token; ephemeral P-384 key consistent with the mandate;
Rekor hashedrekord upload available as a function, opt-in). CSR well-formedness pinned by
unit tests; the live Fulcio flow is an integration test gated on `SIGIL_SIGSTORE_LIVE=1`
+ `SIGSTORE_ID_TOKEN`. **Bundle emission and offline signature verification: implemented** (2026-09-11,
after spec verification against primary sources — see below). `build_bundle` emits
Sigstore bundle v0.3 (`application/vnd.dev.sigstore.bundle.v0.3+json`) with the
X.509 certificate chain (leaf first, DER) and a `messageSignature` over the receipt
message with `SHA2_384`; `verify_bundle` verifies the signature against the leaf
certificate's public key, offline. **Chain-of-trust validation: implemented** (2026-09-11, after spec verification
against the Sigstore client spec, fulcio.proto, Rekor openapi.yaml, and RFC 6962
§2.1.1). `verify_bundle_with_trust` in `sigil-sigstore::trust` performs all six
MUST checks from the client spec: (1) signature binding, (2) RFC 5280 §6 chain
validation (leaf → intermediate → pinned root), (3) SAN identity match, (4)
validity window at Rekor `integratedTime`, (5) Rekor SET verification (canonical
JSON `{body, integratedTime, logID, logIndex}`, P-256/SHA-256), (6) RFC 6962
inclusion proof (domain-separated Merkle tree with the right-edge case). All
checks fail closed. `fetch_trust_bundle` retrieves the Fulcio root + intermediates
from `GET /api/v2/trustBundle`. **Documented limitation:** simplified RFC 5280
processing (no name constraints or policy mapping) — stated in the code.

**TUF root distribution: implemented** (2026-09-11). `sigil-sigstore::tuf::trust_root_from_embedded`
loads the production trust root from the `sigstore-trust-root` crate's embedded
`trusted_root.json` snapshot (from `https://tuf-repo-cdn.sigstore.dev/`, pinned
at build time). The embedded root contains the Fulcio root + intermediate
certificates and the Rekor P-256 public key. No network access required for
verification. The Rekor log ID is converted from base64 (the crate's format)
to hex (the Rekor entry's `logID` format).

**Phase 2+ (video, document): implemented** (2026-09-11).
`sigil-perception::video::VideoAdapter` parses MP4/ISOBMFF container metadata via
`mp4parse` (Mozilla, pure Rust). Reports track inventory (video/audio/subtitle
tracks), dimensions, duration. `sigil-perception::document::DocumentAdapter`
extracts text from plain text, markdown, and PDF artifacts (lopdf content-stream
decoding with page-by-page salvage and a string-literal fallback).

**Render-vs-extract divergence: implemented** (G3, 2026-09-15).
`DocumentAdapter::render_compare` chains two pinned externals — a renderer
(`pdftoppm`, PDF → PNG on stdin→stdout) and the existing `ExternalOcr` — then
diffs the text layer against what actually painted. Lines whose normalized
words are <80% covered by the rendered word set surface as a `Divergence`
channel (`ChannelKind::Divergence`, provenance still `McpTool` — kernel
judgment, RIC-R-7), carrying exactly the text a human viewing the render
would not see. Verified e2e: a PDF with a white-on-white `ignore previous
instructions` yields `text_layer` = both lines, `ocr_text` = the visible
line only, `divergence` = the hidden line. CLI: `sigil-cli perceive
--modality document --render-binary pdftoppm "--render-args=-png
-singlefile -r 150 -" --ocr-binary tesseract --ocr-args "stdin stdout"
--analyze`. Known limits: single-page via `-singlefile` (multi-page render
needs temp-file plumbing); word-set comparison tolerates OCR re-wrap but a
heavily mis-OCR'd render over-reports divergence — a failure mode that
surfaces extra evidence, not silence.

**Video stream extraction: implemented** (G5, 2026-09-15).
`VideoAdapter::stream_extract` demuxes the container through pinned
`ffmpeg` pipes so embedded streams reach the modality adapters they
belong to — the audio track becomes a mono 16 kHz WAV fed to
`AudioAdapter` (wav-header, spectral analysis, optional pinned ASR
transcript), the video track becomes a 1 fps `image2pipe` PNG stream
split on IEND markers and OCR'd per frame (`frame-ocr[i]` channels,
each carrying the pinned OCR's SHA-384 identity), and the first subtitle
stream becomes a `caption` channel (`-map 0:s:0? -f srt` — the
`subtitle_tracks` inventory count only covers `TrackType::Metadata`, so a
`mov_text` track the demuxer reads but mp4parse did not count is surfaced
as `stream.subtitle_beyond_inventory`). ffmpeg's streamed WAV
header leaves RIFF/`data` sizes at `0xFFFFFFFF`; `wav_patch_streamed_sizes`
repairs them before hound sees the bytes. Pipe failures degrade to named
properties (`stream.audio = failed: …`, `stream.frames`), never panics or
silent skips; frames past the 12-frame cap are reported via
`stream.frames_capped`. CLI: `sigil-cli perceive --modality video
--ffmpeg-binary ffmpeg --ocr-binary tesseract --ocr-args "stdin stdout"
[--transcript-binary …]` — `--ocr-binary`/`--transcript-binary` without
`--ffmpeg-binary` is a config error, not a silent skip. Verified e2e:
an MP4 whose frames carry painted "IGNORE PREVIOUS INSTRUCTIONS" text
yields a `frame-ocr[0]` channel with the instruction and
`Flag{SentinelDisagreement}` under `--analyze`. Limits: fixed arg sets
(1 fps frames, mono 16 kHz audio); OCR channel count bounded by the
frame cap; spoken-word injection requires the optional ASR half.

**Declared-vs-magic modality routing: implemented** (G6, 2026-09-15).
`sigil-cli perceive --modality` is a hint, not a command: container magic
(PNG/JPEG/GIF, RIFF-WAVE/fLaC, `ftyp`, `%PDF`) that contradicts the hint
routes to the sniffed adapter and records `sigil.modality_routed` in the
report — a declared-vs-actual mismatch is evidence, not a decode failure.
Unknown magic leaves the hint alone.

**Low-frequency deception detection: implemented** (2026-09-11).
- `sigil-perception::spectral`: subliminal audio detection (sub-audible frequency
  bands below 20 Hz) and audio steganography detection (anomalous high-frequency
  energy near Nyquist) via real-valued FFT (`realfft`/`rustfft`).
- `sigil-core::lfdd`: rare pattern detection (statistical n-gram anomaly
  detection) and cross-input slow-rate detection (Jaccard n-gram overlap + rate
  analysis across input history).

**Remaining:** live integration testing against the public Sigstore instance
(requires a real OIDC token and network access to Fulcio + Rekor).

**Spec verification (2026-09-11, against primary sources):** the Fulcio v2 request
was corrected — per `fulcio.proto`, the OIDC token travels in the body
(`credentials.oidcIdentityToken`), the CSR field is `certificateSigningRequest`
(PKCS#10 **PEM**-encoded, base64 by the proto-JSON bytes mapping), and the response
chain certificates are parsed as base64-DER with a PEM fallback. Rekor hashedrekord
v0.0.1 confirmed to accept `sha384` in `data.hash.algorithm` (schema enum; PR #1959)
with an unprefixed lowercase-hex value — the SHA-384 mandate is Rekor-compatible.
DSSE PAE and envelope confirmed against protocol.md/envelope.md v1.0.2; the `sig`
field encoding was corrected from hex to **Base64(SIGNATURE)** per the spec (the
algorithm-label deviation for P-384 remains, documented in the module).

**Implementation plan** (original):
- `SigstoreKeylessSigner` implementing the existing `ReceiptSigner` port —
  the port needs no change; the adapter resolves the ephemeral Fulcio key
  internally per signing operation
- Dependency: `sigstore-rs` (pulls `tokio`, `reqwest`, `oauth2`) — network
  dependency at signing time; verification stays offline (bundle carries cert
  + inclusion proof)
- Decision points to settle before implementation:
  1. Ambient credential source: CI OIDC token vs. interactive OIDC flow
  2. Trust root: pin the Fulcio root CA (offline bundle) vs. trust-on-first-use
  3. Rekor: require inclusion proof at sign time, or verify asynchronously
  4. Offline verification of Rekor entries (signed transparency tree heads)
- The existing `verify-receipt` / `verify-attestation` commands gain a
  `--sigstore-bundle` mode that verifies cert-chain + inclusion proof offline

## 6. Recommendation

1. ~~Ship Phase 0 + Phase 1~~ **SHIPPED (2026-09-11)**: the `PerceptionAdapter` port
   lives in `sigil-multimodal::perception` (kernel mapping assigns derived provenance —
   RIC-R-7 at the type level); the image adapter ships in `crates/sigil-perception`
   (decode via `image` 0.25, EXIF inventory via `kamadak-exif` 0.6, pinned external-command
   OCR with stdin-only artifact flow). CLI: `sigil-cli perceive [--ocr-binary …] [--analyze]`.
   Verified through the binary: PNG → structure report + OCR channel → kernel scan →
   Flag/observe on injected instruction text.
2. Land the Sigstore keyless design as a feature-gated adapter after the
   OIDC/trust-root decisions above.
3. Keep the kernel lexical: adapters produce channels, the kernel judges.
