# SIGIL · Inside the representation (artifact snapshot)

A local, version-controlled copy of the explainer page published at
https://claude.ai/artifact/FvusRYjhGjqyiybsMNCBY7 (artifact version
`1795294552-6a02`, restored 2026-11-21). Open `index.html` in a browser; it
loads Google-hosted fonts and falls back to system fonts offline.

## What it shows, and against which build

The page dissects the RIC-MM-001 specimens: the image scaling attack (source,
nearest-80 and Qwen2-VL 644² views), the 96 kHz audio attack through the
filtered and decimated resample paths, the BPE merge seam, invisible
characters and the embedding-filter example.

It was measured at the mission baseline `a34e8cf` (receipt v3, ASR extractor
identity `619f7ddc…`), not at this branch's base `bae5ad4`. Its audio panel
shows the WP2 *before* state (`steganography_findings: []`); on
`ric-mm/2026-11` the same file now raises `inaudible_band_energy` and
`resampler_aliasing`. The page has not been updated for that.

## Integrity

`attack-96k.wav` and `source.png` are byte-identical to
`tests/fixtures/multimodal/attack_96k.wav` and `attack_source.png`
(SHA-384 `4a93d003…` and `725d3473…`). SHA-256 as reported by the artifact
service and re-checked after download:

| File | Bytes | SHA-256 |
|---|---|---|
| `attack-96k.wav` | 1632960 | `de09c18db1bce73f424301eae1d94c1125b0e031db243f4d56719e74e924abf7` |
| `heard-decimated-16k.wav` | 272198 | `ee07f91b8f996b0ec636bf5694f3c90a22ce1c4c4fd2f961d731e62d103c2b86` |
| `heard-ffmpeg-16k.wav` | 272232 | `7768e9d93c86d7e684411a2fd9c6dc35580a2413f4d862fb39fe49769e51a85e` |
| `index.html` | 199140 | `56b070c56de67fae159dd34039a09e6c0f890da9b2c1fe507fe1b7e3e510441c` |
| `logmel-ffmpeg.png` | 23046 | `29ebbbeb87b6662f7dd8146b8d69b7466b699f322d66af93203bae3d8b06ef7d` |
| `logmel-naive.png` | 52020 | `d4fb4aea80831f5c9dc6113f394c0bd778de949543a8ebc003caf5e59dc79fe1` |
| `model-view.png` | 624 | `e519ec794f257e3654e75d34d172ee408c5a0ecdff9f0db5e3e99b0dbad243a0` |
| `qwen-view.png` | 708218 | `a252f9d8a73a4b5348b9a062d95875681f4908f8ec6c49cc669c7744afe6cf26` |
| `source.png` | 745920 | `033f3115faca114c3f863779b15cb45782f6ed29dabe3707cf98e9c27d8e8240` |
| `spec-ffmpeg.png` | 87519 | `9836ba8f6ec5548781deac48dcb93819256353c23b7dd4384605b7cca26ee3ee` |
| `spec-file.png` | 162432 | `2c2de977a28b927823db1207485e7c437117de0446afcdec44f0659a21c4510a` |
| `spec-naive.png` | 200665 | `184635d0864c225556da44c289db66d08aa4f69f5e9473d27ab344b4f46ce41b` |
