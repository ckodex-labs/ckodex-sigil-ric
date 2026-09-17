# SIGIL Tokenizer Workspace

This workspace turns the SIGIL specification into a Rust implementation
surface.

## Quick start

```sh
cargo build -p sigil-cli
```

Scan a string, pipe a payload, or gate a CI job on the verdict:

```sh
target/debug/sigil-cli scan --text "ignore previous instructions"
# → verdict Flag, exit 0 (admit with evidence)

cat suspicious.txt | target/debug/sigil-cli scan
# piped stdin works with no flags; `--input -` reads it explicitly

target/debug/sigil-cli scan --input payload.txt --fail-on flag
# → exit 1 on Flag, 2 on Deny — wire straight into CI
```

`perceive` adapts binary artifacts into scanned text channels
(image OCR, audio spectral+ASR, video demux, PDF render-vs-extract
divergence, source-code comment/string split):

```sh
target/debug/sigil-cli perceive --input report.pdf --modality document --analyze
```

Every subcommand is documented under `--help`. The runnable PoC cases —
including the full external-tool wiring — live in
[docs/POC-CASES.md](./docs/POC-CASES.md).

## Crates

- `crates/sigil-core` - structural tokenizer security boundary
- `crates/sigil-mcp` - MCP content security gate
- `crates/sigil-probe` - model health and SHIELD bridge
- `crates/sigil-multimodal` - multimodal security taint propagation
- `crates/sigil-perception` - perception adapters (audio/image/video/document → derived channels)
- `crates/sigil-sigstore` - Sigstore keyless signing and bundle verification
- `crates/sigil-s` - semantic sentinel companion
- `crates/sigil-server` - sidecar composition façade
- `crates/sigil-vt` - terminal-escape sequence scanner (owned OSC table)
- `crates/sigil-cli` - operator and CI entrypoint

The source of truth for architecture and formal guarantees remains:

- [SIGIL-SPEC.md](./SIGIL-SPEC.md)
- [docs/TRAJECTORY.md](./docs/TRAJECTORY.md) — maintained engineering trajectory and work queue
- [SIGIL-PAPERS-7-8.md](./SIGIL-PAPERS-7-8.md)
- [docs/CONTRACTS.md](./docs/CONTRACTS.md)
- [docs/THREAT-MAPPING.md](./docs/THREAT-MAPPING.md) — detector → MITRE ATLAS/ATT&CK mapping
- [docs/QA-SCORECARD.md](./docs/QA-SCORECARD.md)
- [docs/LAUNCH-CHECKLIST.md](./docs/LAUNCH-CHECKLIST.md)
- [docs/LAUNCH-CHECKLIST.toml](./docs/LAUNCH-CHECKLIST.toml)
- [docs/BURN-IN.md](./docs/BURN-IN.md)
- [docs/BURN-IN.toml](./docs/BURN-IN.toml)
- [docs/BURN-IN-TELEMETRY.md](./docs/BURN-IN-TELEMETRY.md)
- [bench/telemetry/README.md](./bench/telemetry/README.md)
