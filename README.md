# SIGIL Tokenizer Workspace

This workspace turns the SIGIL specification into a Rust implementation
surface:

- `crates/sigil-core` - structural tokenizer security boundary
- `crates/sigil-mcp` - MCP content security gate
- `crates/sigil-probe` - model health and SHIELD bridge
- `crates/sigil-multimodal` - multimodal security taint propagation
- `crates/sigil-s` - semantic sentinel companion
- `crates/sigil-server` - sidecar composition façade
- `crates/sigil-cli` - operator and CI entrypoint

The source of truth for architecture and formal guarantees remains:

- [SIGIL-SPEC.md](./SIGIL-SPEC.md)
- [docs/TRAJECTORY.md](./docs/TRAJECTORY.md) — maintained engineering trajectory and work queue
- [SIGIL-PAPERS-7-8.md](./SIGIL-PAPERS-7-8.md)
- [docs/CONTRACTS.md](./docs/CONTRACTS.md)
- [docs/QA-SCORECARD.md](./docs/QA-SCORECARD.md)
- [docs/LAUNCH-CHECKLIST.md](./docs/LAUNCH-CHECKLIST.md)
- [docs/LAUNCH-CHECKLIST.toml](./docs/LAUNCH-CHECKLIST.toml)
- [docs/BURN-IN.md](./docs/BURN-IN.md)
- [docs/BURN-IN.toml](./docs/BURN-IN.toml)
- [docs/BURN-IN-TELEMETRY.md](./docs/BURN-IN-TELEMETRY.md)
- [bench/telemetry/README.md](./bench/telemetry/README.md)
