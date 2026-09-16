# SIGIL Launch Readiness Checklist

Use this checklist for burn-in, staged rollout, and go/no-go decisions.

The machine-readable source of truth is [docs/LAUNCH-CHECKLIST.toml](./LAUNCH-CHECKLIST.toml), and `scripts/render_launch_readiness.py` renders the report from that file.
For rollout and burn-in evidence, see [docs/BURN-IN.md](./BURN-IN.md) and `scripts/render_burn_in_report.py`.

Quick usage:

```bash
python3 scripts/render_launch_readiness.py --stage internal_qa --assume-commands-pass
python3 scripts/render_launch_readiness.py --stage staged_rollout
python3 scripts/render_launch_readiness.py --stage staged_rollout --assume-commands-pass --burn-in-report /path/to/burn-in.json
python3 scripts/render_launch_readiness.py --stage production_launch
cargo run -p sigil-cli -- telemetry --benchmark /path/to/small.json --benchmark /path/to/medium.json --benchmark /path/to/stress.json --deployment-mode monitor --monitor-shadow-enabled --false-positive-rate 0.0 --rollback-ready --output /path/to/telemetry.json
python3 scripts/render_burn_in_report.py --benchmark /path/to/stress.json --telemetry /path/to/telemetry.json --fail-on-not-ready
```

## Go / No-Go Criteria

### Core correctness

- [ ] `cargo test --workspace` passes
- [ ] `cargo clippy --workspace --all-targets -- -D warnings` passes
- [ ] Zig tokenizer builds in both static and shared modes
- [ ] `scripts/check_contracts.py` passes
- [ ] `docs/QA-SCORECARD.md` renders cleanly in CI

### Security and contract boundaries

- [ ] `crates/sigil-core/tests/contracts.rs` passes
- [ ] `crates/sigil-core/tests/attack_proofs.rs` passes
- [ ] `crates/sigil-core/tests/firewall.rs` passes
- [ ] `crates/sigil-core/tests/property_defense.rs` passes
- [ ] `crates/sigil-mcp/tests/attack_proofs.rs` passes
- [ ] `crates/sigil-multimodal/tests/attack_proofs.rs` passes
- [ ] `crates/sigil-probe/tests/attack_proofs.rs` passes
- [ ] `crates/sigil-s/tests/composition.rs` passes
- [ ] `crates/sigil-cli/tests/cli_integration.rs` passes (verdict exit codes, stdin, flag validation)
- [ ] Sentinel composition never weakens a core `Deny`
- [ ] MCP and multimodal layers remain fail-closed under schema drift and taint accumulation

### Tokenizer and bindings

- [ ] Zig-backed tokenizer parity holds for the checked corpus
- [ ] Special-token allow/disallow semantics match the upstream contract
- [ ] Python binding smoke tests pass
- [ ] Go binding smoke tests pass
- [ ] Batch and actor-parallel tokenizer results match sequential results

### Benchmark and operations

- [ ] `sigil bench --preset small` compares cleanly to baselines
- [ ] `sigil bench --preset medium` compares cleanly to baselines
- [ ] `sigil bench --preset stress` is recorded for trend tracking
- [ ] No unexplained throughput regression exceeds the accepted threshold
- [ ] CI summary and PR comment scorecard are visible to reviewers

### Burn-in rollout

- [ ] Monitor/shadow mode is enabled for the first rollout window
- [ ] Real traffic or a representative corpus has been exercised
- [ ] False-positive rate is stable and within the approved threshold
- [ ] No unresolved high-severity security findings remain
- [ ] Rollout can be paused or reverted without data loss

## Decision Rule

- **Go** only when every checkbox in the active rollout scope is complete.
- **No-Go** if any core correctness, security, or contract boundary check fails.
- **Hold** if the workspace is green but burn-in telemetry is still unstable or incomplete.

## Recommended Scope By Stage

- **Internal QA**: core correctness, security and contract boundaries, tokenizer and bindings
- **Staged rollout**: everything above plus monitor/shadow burn-in
- **Production launch**: everything above plus stable telemetry, acceptable false-positive rate, and an explicit rollback plan
