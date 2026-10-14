# SIGIL launch readiness checklist

Use this checklist for burn-in verification, staged rollout decisions, and production launch gates.

The machine-readable source of truth is [docs/LAUNCH-CHECKLIST.toml](./LAUNCH-CHECKLIST.toml), rendered by `scripts/render_launch_readiness.py`.
For rollout and burn-in evidence, see [docs/BURN-IN.md](./BURN-IN.md) and `scripts/render_burn_in_report.py`.

## Quick usage

Generate the internal QA evaluation:

```sh
python3 scripts/render_launch_readiness.py --stage internal_qa --assume-commands-pass
```

Generate the staged rollout evaluation:

```sh
python3 scripts/render_launch_readiness.py --stage staged_rollout --assume-commands-pass --burn-in-report ci-out/burn-in-smoke.generated.json
```

Generate the production launch evaluation:

```sh
python3 scripts/render_launch_readiness.py --stage production_launch --assume-commands-pass --burn-in-report ci-out/burn-in-smoke.generated.json
```

Record telemetry from benchmark baselines:

```sh
cargo run -p sigil-cli -- telemetry \
  --benchmark bench/baselines/correctness/small.json \
  --benchmark bench/baselines/correctness/medium.json \
  --benchmark bench/baselines/correctness/stress.json \
  --deployment-mode monitor \
  --monitor-shadow-enabled \
  --false-positive-rate 0.0 \
  --false-positive-rate-threshold 0.01 \
  --unresolved-high-severity-findings 0 \
  --rollback-ready \
  --source ci-smoke \
  --output ci-out/burn-in-smoke.telemetry.json
```

Render the burn-in report:

```sh
python3 scripts/render_burn_in_report.py \
  --benchmark bench/baselines/correctness/stress.json \
  --telemetry ci-out/burn-in-smoke.telemetry.json \
  --fail-on-not-ready
```

## Go and no-go criteria

### Core correctness

- `cargo test --workspace` passes
- `cargo clippy --workspace --all-targets -- -D warnings` passes
- Zig tokenizer builds in both static and shared modes
- `scripts/check_contracts.py` passes
- `docs/QA-SCORECARD.md` renders cleanly in CI

### Security and contract boundaries

- `crates/sigil-core/tests/contracts.rs` passes
- `crates/sigil-core/tests/attack_proofs.rs` passes
- `crates/sigil-core/tests/firewall.rs` passes
- `crates/sigil-core/tests/property_defense.rs` passes
- `crates/sigil-mcp/tests/attack_proofs.rs` passes
- `crates/sigil-multimodal/tests/attack_proofs.rs` passes
- `crates/sigil-probe/tests/attack_proofs.rs` passes
- `crates/sigil-s/tests/composition.rs` passes
- `crates/sigil-cli/tests/cli_integration.rs` passes
- Sentinel composition never weakens a core `Deny`
- MCP and multimodal layers remain fail-closed under schema drift and taint accumulation

### Tokenizer and bindings

- Zig-backed tokenizer parity holds for the checked corpus
- Special-token allow and disallow semantics match the upstream contract
- Python binding smoke tests pass
- Go binding smoke tests pass
- Batch and actor-parallel tokenizer results match sequential results

### Benchmark and operations

- `sigil bench --preset small` compares cleanly to baselines
- `sigil bench --preset medium` compares cleanly to baselines
- `sigil bench --preset stress` is recorded for trend tracking
- No unexplained throughput regression exceeds the accepted threshold
- CI summary and PR comment scorecard are visible to reviewers

### Burn-in rollout

- Monitor and shadow mode is enabled for the first rollout window
- Real traffic or a representative corpus has been exercised
- False-positive rate is stable and within the approved threshold
- No unresolved high-severity security findings remain
- Rollout can be paused or reverted without data loss

## Decision rule

- **Go**: allowed only when every requirement in the active rollout scope is verified.
- **No-Go**: triggered if any core correctness, security, or contract boundary check fails.
- **Hold**: applied if the workspace is green but burn-in telemetry remains incomplete or unstable.

## Recommended scope by stage

- **Internal QA**: core correctness, security and contract boundaries, tokenizer and bindings.
- **Staged rollout**: all internal QA requirements plus monitor and shadow burn-in telemetry.
- **Production launch**: all staged rollout requirements plus stable telemetry, acceptable false-positive rate, and an explicit rollback plan.
