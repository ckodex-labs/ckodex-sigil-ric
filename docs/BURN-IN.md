# SIGIL Burn-In Report

The burn-in report is the operational bridge between internal QA and rollout readiness.

## Source of Truth

- [docs/BURN-IN.toml](./BURN-IN.toml) defines the threshold policy.
- [docs/BURN-IN-TELEMETRY.md](./BURN-IN-TELEMETRY.md) defines the telemetry bundle schema.
- `scripts/render_burn_in_report.py` renders the machine-readable and markdown reports.

## Inputs

- A benchmark result JSON produced by `sigil bench`, typically from the `stress` preset.
- Optional rollout telemetry JSON containing:
  - `deployment_mode`
  - `monitor_shadow_enabled`
  - `representative_corpora`
  - `false_positive_rate`
  - `unresolved_high_severity_findings`
  - `rollback_ready`
- The telemetry JSON should follow [docs/BURN-IN-TELEMETRY.md](./BURN-IN-TELEMETRY.md) and may be validated locally with [bench/telemetry/stress.sample.json](../bench/telemetry/stress.sample.json).

## Usage

```bash
cargo run -p sigil-cli -- telemetry --benchmark /path/to/small.json --benchmark /path/to/medium.json --benchmark /path/to/stress.json --deployment-mode monitor --monitor-shadow-enabled --false-positive-rate 0.0 --rollback-ready --output /path/to/telemetry.json
python3 scripts/render_burn_in_report.py --benchmark /path/to/stress.json
python3 scripts/render_burn_in_report.py --benchmark /path/to/stress.json --telemetry /path/to/telemetry.json
python3 scripts/render_burn_in_report.py --benchmark /path/to/stress.json --telemetry /path/to/telemetry.json --fail-on-not-ready
```

## Interpretation

- **Ready** means the benchmark inputs passed and the rollout telemetry satisfied the policy thresholds.
- **Not Ready** means at least one policy threshold is missing or violated.
- Items without telemetry are shown as needing operator confirmation rather than being silently treated as passing.
- The nightly benchmark workflow renders this report from the stress benchmark artifact so the rollout signal is visible over time.
- The runtime telemetry bundle is emitted by `sigil telemetry` from benchmark outputs and rollout signals.
- `scripts/render_launch_readiness.py --stage staged_rollout --burn-in-report <burn-in.json>` can turn burn-in evidence into a staged-rollout readiness readout.
- CI also runs a smoke render against checked-in benchmark baselines and a telemetry bundle emitted by `sigil telemetry` so the report path stays executable in every pull request.
