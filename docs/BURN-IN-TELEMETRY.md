# SIGIL Burn-In Telemetry Schema

This document defines the telemetry bundle consumed by `scripts/render_burn_in_report.py`.

## Version

- `schema_version`: integer
- Current version: `1`

## Required fields

- `deployment_mode`: string, expected values include `monitor`, `shadow`, `staged`, `production`
- `monitor_shadow_enabled`: boolean
- `representative_corpora`: array of corpus names used during burn-in
- `false_positive_rate`: number between `0.0` and `1.0`
- `unresolved_high_severity_findings`: integer
- `rollback_ready`: boolean

## Optional fields

- `schema_version`: integer, defaults to `1`
- `false_positive_rate_threshold`: number, overrides the policy default for this report
- `captured_at_unix_ms`: integer Unix epoch milliseconds
- `source`: string describing where the telemetry was collected from
- `evidence_refs`: array of strings pointing at benchmark, probe, or deployment artifacts
- `notes`: free-form string for operator context

## Example

```json
{
  "schema_version": 1,
  "deployment_mode": "monitor",
  "monitor_shadow_enabled": true,
  "representative_corpora": ["small", "medium", "stress"],
  "false_positive_rate": 0.0,
  "false_positive_rate_threshold": 0.01,
  "unresolved_high_severity_findings": 0,
  "rollback_ready": true,
  "captured_at_unix_ms": 0,
  "source": "nightly-burn-in",
  "evidence_refs": [
    "bench/stress.json",
    "probe/weekly.json"
  ],
  "notes": "sample telemetry for staged rollout validation"
}
```

## Runtime emitter

The canonical way to produce this bundle is `sigil telemetry`, which aggregates
one or more benchmark result JSON files plus live rollout signals into the
versioned telemetry shape above.

Example:

```bash
cargo run -p sigil-cli -- telemetry \
  --benchmark /path/to/small.json \
  --benchmark /path/to/medium.json \
  --benchmark /path/to/stress.json \
  --deployment-mode monitor \
  --monitor-shadow-enabled \
  --false-positive-rate 0.0 \
  --rollback-ready \
  --output /path/to/telemetry.json
```

## Contract

- Missing required fields are a hard failure.
- Telemetry must be versioned and must not be silently coerced from incompatible shapes.
- The burn-in renderer only consumes this schema and should fail closed when the bundle is invalid.
