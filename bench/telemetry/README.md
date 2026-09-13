# Burn-In Telemetry Samples

This directory stores sample telemetry bundles for burn-in validation.

- `stress.sample.json` is a checked-in example of the versioned telemetry schema.
- Real deployment telemetry should be emitted by `sigil telemetry` from live benchmark outputs and rollout signals.
- You can still drop temporary local bundles here while validating a rollout, but CI should rely on the runtime emitter path instead of these samples.
