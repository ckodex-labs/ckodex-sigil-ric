# SIGIL-PROBE Guide

`sigil-probe` estimates model health from:

- canary pass rates
- fingerprint confidence
- distribution shift
- consistency drift
- boundary failures
- sustained anomaly windows

When drift crosses the critical threshold, the probe layer emits a SHIELD
trigger rather than a transient alert.
