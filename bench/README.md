# Benchmarks

Benchmark corpora and baseline results for `sigil-core` and companion crates
belong here.

## Layout

- `bench/corpora/` stores checked-in benchmark input sets.
- `bench/manifests/` stores the preset definitions used by `sigil bench`.
- `bench/baselines/correctness/` stores schema and parity baselines.
- `bench/baselines/timing/` stores ns/token baselines and the allowed regression budget.

## Refresh flow

Update baselines explicitly with:

```bash
cargo run -p sigil-cli -- bench --preset small --refresh-baselines
cargo run -p sigil-cli -- bench --preset medium --refresh-baselines
cargo run -p sigil-cli -- bench --preset stress --refresh-baselines
```

The CI workflows compare against the checked-in baselines and do not update
them automatically.
