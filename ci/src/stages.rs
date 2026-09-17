//! Pipeline stages — one function per CI lane, each returning a
//! Container (or exporting artifacts) so failures propagate as errors.

use crate::base::{rust, rust_zig_go, sh, LLVM_COV_INSTALL};
use dagger_sdk::Query;
use eyre::Result;

/// cargo fmt --all -- --check
pub async fn fmt(client: &Query) -> Result<()> {
    rust(client, "1.78")
        .with_exec(sh("cargo fmt --all -- --check"))
        .sync()
        .await?;
    Ok(())
}

/// python3 scripts/check_contracts.py
pub async fn contracts(client: &Query) -> Result<()> {
    rust(client, "1.78")
        .with_exec(sh("python3 scripts/check_contracts.py"))
        .sync()
        .await?;
    Ok(())
}

/// cargo test --workspace
pub async fn test(client: &Query) -> Result<()> {
    rust(client, "1.78")
        .with_exec(sh("cargo test --workspace"))
        .sync()
        .await?;
    Ok(())
}

/// cargo clippy --workspace --all-targets -- -D warnings
pub async fn clippy(client: &Query) -> Result<()> {
    rust(client, "1.78")
        .with_exec(sh("cargo clippy --workspace --all-targets -- -D warnings"))
        .sync()
        .await?;
    Ok(())
}

/// Coverage gate: llvm-cov ≥80% lines, export lcov.info to ./ci-out/.
pub async fn coverage(client: &Query) -> Result<()> {
    let ctr = rust(client, "1.78")
        .with_exec(sh(LLVM_COV_INSTALL))
        .with_exec(sh(
            "mkdir -p /out && cargo llvm-cov --workspace --lcov \
             --output-path /out/lcov.info --fail-under-lines 80",
        ));
    ctr.file("/out/lcov.info").export("ci-out/lcov.info").await?;
    Ok(())
}

/// Zig tokenizer static lib (ReleaseSafe) — smoke that lib.zig builds.
pub async fn zig_build(client: &Query) -> Result<()> {
    rust_zig_go(client, "1.78")
        .with_exec(sh(
            "zig build-lib -O ReleaseSafe -fPIC \
             -femit-bin=/tmp/libzig_tiktoken.a zig/tiktoken/src/lib.zig",
        ))
        .sync()
        .await?;
    Ok(())
}

/// Benchmark regression for one preset (small|medium); exports the
/// result JSON to ./ci-out/bench-<preset>.json.
pub async fn bench(client: &Query, preset: &str) -> Result<()> {
    let out = format!("/out/bench-{preset}.json");
    let ctr = rust_zig_go(client, "1.78")
        .with_exec(sh("mkdir -p /out"))
        .with_exec(sh(&format!(
            "cargo run -p sigil-cli --release -- bench --preset {preset} \
             --format json --baseline-dir bench/baselines --output {out}"
        )));
    ctr.file(&out).export(format!("ci-out/bench-{preset}.json")).await?;
    Ok(())
}

/// Binding smoke tests — zig libs, Python py_compile + benchmark,
/// libsigil cdylib + wasm artifact, Go test + bench binary.
pub async fn bindings(client: &Query) -> Result<()> {
    rust_zig_go(client, "1.78")
        .with_exec(sh(
            "mkdir -p zig/tiktoken/zig-out/lib && \
             zig build-lib -dynamic -O ReleaseSafe -fPIC \
               -femit-bin=zig/tiktoken/zig-out/lib/libzig_tiktoken.so \
               zig/tiktoken/src/lib.zig && \
             zig build-lib -O ReleaseSafe -fPIC \
               -femit-bin=zig/tiktoken/zig-out/lib/libzig_tiktoken.a \
               zig/tiktoken/src/lib.zig",
        ))
        .with_exec(sh(
            "export SIGIL_TIKTOKEN_LIB=$PWD/zig/tiktoken/zig-out/lib/libzig_tiktoken.so \
             PYTHONPATH=$PWD/bindings/python && \
             python3 -m py_compile bindings/python/sigil_tiktoken/__init__.py \
               bindings/python/benchmark.py && \
             python3 bindings/python/benchmark.py --json --rounds 1 \
               --corpus bench/corpora/small.json",
        ))
        .with_exec(sh(
            "cargo build -p sigil-ffi --release && scripts/build_wasm.sh && \
             ls -l target/release/libsigil.* zig/tiktoken/zig-out/sigil.wasm",
        ))
        .with_exec(sh(
            "export SIGIL_TIKTOKEN_LIB=$PWD/target/release/libsigil.so \
             PYTHONPATH=$PWD/bindings/python && \
             python3 bindings/python/benchmark.py --json --rounds 1 \
               --corpus bench/corpora/small.json",
        ))
        .with_exec(sh(
            "cd bindings/go && go test ./... && \
             go run ./cmd/sigil-bench --json --rounds 1 \
               --corpus ../../bench/corpora/small.json",
        ))
        .sync()
        .await?;
    Ok(())
}

/// vt-conformance lane: libghostty-vt cross-check needs Rust 1.90 +
/// pinned Zig — confined to this lane, the runtime path never sees it.
pub async fn conformance(client: &Query) -> Result<()> {
    rust_zig_go(client, "1.90")
        .with_exec(sh("cargo test -p sigil-vt --features conformance"))
        .with_exec(sh(
            "cargo clippy -p sigil-vt --features conformance \
             --all-targets -- -D warnings",
        ))
        .sync()
        .await?;
    Ok(())
}

/// Report lane: contracts render + launch readiness + burn-in smoke +
/// staged-rollout smoke; exports generated artifacts to ./ci-out/.
pub async fn reports(client: &Query) -> Result<()> {
    let ctr = rust(client, "1.78")
        .with_exec(sh("mkdir -p /out"))
        .with_exec(sh(
            "python3 scripts/render_qa_scorecard.py \
             --markdown-out /out/qa-scorecard.generated.md \
             --json-out /out/qa-scorecard.generated.json \
             --comment-out /out/qa-scorecard.comment.md",
        ))
        .with_exec(sh(
            "python3 scripts/render_launch_readiness.py \
             --stage internal_qa --assume-commands-pass \
             --markdown-out /out/launch-readiness.generated.md \
             --json-out /out/launch-readiness.generated.json",
        ))
        .with_exec(sh(
            "cargo run -p sigil-cli -- telemetry \
             --benchmark bench/baselines/correctness/small.json \
             --benchmark bench/baselines/correctness/medium.json \
             --benchmark bench/baselines/correctness/stress.json \
             --deployment-mode monitor --monitor-shadow-enabled \
             --false-positive-rate 0.0 --false-positive-rate-threshold 0.01 \
             --unresolved-high-severity-findings 0 --rollback-ready \
             --source ci-smoke \
             --evidence-ref bench/baselines/correctness/small.json \
             --evidence-ref bench/baselines/correctness/medium.json \
             --evidence-ref bench/baselines/correctness/stress.json \
             --output /out/burn-in-smoke.telemetry.json",
        ))
        .with_exec(sh(
            "python3 scripts/render_burn_in_report.py \
             --benchmark bench/baselines/correctness/stress.json \
             --telemetry /out/burn-in-smoke.telemetry.json \
             --markdown-out /out/burn-in-smoke.generated.md \
             --json-out /out/burn-in-smoke.generated.json \
             --fail-on-not-ready",
        ))
        .with_exec(sh(
            "python3 scripts/render_launch_readiness.py \
             --stage staged_rollout --assume-commands-pass \
             --burn-in-report /out/burn-in-smoke.generated.json \
             --markdown-out /out/staged-rollout-smoke.generated.md \
             --json-out /out/staged-rollout-smoke.generated.json",
        ));
    ctr.directory("/out").export("ci-out").await?;
    Ok(())
}
