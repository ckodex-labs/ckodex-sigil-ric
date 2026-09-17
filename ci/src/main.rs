//! sigil-ci — Dagger CI driver.
//!
//! Usage (always via the engine): `dagger run cargo run -- <stage>`
//! where <stage> is one of the names below, or `all` for the full
//! verify lane. GitHub Actions jobs are thin wrappers that call
//! exactly this — no pipeline logic lives in YAML.

mod base;
mod stages;

use dagger_sdk::connect;
use eyre::{eyre, Result};

const STAGES: &[&str] = &[
    "all",
    "fmt",
    "contracts",
    "test",
    "clippy",
    "coverage",
    "zig-build",
    "bench",
    "bench-nightly",
    "bindings",
    "conformance",
    "reports",
];

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let stage = args.first().cloned().unwrap_or_else(|| "all".into());
    let preset = args.get(1).cloned().unwrap_or_else(|| "small".into());

    connect(move |client| async move {
        match stage.as_str() {
            // The full verify lane, concurrent within one engine session.
            // contracts/fmt/zig-build never touch the cargo target lock, so
            // they overlap the compile-bound lanes; clippy→test serialize on
            // /src/target inside one chain; coverage builds instrumented into
            // its own target dir; reports' cargo run waits on the lock when
            // needed. join! (not try_join!) — a failing lane must not cancel
            // siblings, so every lane's exports still land in ci-out.
            "all" => {
                // Pre-unpack the shared registry serially: concurrent cargo
                // invocations racing to unpack the same crate corrupt the
                // cache volume (flock does not hold across cache mounts).
                // After this, parallel lanes only read it.
                base::rust(&client, base::MSRV)
                    .with_exec(base::sh("cargo fetch"))
                    .sync()
                    .await?;
                let compile = async {
                    stages::clippy(&client).await?;
                    stages::test(&client).await
                };
                let (contracts_r, fmt_r, zig_r, compile_r, coverage_r, reports_r) = tokio::join!(
                    stages::contracts(&client),
                    stages::fmt(&client),
                    stages::zig_build(&client),
                    compile,
                    stages::coverage(&client),
                    stages::reports(&client),
                );
                let failed: Vec<String> = [
                    ("contracts", contracts_r),
                    ("fmt", fmt_r),
                    ("zig-build", zig_r),
                    ("clippy+test", compile_r),
                    ("coverage", coverage_r),
                    ("reports", reports_r),
                ]
                .into_iter()
                .filter_map(|(lane, r)| r.err().map(|e| format!("{lane}: {e}")))
                .collect();
                if !failed.is_empty() {
                    return Err(eyre!("verify lane failures:\n{}", failed.join("\n")));
                }
            }
            "fmt" => stages::fmt(&client).await?,
            "contracts" => stages::contracts(&client).await?,
            "test" => stages::test(&client).await?,
            "clippy" => stages::clippy(&client).await?,
            "coverage" => stages::coverage(&client).await?,
            "zig-build" => stages::zig_build(&client).await?,
            "bench" => stages::bench(&client, &preset).await?,
            "bench-nightly" => stages::bench_nightly(&client).await?,
            "bindings" => stages::bindings(&client).await?,
            "conformance" => stages::conformance(&client).await?,
            "reports" => stages::reports(&client).await?,
            other => {
                return Err(eyre!(
                    "unknown stage '{other}' — expected one of: {}",
                    STAGES.join(", ")
                ))
            }
        }
        Ok(())
    })
    .await
    .map_err(|e| eyre!("dagger pipeline failed: {e}"))
}
