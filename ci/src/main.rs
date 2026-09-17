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
            "all" => {
                stages::contracts(&client).await?;
                stages::fmt(&client).await?;
                stages::clippy(&client).await?;
                stages::test(&client).await?;
                stages::zig_build(&client).await?;
            }
            "fmt" => stages::fmt(&client).await?,
            "contracts" => stages::contracts(&client).await?,
            "test" => stages::test(&client).await?,
            "clippy" => stages::clippy(&client).await?,
            "coverage" => stages::coverage(&client).await?,
            "zig-build" => stages::zig_build(&client).await?,
            "bench" => stages::bench(&client, &preset).await?,
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
