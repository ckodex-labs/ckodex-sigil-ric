use super::Context;
use crate::cli::benchmark::*;
use crate::cli::benchmark_render::*;
use crate::cli::types::*;
use anyhow::{Context as _, Result, anyhow};
use sigil_core::{TokenizerActor, Vocab};
use std::fs;

pub(super) fn bench(ctx: &Context, command: &BenchCommand) -> Result<()> {
    let benchmark = resolve_benchmark(&ctx.vocab_name, command)?;
    let bench_vocab = Vocab::tiktoken(benchmark.vocab.clone());
    bench_vocab.validate().map_err(|_| {
        anyhow!(
            "unknown tokenizer vocab `{}` in benchmark manifest",
            benchmark.vocab
        )
    })?;
    let bench_actor = TokenizerActor::new(bench_vocab.clone());
    let result = run_benchmark(&bench_vocab, &bench_actor, benchmark)?;
    if command.refresh_baselines {
        let baseline_dir = command
            .baseline_dir
            .clone()
            .unwrap_or_else(default_benchmark_baseline_dir);
        write_benchmark_baselines(&baseline_dir, &result)?;
    }
    if let Some(baseline_dir) = command.baseline_dir.as_ref() {
        compare_benchmark_baselines(baseline_dir, &result)?;
    }
    let rendered = render_benchmark_output(&result, command.report_format)?;
    write_report(command, &rendered)
}

/// Writes the rendered report to `--output`, or to stdout with a trailing newline.
fn write_report(command: &BenchCommand, rendered: &str) -> Result<()> {
    if let Some(path) = command.output.as_ref() {
        fs::write(path, rendered).with_context(|| format!("write {}", path.display()))?;
    } else {
        print!("{rendered}");
        if !rendered.ends_with('\n') {
            println!();
        }
    }
    Ok(())
}

pub(super) fn telemetry(command: &BurnInTelemetryCommand) -> Result<()> {
    let telemetry = emit_burn_in_telemetry(command)?;
    let rendered = serde_json::to_string_pretty(&telemetry)? + "\n";
    if let Some(path) = command.output.as_ref() {
        fs::write(path, rendered).with_context(|| format!("write {}", path.display()))?;
    } else {
        print!("{rendered}");
    }
    Ok(())
}
