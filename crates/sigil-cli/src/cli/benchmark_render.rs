use crate::cli::benchmark::*;
use crate::cli::results::*;
use crate::cli::types::*;
use anyhow::{anyhow, Result};
use sigil_core::vocab::EncodedToken;
use sigil_core::vocab::SpecialTokenMode;
use sigil_core::Vocab;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

type TomlValue = toml::Value;

pub fn encode_sequential(
    vocab: &Vocab,
    chunk: &[String],
    mode: &SpecialTokenMode,
) -> Result<Vec<Vec<EncodedToken>>> {
    chunk
        .iter()
        .map(|text| -> Result<Vec<EncodedToken>> {
            Ok(match mode {
                SpecialTokenMode::AllowAll => {
                    vocab.try_encode_with_specials(text, SpecialTokenMode::AllowAll)?
                }
                SpecialTokenMode::Disallow => vocab.try_encode(text)?,
                SpecialTokenMode::AllowOnly(_) => {
                    unreachable!("benchmark special-token mode only uses allow-all/disallow")
                }
            })
        })
        .collect()
}

pub fn count_tokens(batches: &[Vec<EncodedToken>]) -> usize {
    batches.iter().map(Vec::len).sum()
}

pub fn ns_per_token(elapsed: Duration, tokens: usize) -> u128 {
    if tokens == 0 {
        0
    } else {
        elapsed.as_nanos() / tokens as u128
    }
}

pub fn render_benchmark_output(
    result: &BenchmarkResult,
    format: BenchmarkOutputFormat,
) -> Result<String> {
    Ok(match format {
        BenchmarkOutputFormat::Human => render_benchmark_human(result),
        BenchmarkOutputFormat::Json => serde_json::to_string_pretty(result)?,
        BenchmarkOutputFormat::Jsonl => format!("{}\n", serde_json::to_string(result)?),
        BenchmarkOutputFormat::Csv => render_benchmark_csv(result),
    })
}

pub fn render_benchmark_human(result: &BenchmarkResult) -> String {
    format!(
        "benchmark {name}\n  preset: {preset}\n  corpus: {corpus}\n  vocab: {vocab}\n  special-token-mode: {mode}\n  expected-parity: {expected}\n  outputs-match: {match_ok}\n  rounds: {rounds}\n  batch-size: {batch_size}\n  items: {items}\n  sequential: tokens={seq_tokens} elapsed_ns={seq_elapsed} ns_per_token={seq_rate}\n  parallel: tokens={par_tokens} elapsed_ns={par_elapsed} ns_per_token={par_rate}\n",
        name = result.name,
        preset = result.preset,
        corpus = result.corpus,
        vocab = result.vocab,
        mode = benchmark_mode_label(result.special_token_mode),
        expected = result.expected_parity,
        match_ok = result.outputs_match,
        rounds = result.rounds,
        batch_size = result.batch_size,
        items = result.items,
        seq_tokens = result.sequential.tokens,
        seq_elapsed = result.sequential.elapsed_ns,
        seq_rate = result.sequential.ns_per_token,
        par_tokens = result.parallel.tokens,
        par_elapsed = result.parallel.elapsed_ns,
        par_rate = result.parallel.ns_per_token,
    )
}

pub fn render_benchmark_csv(result: &BenchmarkResult) -> String {
    let headers = [
        "name",
        "preset",
        "corpus",
        "vocab",
        "special_token_mode",
        "expected_parity",
        "outputs_match",
        "rounds",
        "batch_size",
        "items",
        "sequential_tokens",
        "sequential_elapsed_ns",
        "sequential_ns_per_token",
        "parallel_tokens",
        "parallel_elapsed_ns",
        "parallel_ns_per_token",
    ];
    let values = [
        csv_field(&result.name),
        csv_field(&result.preset),
        csv_field(&result.corpus),
        csv_field(&result.vocab),
        csv_field(benchmark_mode_label(result.special_token_mode)),
        csv_field(&result.expected_parity.to_string()),
        csv_field(&result.outputs_match.to_string()),
        csv_field(&result.rounds.to_string()),
        csv_field(&result.batch_size.to_string()),
        csv_field(&result.items.to_string()),
        csv_field(&result.sequential.tokens.to_string()),
        csv_field(&result.sequential.elapsed_ns.to_string()),
        csv_field(&result.sequential.ns_per_token.to_string()),
        csv_field(&result.parallel.tokens.to_string()),
        csv_field(&result.parallel.elapsed_ns.to_string()),
        csv_field(&result.parallel.ns_per_token.to_string()),
    ];

    format!("{}\n{}\n", headers.join(","), values.join(","))
}

pub fn csv_field(value: &str) -> String {
    let escaped = value.replace('"', "\"\"");
    format!("\"{escaped}\"")
}

pub fn benchmark_mode_label(mode: BenchmarkSpecialTokenMode) -> &'static str {
    match mode {
        BenchmarkSpecialTokenMode::Disallow => "disallow",
        BenchmarkSpecialTokenMode::AllowAll => "allow_all",
    }
}

pub fn emit_burn_in_telemetry(command: &BurnInTelemetryCommand) -> Result<BurnInTelemetryBundle> {
    if command.benchmark.is_empty() {
        return Err(anyhow!("provide at least one --benchmark path"));
    }
    let threshold = command
        .false_positive_rate_threshold
        .or_else(read_burn_in_false_positive_threshold)
        .unwrap_or(0.01);
    let false_positive_rate = command.false_positive_rate.unwrap_or(0.0);
    if !(0.0..=1.0).contains(&false_positive_rate) {
        return Err(anyhow!(
            "false-positive rate must be a fraction between 0.0 and 1.0"
        ));
    }

    let mut representative_corpora = BTreeSet::new();
    let mut evidence_refs = BTreeSet::new();
    for benchmark_path in &command.benchmark {
        let benchmark: BurnInBenchmarkSummary = load_json_file(benchmark_path)?;
        if benchmark.outputs_match != benchmark.expected_parity {
            return Err(anyhow!(
                "benchmark {} does not satisfy expected parity",
                benchmark_path.display()
            ));
        }
        representative_corpora.insert(benchmark.corpus.clone());
        evidence_refs.insert(benchmark_path.display().to_string());
        evidence_refs.insert(format!(
            "benchmark:{}:{}",
            benchmark.preset, benchmark.corpus
        ));
        evidence_refs.insert(format!("benchmark:vocab:{}", benchmark.vocab));
    }

    for ref_item in &command.evidence_ref {
        evidence_refs.insert(ref_item.clone());
    }

    Ok(BurnInTelemetryBundle {
        schema_version: 1,
        deployment_mode: command.deployment_mode.as_str().to_string(),
        monitor_shadow_enabled: command.monitor_shadow_enabled,
        representative_corpora: representative_corpora.into_iter().collect(),
        false_positive_rate,
        false_positive_rate_threshold: Some(threshold),
        unresolved_high_severity_findings: command.unresolved_high_severity_findings,
        rollback_ready: command.rollback_ready,
        captured_at_unix_ms: command.captured_at_unix_ms,
        source: command
            .source
            .clone()
            .or_else(|| Some("sigil-cli telemetry".to_string())),
        evidence_refs: evidence_refs.into_iter().collect(),
        notes: command.note.clone(),
    })
}

pub fn read_burn_in_false_positive_threshold() -> Option<f64> {
    let text = fs::read_to_string(PathBuf::from(BENCH_ROOT).join("../docs/BURN-IN.toml")).ok()?;
    let value: TomlValue = text.parse().ok()?;
    value
        .get("burn_in")
        .and_then(|entry| entry.get("false_positive_rate_max"))
        .and_then(TomlValue::as_float)
}
