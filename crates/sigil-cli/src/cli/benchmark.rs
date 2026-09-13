use crate::cli::benchmark_render::*;
use crate::cli::helpers::*;
use crate::cli::results::*;
use crate::cli::types::*;
use anyhow::{anyhow, Context, Result};
use sigil_core::vocab::SpecialTokenMode;
use sigil_core::{TokenizerActor, Vocab};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const BENCH_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../bench");
pub const BENCHMARK_MAX_REGRESSION_PCT: u32 = 200;

#[derive(Clone, Debug)]
pub struct ResolvedBenchmark {
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub vocab: String,
    pub rounds: usize,
    pub batch_size: usize,
    pub special_token_mode: BenchmarkSpecialTokenMode,
    pub expected_parity: bool,
    pub texts: Vec<String>,
}

pub fn resolve_benchmark(default_vocab: &str, command: &BenchCommand) -> Result<ResolvedBenchmark> {
    if command.manifest.is_some() {
        return resolve_manifest_benchmark(command);
    }

    if !command.text.is_empty() || command.input.is_some() {
        return resolve_adhoc_benchmark(default_vocab, command);
    }

    let manifest_path = benchmark_manifest_path(command.preset);
    let manifest = load_benchmark_manifest(&manifest_path)?;
    let corpus = command
        .corpus
        .clone()
        .unwrap_or_else(|| manifest.corpus.clone());
    let texts = load_benchmark_corpus(&corpus)?;
    Ok(ResolvedBenchmark {
        name: manifest.name,
        preset: preset_name(command.preset).to_string(),
        corpus,
        vocab: manifest.vocab,
        rounds: manifest.rounds,
        batch_size: manifest.batch_size.max(1),
        special_token_mode: manifest.special_token_mode,
        expected_parity: manifest.expected_parity,
        texts,
    })
}

pub fn resolve_manifest_benchmark(command: &BenchCommand) -> Result<ResolvedBenchmark> {
    let manifest_path = command
        .manifest
        .as_ref()
        .ok_or_else(|| anyhow!("manifest path missing"))?;
    if command.input.is_some() || !command.text.is_empty() {
        return Err(anyhow!(
            "--manifest is mutually exclusive with --input or --text"
        ));
    }
    if command.corpus.is_some()
        || command.rounds.is_some()
        || command.batch_size.is_some()
        || command.special_token_mode.is_some()
    {
        return Err(anyhow!(
            "--manifest is authoritative; do not combine it with corpus or tuning overrides"
        ));
    }

    let manifest = load_benchmark_manifest(manifest_path)?;
    let texts = load_benchmark_corpus(&manifest.corpus)?;
    Ok(ResolvedBenchmark {
        name: manifest.name,
        preset: "manifest".to_string(),
        corpus: manifest.corpus,
        vocab: manifest.vocab,
        rounds: manifest.rounds,
        batch_size: manifest.batch_size.max(1),
        special_token_mode: manifest.special_token_mode,
        expected_parity: manifest.expected_parity,
        texts,
    })
}

pub fn resolve_adhoc_benchmark(
    default_vocab: &str,
    command: &BenchCommand,
) -> Result<ResolvedBenchmark> {
    if command.corpus.is_some() {
        return Err(anyhow!(
            "--corpus is only valid with preset or manifest benchmark runs"
        ));
    }

    let texts = match (&command.input, command.text.is_empty()) {
        (Some(path), true) => load_json_array(Some(path))?,
        (None, false) => command.text.clone(),
        (Some(_), false) => return Err(anyhow!("--input and --text are mutually exclusive")),
        (None, true) => {
            return Err(anyhow!(
                "provide either --input, one or more --text values, or a preset/manifest"
            ))
        }
    };

    let rounds = command.rounds.unwrap_or(1).max(1);
    let batch_size = command.batch_size.unwrap_or(1).max(1);
    let special_token_mode = command
        .special_token_mode
        .unwrap_or(BenchmarkSpecialTokenMode::Disallow);

    Ok(ResolvedBenchmark {
        name: "adhoc".to_string(),
        preset: "adhoc".to_string(),
        corpus: "adhoc".to_string(),
        vocab: default_vocab.to_string(),
        rounds,
        batch_size,
        special_token_mode,
        expected_parity: true,
        texts,
    })
}

pub fn load_benchmark_manifest(path: &PathBuf) -> Result<BenchmarkManifest> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_benchmark_corpus(name: &str) -> Result<Vec<String>> {
    let path = benchmark_corpus_path(name);
    load_json_array(Some(&path))
}

pub fn default_benchmark_baseline_dir() -> PathBuf {
    PathBuf::from(BENCH_ROOT).join("baselines")
}

pub fn benchmark_baseline_correctness_path(dir: &Path, preset: &str) -> PathBuf {
    dir.join("correctness").join(format!("{preset}.json"))
}

pub fn benchmark_baseline_timing_path(dir: &Path, preset: &str) -> PathBuf {
    dir.join("timing").join(format!("{preset}.json"))
}

pub fn benchmark_manifest_path(preset: BenchmarkPreset) -> PathBuf {
    PathBuf::from(BENCH_ROOT)
        .join("manifests")
        .join(format!("{}.json", preset_name(preset)))
}

pub fn benchmark_corpus_path(name: &str) -> PathBuf {
    PathBuf::from(BENCH_ROOT)
        .join("corpora")
        .join(format!("{name}.json"))
}

pub fn preset_name(preset: BenchmarkPreset) -> &'static str {
    match preset {
        BenchmarkPreset::Small => "small",
        BenchmarkPreset::Medium => "medium",
        BenchmarkPreset::Stress => "stress",
    }
}

pub fn run_benchmark(
    vocab: &Vocab,
    actor: &TokenizerActor,
    benchmark: ResolvedBenchmark,
) -> Result<BenchmarkResult> {
    if benchmark.texts.is_empty() {
        return Err(anyhow!("benchmark requires at least one input"));
    }

    let mode = benchmark.special_token_mode.as_runtime_mode();

    let sequential_start = Instant::now();
    let mut sequential_tokens = 0usize;
    for _ in 0..benchmark.rounds {
        for chunk in benchmark.texts.chunks(benchmark.batch_size) {
            let expected = encode_sequential(vocab, chunk, &mode)?;
            sequential_tokens += count_tokens(&expected);
        }
    }
    let sequential_elapsed = sequential_start.elapsed();

    let parallel_start = Instant::now();
    let mut parallel_tokens = 0usize;
    let mut outputs_match = true;
    for _ in 0..benchmark.rounds {
        for chunk in benchmark.texts.chunks(benchmark.batch_size) {
            let owned_chunk: Vec<String> = chunk.to_vec();
            let actual = match benchmark.special_token_mode {
                BenchmarkSpecialTokenMode::AllowAll => {
                    actor.encode_batch_with_specials(&owned_chunk, SpecialTokenMode::AllowAll)?
                }
                BenchmarkSpecialTokenMode::Disallow => actor.encode_batch(&owned_chunk)?,
            };
            parallel_tokens += count_tokens(&actual);

            let expected = encode_sequential(vocab, chunk, &mode)?;
            if expected != actual {
                outputs_match = false;
            }
        }
    }
    let parallel_elapsed = parallel_start.elapsed();

    let result = BenchmarkResult {
        name: benchmark.name,
        preset: benchmark.preset,
        corpus: benchmark.corpus,
        vocab: benchmark.vocab,
        rounds: benchmark.rounds,
        batch_size: benchmark.batch_size,
        special_token_mode: benchmark.special_token_mode,
        expected_parity: benchmark.expected_parity,
        items: benchmark.texts.len(),
        sequential: BenchmarkTiming {
            rounds: benchmark.rounds,
            items: benchmark.texts.len(),
            tokens: sequential_tokens,
            elapsed_ns: sequential_elapsed.as_nanos(),
            ns_per_token: ns_per_token(sequential_elapsed, sequential_tokens),
        },
        parallel: BenchmarkTiming {
            rounds: benchmark.rounds,
            items: benchmark.texts.len(),
            tokens: parallel_tokens,
            elapsed_ns: parallel_elapsed.as_nanos(),
            ns_per_token: ns_per_token(parallel_elapsed, parallel_tokens),
        },
        outputs_match,
    };

    if result.outputs_match != result.expected_parity {
        return Err(anyhow!(
            "benchmark parity mismatch: expected {}, got {}",
            result.expected_parity,
            result.outputs_match
        ));
    }

    Ok(result)
}

pub fn write_benchmark_baselines(dir: &Path, result: &BenchmarkResult) -> Result<()> {
    let correctness_path = benchmark_baseline_correctness_path(dir, &result.preset);
    let timing_path = benchmark_baseline_timing_path(dir, &result.preset);
    fs::create_dir_all(
        correctness_path
            .parent()
            .ok_or_else(|| anyhow!("missing correctness baseline parent"))?,
    )?;
    fs::create_dir_all(
        timing_path
            .parent()
            .ok_or_else(|| anyhow!("missing timing baseline parent"))?,
    )?;

    let correctness = BenchmarkCorrectnessBaseline::from(result);
    let timing = BenchmarkTimingBaseline::from(result);
    fs::write(
        &correctness_path,
        serde_json::to_string_pretty(&correctness)?,
    )
    .with_context(|| format!("write {}", correctness_path.display()))?;
    fs::write(&timing_path, serde_json::to_string_pretty(&timing)?)
        .with_context(|| format!("write {}", timing_path.display()))?;
    Ok(())
}

pub fn compare_benchmark_baselines(
    baseline_dir: &Path,
    result: &BenchmarkResult,
) -> Result<BenchmarkComparisonReport> {
    let correctness_path = benchmark_baseline_correctness_path(baseline_dir, &result.preset);
    let timing_path = benchmark_baseline_timing_path(baseline_dir, &result.preset);
    let correctness: BenchmarkCorrectnessBaseline = load_json_file(&correctness_path)?;
    let timing: BenchmarkTimingBaseline = load_json_file(&timing_path)?;

    let current_correctness = BenchmarkCorrectnessBaseline::from(result);
    let current_timing = BenchmarkTimingBaseline::from(result);

    let sequential_regression_pct = regression_percent(
        timing.sequential_ns_per_token,
        current_timing.sequential_ns_per_token,
    );
    let parallel_regression_pct = regression_percent(
        timing.parallel_ns_per_token,
        current_timing.parallel_ns_per_token,
    );

    let report = BenchmarkComparisonReport {
        name: result.name.clone(),
        preset: result.preset.clone(),
        corpus: result.corpus.clone(),
        correctness_path,
        timing_path,
        expected_parity: correctness.expected_parity,
        observed_parity: current_correctness.outputs_match,
        sequential_baseline_ns_per_token: timing.sequential_ns_per_token,
        sequential_observed_ns_per_token: current_timing.sequential_ns_per_token,
        parallel_baseline_ns_per_token: timing.parallel_ns_per_token,
        parallel_observed_ns_per_token: current_timing.parallel_ns_per_token,
        max_regression_pct: timing.max_regression_pct,
        sequential_regression_pct,
        parallel_regression_pct,
    };

    if correctness != current_correctness {
        return Err(anyhow!(report.to_message()));
    }

    if !timing.metadata_matches(&current_timing)
        || sequential_regression_pct > timing.max_regression_pct as u128
        || parallel_regression_pct > timing.max_regression_pct as u128
    {
        return Err(anyhow!(report.to_message()));
    }

    Ok(report)
}

pub fn load_json_file<T: for<'de> serde::Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn regression_percent(baseline: u128, observed: u128) -> u128 {
    if observed <= baseline || baseline == 0 {
        0
    } else {
        ((observed - baseline) * 100) / baseline
    }
}
