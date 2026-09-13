use crate::cli::benchmark::*;
use crate::cli::types::*;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize)]
pub struct JsonResult<T> {
    pub result: T,
}

#[derive(Serialize)]
pub struct BatchTokenizeResult {
    pub inputs: Vec<String>,
    pub token_ids: Vec<Vec<u32>>,
}

impl BatchTokenizeResult {
    pub(crate) fn from_encoded(
        inputs: Vec<String>,
        encoded: Vec<Vec<sigil_core::vocab::EncodedToken>>,
    ) -> Self {
        Self {
            inputs,
            token_ids: encoded
                .into_iter()
                .map(|tokens| tokens.into_iter().map(|token| token.token_id).collect())
                .collect(),
        }
    }
}

#[derive(Serialize)]
pub struct DecodeResult {
    pub ids: Vec<u32>,
    pub text: String,
}

#[derive(Serialize)]
pub struct BatchDecodeResult {
    pub batches: Vec<Vec<u32>>,
    pub texts: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BenchmarkTiming {
    pub rounds: usize,
    pub items: usize,
    pub tokens: usize,
    pub elapsed_ns: u128,
    pub ns_per_token: u128,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub vocab: String,
    pub rounds: usize,
    pub batch_size: usize,
    pub special_token_mode: BenchmarkSpecialTokenMode,
    pub expected_parity: bool,
    pub items: usize,
    pub sequential: BenchmarkTiming,
    pub parallel: BenchmarkTiming,
    pub outputs_match: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkCorrectnessBaseline {
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub vocab: String,
    pub rounds: usize,
    pub batch_size: usize,
    pub special_token_mode: BenchmarkSpecialTokenMode,
    pub expected_parity: bool,
    pub items: usize,
    pub outputs_match: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BenchmarkTimingBaseline {
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub vocab: String,
    pub rounds: usize,
    pub batch_size: usize,
    pub special_token_mode: BenchmarkSpecialTokenMode,
    pub expected_parity: bool,
    pub items: usize,
    pub sequential_ns_per_token: u128,
    pub parallel_ns_per_token: u128,
    pub max_regression_pct: u32,
}

#[derive(Clone, Debug)]
pub struct BenchmarkComparisonReport {
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub correctness_path: PathBuf,
    pub timing_path: PathBuf,
    pub expected_parity: bool,
    pub observed_parity: bool,
    pub sequential_baseline_ns_per_token: u128,
    pub sequential_observed_ns_per_token: u128,
    pub parallel_baseline_ns_per_token: u128,
    pub parallel_observed_ns_per_token: u128,
    pub max_regression_pct: u32,
    pub sequential_regression_pct: u128,
    pub parallel_regression_pct: u128,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BurnInTelemetryBundle {
    pub schema_version: u32,
    pub deployment_mode: String,
    pub monitor_shadow_enabled: bool,
    pub representative_corpora: Vec<String>,
    pub false_positive_rate: f64,
    pub false_positive_rate_threshold: Option<f64>,
    pub unresolved_high_severity_findings: u32,
    pub rollback_ready: bool,
    pub captured_at_unix_ms: Option<u64>,
    pub source: Option<String>,
    pub evidence_refs: Vec<String>,
    pub notes: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BurnInBenchmarkSummary {
    #[serde(default)]
    pub name: String,
    pub preset: String,
    pub corpus: String,
    pub vocab: String,
    #[serde(default)]
    pub expected_parity: bool,
    #[serde(default)]
    pub outputs_match: bool,
}

impl BenchmarkCorrectnessBaseline {
    fn from_result(result: &BenchmarkResult) -> Self {
        Self {
            name: result.name.clone(),
            preset: result.preset.clone(),
            corpus: result.corpus.clone(),
            vocab: result.vocab.clone(),
            rounds: result.rounds,
            batch_size: result.batch_size,
            special_token_mode: result.special_token_mode,
            expected_parity: result.expected_parity,
            items: result.items,
            outputs_match: result.outputs_match,
        }
    }
}

impl From<&BenchmarkResult> for BenchmarkCorrectnessBaseline {
    fn from(result: &BenchmarkResult) -> Self {
        Self::from_result(result)
    }
}

impl BenchmarkTimingBaseline {
    fn from_result(result: &BenchmarkResult) -> Self {
        Self {
            name: result.name.clone(),
            preset: result.preset.clone(),
            corpus: result.corpus.clone(),
            vocab: result.vocab.clone(),
            rounds: result.rounds,
            batch_size: result.batch_size,
            special_token_mode: result.special_token_mode,
            expected_parity: result.expected_parity,
            items: result.items,
            sequential_ns_per_token: result.sequential.ns_per_token,
            parallel_ns_per_token: result.parallel.ns_per_token,
            max_regression_pct: BENCHMARK_MAX_REGRESSION_PCT,
        }
    }

    pub(crate) fn metadata_matches(&self, other: &Self) -> bool {
        self.name == other.name
            && self.preset == other.preset
            && self.corpus == other.corpus
            && self.vocab == other.vocab
            && self.rounds == other.rounds
            && self.batch_size == other.batch_size
            && self.special_token_mode == other.special_token_mode
            && self.expected_parity == other.expected_parity
            && self.items == other.items
            && self.max_regression_pct == other.max_regression_pct
    }
}

impl From<&BenchmarkResult> for BenchmarkTimingBaseline {
    fn from(result: &BenchmarkResult) -> Self {
        Self::from_result(result)
    }
}

impl BenchmarkComparisonReport {
    pub(crate) fn to_message(&self) -> String {
        format!(
            "benchmark comparison failed\n  name: {}\n  preset: {}\n  corpus: {}\n  correctness baseline: {}\n  timing baseline: {}\n  expected parity: {}\n  observed parity: {}\n  sequential baseline ns/token: {}\n  sequential observed ns/token: {}\n  sequential regression: {}%\n  parallel baseline ns/token: {}\n  parallel observed ns/token: {}\n  parallel regression: {}%\n  max regression: {}%",
            self.name,
            self.preset,
            self.corpus,
            self.correctness_path.display(),
            self.timing_path.display(),
            self.expected_parity,
            self.observed_parity,
            self.sequential_baseline_ns_per_token,
            self.sequential_observed_ns_per_token,
            self.sequential_regression_pct,
            self.parallel_baseline_ns_per_token,
            self.parallel_observed_ns_per_token,
            self.parallel_regression_pct,
            self.max_regression_pct,
        )
    }
}
