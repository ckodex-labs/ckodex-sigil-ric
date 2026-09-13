use crate::cli::benchmark::*;
use crate::cli::benchmark_render::*;
use crate::cli::results::*;
use crate::cli::types::*;
use clap::Parser;
use sigil_core::TokenizerActor;
use sigil_core::Vocab;
use std::fs;
use std::path::PathBuf;

#[allow(clippy::module_inception)]
mod tests {
    use super::*;

    fn bench_root() -> PathBuf {
        PathBuf::from(BENCH_ROOT)
    }

    fn preset_command() -> BenchCommand {
        BenchCommand {
            input: None,
            text: Vec::new(),
            manifest: None,
            corpus: None,
            preset: BenchmarkPreset::Small,
            format: BenchmarkOutputFormat::Human,
            output: None,
            baseline_dir: None,
            refresh_baselines: false,
            rounds: None,
            batch_size: None,
            special_token_mode: None,
        }
    }

    #[test]
    fn benchmark_alias_parses_as_bench() {
        let cli = Cli::try_parse_from(["sigil", "benchmark", "--text", "hello"])
            .expect("benchmark alias should parse");
        assert!(matches!(cli.command, Commands::Bench(_)));
    }

    #[test]
    fn benchmark_presets_load_checked_in_manifests() {
        let manifest = load_benchmark_manifest(&bench_root().join("manifests/small.json"))
            .expect("small manifest should load");
        assert_eq!(manifest.name, "small");
        assert_eq!(manifest.corpus, "small");
        assert_eq!(manifest.vocab, "cl100k_base");
        assert_eq!(manifest.rounds, 20);
        assert_eq!(manifest.batch_size, 2);
        assert_eq!(
            manifest.special_token_mode,
            BenchmarkSpecialTokenMode::AllowAll
        );
        assert!(manifest.expected_parity);

        let corpus = load_benchmark_corpus(&manifest.corpus).expect("small corpus should load");
        assert!(!corpus.is_empty());
        assert!(corpus.iter().any(|entry| entry.contains("<|endoftext|>")));
    }

    #[test]
    fn benchmark_runs_match_across_batch_sizes() {
        let command = preset_command();
        let resolved = resolve_benchmark("cl100k_base", &command).expect("preset should resolve");
        let vocab = Vocab::tiktoken(resolved.vocab.clone());
        let actor = TokenizerActor::new(vocab.clone());

        let mut batch_one = resolved.clone();
        batch_one.batch_size = 1;
        let mut batch_three = resolved;
        batch_three.batch_size = 3;

        let report_one =
            run_benchmark(&vocab, &actor, batch_one).expect("batch size 1 should work");
        let report_three =
            run_benchmark(&vocab, &actor, batch_three).expect("batch size 3 should work");

        assert!(report_one.outputs_match);
        assert!(report_three.outputs_match);
        assert_eq!(report_one.sequential.tokens, report_three.sequential.tokens);
        assert_eq!(report_one.parallel.tokens, report_three.parallel.tokens);
        assert_eq!(report_one.expected_parity, report_three.expected_parity);
    }

    #[test]
    fn benchmark_smokes_all_presets() {
        for preset in [
            BenchmarkPreset::Small,
            BenchmarkPreset::Medium,
            BenchmarkPreset::Stress,
        ] {
            let mut command = preset_command();
            command.preset = preset;
            let resolved =
                resolve_benchmark("cl100k_base", &command).expect("preset should resolve");
            let vocab = Vocab::tiktoken(resolved.vocab.clone());
            let actor = TokenizerActor::new(vocab.clone());
            let report = run_benchmark(&vocab, &actor, resolved).expect("benchmark should run");
            assert!(report.outputs_match);
            assert!(report.expected_parity);
        }
    }

    #[test]
    fn benchmark_output_formats_are_stable() {
        let result = BenchmarkResult {
            name: "small".to_string(),
            preset: "small".to_string(),
            corpus: "small".to_string(),
            vocab: "cl100k_base".to_string(),
            rounds: 2,
            batch_size: 2,
            special_token_mode: BenchmarkSpecialTokenMode::AllowAll,
            expected_parity: true,
            items: 2,
            sequential: BenchmarkTiming {
                rounds: 2,
                items: 2,
                tokens: 8,
                elapsed_ns: 100,
                ns_per_token: 12,
            },
            parallel: BenchmarkTiming {
                rounds: 2,
                items: 2,
                tokens: 8,
                elapsed_ns: 80,
                ns_per_token: 10,
            },
            outputs_match: true,
        };

        let human = render_benchmark_output(&result, BenchmarkOutputFormat::Human).unwrap();
        assert!(human.contains("benchmark small"));
        assert!(human.contains("outputs-match: true"));

        let json = render_benchmark_output(&result, BenchmarkOutputFormat::Json).unwrap();
        assert!(json.contains("\"corpus\": \"small\""));
        assert!(json.contains("\"outputs_match\": true"));

        let csv = render_benchmark_output(&result, BenchmarkOutputFormat::Csv).unwrap();
        assert!(csv.starts_with("name,preset,corpus,vocab"));
        assert!(csv.contains("\"small\""));

        let jsonl = render_benchmark_output(&result, BenchmarkOutputFormat::Jsonl).unwrap();
        assert!(jsonl.ends_with('\n'));
        assert!(jsonl.contains("\"special_token_mode\":\"allow_all\""));
    }

    #[test]
    fn benchmark_manifest_mode_rejects_tuning_overrides() {
        let command = BenchCommand {
            manifest: Some(bench_root().join("manifests/small.json")),
            rounds: Some(3),
            ..preset_command()
        };

        let err = resolve_benchmark("cl100k_base", &command).unwrap_err();
        assert!(err.to_string().contains("authoritative"));
    }

    #[test]
    fn benchmark_baselines_round_trip_and_compare() {
        let result = BenchmarkResult {
            name: "small".to_string(),
            preset: "small".to_string(),
            corpus: "small".to_string(),
            vocab: "cl100k_base".to_string(),
            rounds: 20,
            batch_size: 2,
            special_token_mode: BenchmarkSpecialTokenMode::AllowAll,
            expected_parity: true,
            items: 6,
            sequential: BenchmarkTiming {
                rounds: 20,
                items: 6,
                tokens: 800,
                elapsed_ns: 54_643_583,
                ns_per_token: 68_304,
            },
            parallel: BenchmarkTiming {
                rounds: 20,
                items: 6,
                tokens: 800,
                elapsed_ns: 29_557_417,
                ns_per_token: 36_946,
            },
            outputs_match: true,
        };

        let dir = temp_benchmark_dir("roundtrip");
        write_benchmark_baselines(&dir, &result).expect("baselines should write");

        let correctness_path = benchmark_baseline_correctness_path(&dir, "small");
        let timing_path = benchmark_baseline_timing_path(&dir, "small");
        assert!(correctness_path.exists());
        assert!(timing_path.exists());

        let report = compare_benchmark_baselines(&dir, &result).expect("comparison should pass");
        assert_eq!(report.expected_parity, report.observed_parity);
        assert_eq!(report.sequential_regression_pct, 0);
        assert_eq!(report.parallel_regression_pct, 0);
        assert_eq!(report.correctness_path, correctness_path);
        assert_eq!(report.timing_path, timing_path);
    }

    #[test]
    fn benchmark_baseline_comparison_reports_regression() {
        let baseline = BenchmarkResult {
            name: "small".to_string(),
            preset: "small".to_string(),
            corpus: "small".to_string(),
            vocab: "cl100k_base".to_string(),
            rounds: 20,
            batch_size: 2,
            special_token_mode: BenchmarkSpecialTokenMode::AllowAll,
            expected_parity: true,
            items: 6,
            sequential: BenchmarkTiming {
                rounds: 20,
                items: 6,
                tokens: 800,
                elapsed_ns: 54_643_583,
                ns_per_token: 68_304,
            },
            parallel: BenchmarkTiming {
                rounds: 20,
                items: 6,
                tokens: 800,
                elapsed_ns: 29_557_417,
                ns_per_token: 36_946,
            },
            outputs_match: true,
        };
        let dir = temp_benchmark_dir("regression");
        write_benchmark_baselines(&dir, &baseline).expect("baselines should write");

        let mut observed = baseline.clone();
        observed.parallel.ns_per_token = 300_000;
        let err = compare_benchmark_baselines(&dir, &observed).unwrap_err();
        let message = err.to_string();
        assert!(message.contains("benchmark comparison failed"));
        assert!(message.contains("timing baseline"));
        assert!(message.contains("parallel regression"));
    }

    #[test]
    fn burn_in_telemetry_emitter_aggregates_benchmark_corpora() {
        let root = temp_benchmark_dir("telemetry");
        fs::create_dir_all(&root).expect("temp dir should be creatable");

        let small = benchmark_result("small", "small", 2);
        let medium = benchmark_result("medium", "medium", 4);
        let stress = benchmark_result("stress", "stress", 6);

        let small_path = root.join("small.json");
        let medium_path = root.join("medium.json");
        let stress_path = root.join("stress.json");
        fs::write(&small_path, serde_json::to_string_pretty(&small).unwrap()).unwrap();
        fs::write(&medium_path, serde_json::to_string_pretty(&medium).unwrap()).unwrap();
        fs::write(&stress_path, serde_json::to_string_pretty(&stress).unwrap()).unwrap();

        let command = BurnInTelemetryCommand {
            benchmark: vec![small_path.clone(), medium_path.clone(), stress_path.clone()],
            deployment_mode: BurnInDeploymentMode::Monitor,
            monitor_shadow_enabled: true,
            false_positive_rate: Some(0.0),
            false_positive_rate_threshold: Some(0.01),
            unresolved_high_severity_findings: 0,
            rollback_ready: true,
            source: Some("test-runtime".to_string()),
            captured_at_unix_ms: Some(42),
            note: Some("emitter smoke".to_string()),
            evidence_ref: vec!["bench/run-123".to_string()],
            output: None,
        };

        let telemetry = emit_burn_in_telemetry(&command).expect("telemetry should emit");
        assert_eq!(telemetry.schema_version, 1);
        assert_eq!(telemetry.deployment_mode, "monitor");
        assert!(telemetry.monitor_shadow_enabled);
        assert_eq!(
            telemetry.representative_corpora,
            vec![
                "medium".to_string(),
                "small".to_string(),
                "stress".to_string()
            ]
        );
        assert_eq!(telemetry.false_positive_rate, 0.0);
        assert_eq!(telemetry.false_positive_rate_threshold, Some(0.01));
        assert_eq!(telemetry.unresolved_high_severity_findings, 0);
        assert!(telemetry.rollback_ready);
        assert_eq!(telemetry.source.as_deref(), Some("test-runtime"));
        assert_eq!(telemetry.captured_at_unix_ms, Some(42));
        assert!(telemetry
            .evidence_refs
            .iter()
            .any(|value| value.contains("small.json")));
        assert!(telemetry
            .evidence_refs
            .iter()
            .any(|value| value.contains("bench/run-123")));
    }

    #[test]
    fn burn_in_telemetry_emitter_requires_benchmarks() {
        let command = BurnInTelemetryCommand {
            benchmark: Vec::new(),
            deployment_mode: BurnInDeploymentMode::Monitor,
            monitor_shadow_enabled: true,
            false_positive_rate: Some(0.0),
            false_positive_rate_threshold: None,
            unresolved_high_severity_findings: 0,
            rollback_ready: true,
            source: None,
            captured_at_unix_ms: None,
            note: None,
            evidence_ref: Vec::new(),
            output: None,
        };

        let err = emit_burn_in_telemetry(&command).unwrap_err();
        assert!(err.to_string().contains("at least one --benchmark"));
    }

    #[test]
    fn burn_in_telemetry_emitter_accepts_correctness_baselines() {
        let root = temp_benchmark_dir("telemetry-correctness");
        fs::create_dir_all(&root).expect("temp dir should be creatable");

        let summary = serde_json::json!({
            "name": "small",
            "preset": "small",
            "corpus": "small",
            "vocab": "cl100k_base",
            "expected_parity": true,
            "outputs_match": true,
        });
        let summary_path = root.join("small.json");
        fs::write(
            &summary_path,
            serde_json::to_string_pretty(&summary).unwrap(),
        )
        .unwrap();

        let command = BurnInTelemetryCommand {
            benchmark: vec![summary_path],
            deployment_mode: BurnInDeploymentMode::Monitor,
            monitor_shadow_enabled: true,
            false_positive_rate: Some(0.0),
            false_positive_rate_threshold: Some(0.01),
            unresolved_high_severity_findings: 0,
            rollback_ready: true,
            source: None,
            captured_at_unix_ms: None,
            note: None,
            evidence_ref: Vec::new(),
            output: None,
        };

        let telemetry = emit_burn_in_telemetry(&command).expect("telemetry should emit");
        assert_eq!(telemetry.representative_corpora, vec!["small".to_string()]);
        assert!(telemetry
            .evidence_refs
            .iter()
            .any(|value| value.contains("small.json")));
    }

    fn benchmark_result(name: &str, corpus: &str, items: usize) -> BenchmarkResult {
        BenchmarkResult {
            name: name.to_string(),
            preset: name.to_string(),
            corpus: corpus.to_string(),
            vocab: "cl100k_base".to_string(),
            rounds: 1,
            batch_size: 1,
            special_token_mode: BenchmarkSpecialTokenMode::Disallow,
            expected_parity: true,
            items,
            sequential: BenchmarkTiming {
                rounds: 1,
                items,
                tokens: 1,
                elapsed_ns: 1,
                ns_per_token: 1,
            },
            parallel: BenchmarkTiming {
                rounds: 1,
                items,
                tokens: 1,
                elapsed_ns: 1,
                ns_per_token: 1,
            },
            outputs_match: true,
        }
    }

    fn temp_benchmark_dir(label: &str) -> PathBuf {
        let unique = format!(
            "sigil-bench-{}-{}-{}",
            std::process::id(),
            label,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after epoch")
                .as_nanos()
        );
        std::env::temp_dir().join(unique)
    }
}
