use crate::cli::benchmark::*;
use crate::cli::benchmark_render::*;
use crate::cli::commands::*;
use crate::cli::helpers::*;
use crate::cli::output::*;
use crate::cli::results::*;
use crate::cli::types::*;
use crate::cli::{human, human_reports};
use anyhow::{anyhow, Context, Result};
use clap::{CommandFactory, Parser};
use sigil_core::signing::ReceiptSigner;
use sigil_core::types::{Provenance, TextSegment};
use sigil_core::vocab::SpecialTokenMode;
use sigil_core::{TokenizerActor, Vocab};
use sigil_mcp::{McpEvidenceRecord, McpGate, McpScanConfig, McpSession};
use sigil_multimodal::{ModalInput, Modality};
use sigil_probe::{
    BaselineProfile, BoundaryProbe, CanaryCase, FingerprintProbe, ProbeConfig, ProbeEngine,
    ProbeSample,
};
use sigil_s::{compose_with_sigil, SentinelModel};
use sigil_sigstore::{OidcSource, SigstoreKeylessSigner};
use std::fs;

pub fn run() -> Result<()> {
    let cli = Cli::parse();
    let format = cli.format;
    dispatch(cli).map_err(|err| {
        // Errors print here so --format json callers get a machine-readable
        // envelope; main only maps Err to exit 1.
        if matches!(format, OutputFormat::Json) {
            eprintln!("{}", serde_json::json!({ "error": format!("{err:#}") }));
        } else {
            eprintln!("{err:?}");
        }
        err
    })
}

fn dispatch(cli: Cli) -> Result<()> {
    let printer = Printer::detect(cli.format, cli.color);
    let policy = load_policy(cli.policy.as_ref())?;
    let vocab_name = cli.vocab.clone();
    let vocab = Vocab::tiktoken(vocab_name.clone());
    vocab.validate().map_err(|_| {
        anyhow!("unknown tokenizer vocab `{vocab_name}` (try cl100k_base or o200k_base)")
    })?;
    let actor = TokenizerActor::new(vocab.clone());
    let receipt_signer = if let Some(key_path) = cli.signing_key.as_ref() {
        load_signing_key(Some(key_path))?
    } else if cli.sigstore_keyless {
        let signer: std::sync::Arc<dyn ReceiptSigner> = std::sync::Arc::new(
            SigstoreKeylessSigner::new(&OidcSource::Ambient, false)
                .map_err(|err| anyhow!("sigstore keyless: {err}"))?,
        );
        eprintln!(
            "sigstore keyless: Fulcio certificate obtained (key_id {})",
            signer.key_id()
        );
        Some(signer)
    } else {
        None
    };
    let evidence_sink = open_evidence_sink(cli.evidence_log.as_ref())?;

    match cli.command {
        Commands::Keygen(command) => {
            let outcome = keygen_command(&command)?;
            printer.emit(&outcome, |o| human_reports::render_keygen(o, printer.color))?;
        }
        Commands::Completions(command) => {
            clap_complete::generate(
                command.shell,
                &mut Cli::command(),
                "sigil-cli",
                &mut std::io::stdout(),
            );
        }
        Commands::Tokenize(command) => {
            let sigil = build_sigil(
                vocab,
                policy,
                receipt_signer.as_ref(),
                evidence_sink.as_ref(),
            )?;
            let text = read_text(&command)?;
            let explain = command.explain;
            let fail_on = command.fail_on;
            let output = sigil.process_text_segments(&[TextSegment {
                text: &text,
                provenance: Provenance::User,
            }])?;
            printer.emit(&output, |o| {
                human::render_sigil(o, Some(&text), explain, printer.color)
            })?;
            exit_on_verdict(&output.assessment.verdict, fail_on);
        }
        Commands::TokenizeBatch(command) => {
            let inputs = read_batch_text(&command)?;
            let encoded = if command.allow_specials {
                actor.encode_batch_with_specials(&inputs, SpecialTokenMode::AllowAll)?
            } else {
                actor.encode_batch(&inputs)?
            };
            let result = BatchTokenizeResult::from_encoded(inputs, encoded);
            printer.emit(&result, |r| {
                human_reports::render_batch_tokenize(r, printer.color)
            })?;
        }
        Commands::Decode(command) => {
            let ids = read_token_ids(&command)?;
            let text = vocab.decode(&ids);
            let result = DecodeResult { ids, text };
            printer.emit(&result, |r| human_reports::render_decode(r, printer.color))?;
        }
        Commands::DecodeBatch(command) => {
            let batches = read_token_batches(&command)?;
            let texts = actor.decode_batch(&batches)?;
            let result = BatchDecodeResult { batches, texts };
            printer.emit(&result, |r| {
                human_reports::render_batch_decode(r, printer.color)
            })?;
        }
        Commands::Bench(command) => {
            let benchmark = resolve_benchmark(&vocab_name, &command)?;
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
            if let Some(path) = command.output.as_ref() {
                fs::write(path, rendered).with_context(|| format!("write {}", path.display()))?;
            } else {
                print!("{rendered}");
                if !rendered.ends_with('\n') {
                    println!();
                }
            }
        }
        Commands::Telemetry(command) => {
            let telemetry = emit_burn_in_telemetry(&command)?;
            let rendered = serde_json::to_string_pretty(&telemetry)? + "\n";
            if let Some(path) = command.output.as_ref() {
                fs::write(path, rendered).with_context(|| format!("write {}", path.display()))?;
            } else {
                print!("{rendered}");
            }
        }
        Commands::Scan(command) => {
            let sigil = build_sigil(
                vocab,
                policy,
                receipt_signer.as_ref(),
                evidence_sink.as_ref(),
            )?;
            let text = read_text(&command)?;
            let explain = command.explain;
            let fail_on = command.fail_on;
            let output = sigil.process_text_segments(&[TextSegment {
                text: &text,
                provenance: Provenance::User,
            }])?;
            printer.emit(&output, |o| {
                human::render_sigil(o, Some(&text), explain, printer.color)
            })?;
            exit_on_verdict(&output.assessment.verdict, fail_on);
        }
        Commands::Mcp(command) => {
            let gate = McpGate::new(policy, McpScanConfig::default(), vocab)?;
            let mut session = match &evidence_sink {
                Some(sink) => {
                    let sink: std::sync::Arc<
                        std::sync::Mutex<dyn sigil_mcp::EvidenceSink<McpEvidenceRecord> + Send>,
                    > = sink.clone();
                    McpSession::with_evidence_sink(gate, sink)
                }
                None => McpSession::new(gate),
            };
            let response = read_command_text(&command.input, &command.text)?;
            let schema = match command.schema {
                Some(path) => Some(parse_schema(&path)?),
                None => None,
            };
            let inspection = session.inspect_response(
                &command.server_id,
                &command.request_hash,
                &response,
                schema.as_ref(),
            )?;
            printer.emit(&inspection, |i| human_reports::render_mcp(i, printer.color))?;
            exit_on_verdict(&inspection.verdict, command.fail_on);
        }
        Commands::Probe(command) => {
            let samples: Vec<ProbeSample> = load_json_array(command.samples.as_ref())?;
            let canaries: Vec<CanaryCase> =
                load_json_array(command.canaries.as_ref()).unwrap_or_else(|_| Vec::new());
            let fingerprints: Vec<FingerprintProbe> =
                load_json_array(command.fingerprints.as_ref()).unwrap_or_else(|_| Vec::new());
            let boundaries: Vec<BoundaryProbe> =
                load_json_array(command.boundaries.as_ref()).unwrap_or_else(|_| Vec::new());
            let engine = ProbeEngine::new(
                BaselineProfile::from_samples(&samples),
                ProbeConfig::default(),
            );
            let report = engine.analyze(&samples, &canaries, &fingerprints, &boundaries);
            printer.emit(&report, |r| human_reports::render_probe(r, printer.color))?;
        }
        Commands::Multimodal(command) => {
            let engine = build_multimodal_engine(policy, vocab, receipt_signer.as_ref())?;
            let mut inputs = Vec::new();
            if let Some(text) = command.system {
                inputs.push(ModalInput {
                    modality: Modality::Text,
                    content: text,
                    provenance: Provenance::System,
                    source_id: Some("system".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.text {
                inputs.push(ModalInput {
                    modality: Modality::Text,
                    content: text,
                    provenance: Provenance::User,
                    source_id: Some("user".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.vision {
                inputs.push(ModalInput {
                    modality: Modality::Vision,
                    content: text,
                    provenance: Provenance::McpTool,
                    source_id: Some("vision".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.audio {
                inputs.push(ModalInput {
                    modality: Modality::Audio,
                    content: text,
                    provenance: Provenance::McpTool,
                    source_id: Some("audio".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.video {
                inputs.push(ModalInput {
                    modality: Modality::Video,
                    content: text,
                    provenance: Provenance::McpTool,
                    source_id: Some("video".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.code {
                inputs.push(ModalInput {
                    modality: Modality::Code,
                    content: text,
                    provenance: Provenance::User,
                    source_id: Some("code".to_string()),
                    ..Default::default()
                });
            }
            if let Some(text) = command.document {
                inputs.push(ModalInput {
                    modality: Modality::Document,
                    content: text,
                    provenance: Provenance::Retrieval,
                    source_id: Some("document".to_string()),
                    ..Default::default()
                });
            }
            let assessment = engine.analyze(&inputs)?;
            printer.emit(&assessment, |a| {
                human_reports::render_multimodal(a, printer.color)
            })?;
            exit_on_verdict(&assessment.verdict, command.fail_on);
        }
        Commands::VerifyReceipt(command) => {
            let outcome = verify_receipt_command(&command)?;
            printer.emit(&outcome, |o| {
                human_reports::render_verification(
                    o.valid,
                    &format!(
                        "  algorithm   {}\n  key id      {}\n",
                        o.algorithm.as_deref().unwrap_or("-"),
                        o.key_id.as_deref().unwrap_or("-")
                    ),
                    o.error.as_deref(),
                    printer.color,
                )
            })?;
        }
        Commands::Attest(command) => {
            let envelope = attest_command(&command)?;
            printer.emit(&envelope, |e| {
                human_reports::render_attest(e, printer.color)
            })?;
        }
        Commands::Perceive(command) => {
            let fail_on = command.fail_on;
            let outcome = perceive_command(command, policy, vocab, receipt_signer.as_ref())?;
            printer.emit(&outcome, |o| {
                human_reports::render_perceive(o, printer.color)
            })?;
            if let Some(analysis) = &outcome.analysis {
                exit_on_verdict(&analysis.verdict, fail_on);
            }
        }
        Commands::VerifyAttestation(command) => {
            let outcome = verify_attestation_command(&command)?;
            printer.emit(&outcome, |o| {
                human_reports::render_verification(
                    o.valid,
                    &format!(
                        "  payload     {}\n",
                        o.payload_type.as_deref().unwrap_or("-")
                    ),
                    o.error.as_deref(),
                    printer.color,
                )
            })?;
        }
        Commands::Sentinel(command) => {
            let model = SentinelModel::default();
            let text = read_command_text(&command.input, &command.text)?;
            let sigil_output = build_sigil(
                Vocab::tiktoken("cl100k_base"),
                policy,
                receipt_signer.as_ref(),
                evidence_sink.as_ref(),
            )?
            .process_text_segments(&[TextSegment {
                text: &text,
                provenance: Provenance::User,
            }])?;
            let sentinel = model.classify(&text, Some(&sigil_output.assessment));
            if command.compose {
                let composite = compose_with_sigil(&sigil_output.assessment, &sentinel);
                printer.emit(&composite, |c| {
                    human_reports::render_composite(c, printer.color)
                })?;
                exit_on_verdict(&composite.final_verdict, command.fail_on);
            } else {
                printer.emit(&sentinel, |s| {
                    human_reports::render_sentinel(s, printer.color)
                })?;
            }
        }
    }

    Ok(())
}
