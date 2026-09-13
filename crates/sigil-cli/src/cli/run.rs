use crate::cli::benchmark::*;
use crate::cli::benchmark_render::*;
use crate::cli::commands::*;
use crate::cli::helpers::*;
use crate::cli::output::*;
use crate::cli::results::*;
use crate::cli::types::*;
use anyhow::{anyhow, Context, Result};
use clap::Parser;
use sigil_core::signing::ReceiptSigner;
use sigil_core::types::{Provenance, TextSegment};
use sigil_core::vocab::SpecialTokenMode;
use sigil_core::{TokenizerActor, Vocab};
use sigil_mcp::{JsonlEvidenceSink, McpGate, McpScanConfig, McpSession};
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
    let policy = load_policy(cli.policy.as_ref())?;
    let vocab_name = cli.vocab.clone();
    let vocab = Vocab::tiktoken(vocab_name.clone());
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

    match cli.command {
        Commands::Keygen(command) => {
            let outcome = keygen_command(&command)?;
            print_json(&JsonResult { result: outcome })?;
        }
        Commands::Tokenize(command) => {
            let sigil = build_sigil(vocab, policy, receipt_signer.as_ref())?;
            let output = sigil.process_text_segments(&[TextSegment {
                text: &read_text(&command)?,
                provenance: Provenance::User,
            }])?;
            print_json(&JsonResult { result: output })?;
        }
        Commands::TokenizeBatch(command) => {
            let inputs = read_batch_text(&command)?;
            let encoded = if command.allow_specials {
                actor.encode_batch_with_specials(&inputs, SpecialTokenMode::AllowAll)?
            } else {
                actor.encode_batch(&inputs)?
            };
            print_json(&JsonResult {
                result: BatchTokenizeResult::from_encoded(inputs, encoded),
            })?;
        }
        Commands::Decode(command) => {
            let ids = read_token_ids(&command)?;
            let text = vocab.decode(&ids);
            print_json(&JsonResult {
                result: DecodeResult { ids, text },
            })?;
        }
        Commands::DecodeBatch(command) => {
            let batches = read_token_batches(&command)?;
            let texts = actor.decode_batch(&batches)?;
            print_json(&JsonResult {
                result: BatchDecodeResult { batches, texts },
            })?;
        }
        Commands::Bench(command) => {
            let benchmark = resolve_benchmark(&vocab_name, &command)?;
            let bench_vocab = Vocab::tiktoken(benchmark.vocab.clone());
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
            let rendered = render_benchmark_output(&result, command.format)?;
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
            let sigil = build_sigil(vocab, policy, receipt_signer.as_ref())?;
            let output = sigil.process_text_segments(&[TextSegment {
                text: &read_text(&command)?,
                provenance: Provenance::User,
            }])?;
            print_json(&JsonResult { result: output })?;
        }
        Commands::Mcp(command) => {
            let gate = McpGate::new(policy, McpScanConfig::default(), vocab)?;
            let mut session = match &command.evidence_log {
                Some(path) => McpSession::with_evidence_sink(
                    gate,
                    std::sync::Arc::new(std::sync::Mutex::new(JsonlEvidenceSink::open(path)?)),
                ),
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
            print_json(&JsonResult { result: inspection })?;
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
            print_json(&JsonResult { result: report })?;
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
            print_json(&JsonResult { result: assessment })?;
        }
        Commands::VerifyReceipt(command) => {
            let outcome = verify_receipt_command(&command)?;
            print_json(&JsonResult { result: outcome })?;
        }
        Commands::Attest(command) => {
            let envelope = attest_command(&command)?;
            print_json(&JsonResult { result: envelope })?;
        }
        Commands::Perceive(command) => {
            let outcome = perceive_command(command, policy, vocab, receipt_signer.as_ref())?;
            print_json(&JsonResult { result: outcome })?;
        }
        Commands::VerifyAttestation(command) => {
            let outcome = verify_attestation_command(&command)?;
            print_json(&JsonResult { result: outcome })?;
        }
        Commands::Sentinel(command) => {
            let model = SentinelModel::default();
            let text = read_command_text(&command.input, &command.text)?;
            let sigil_output = build_sigil(
                Vocab::tiktoken("cl100k_base"),
                policy,
                receipt_signer.as_ref(),
            )?
            .process_text_segments(&[TextSegment {
                text: &text,
                provenance: Provenance::User,
            }])?;
            let sentinel = model.classify(&text, Some(&sigil_output.assessment));
            if command.compose {
                let composite = compose_with_sigil(&sigil_output.assessment, &sentinel);
                print_json(&JsonResult { result: composite })?;
            } else {
                print_json(&JsonResult { result: sentinel })?;
            }
        }
    }

    Ok(())
}
