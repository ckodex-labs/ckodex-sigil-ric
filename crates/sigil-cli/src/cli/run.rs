use crate::cli::helpers::*;
use crate::cli::output::*;
use crate::cli::types::*;
use anyhow::{Result, anyhow};
use clap::Parser;
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_core::sink::JsonlEvidenceSink;
use sigil_core::{TokenizerActor, Vocab};
use sigil_sigstore::{OidcSource, SigstoreKeylessSigner};
use std::sync::{Arc, Mutex};

mod bench;
mod gate;
mod proof;
mod text;

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

/// Everything the global flags resolve to before a subcommand runs.
struct Context {
    printer: Printer,
    policy: Policy,
    vocab_name: String,
    vocab: Vocab,
    actor: TokenizerActor,
    receipt_signer: Option<Arc<dyn ReceiptSigner>>,
    evidence_sink: Option<Arc<Mutex<JsonlEvidenceSink>>>,
}

impl Context {
    fn resolve(cli: &Cli) -> Result<Self> {
        let printer = Printer::detect(cli.format, cli.color);
        let policy = load_policy(cli.policy.as_ref())?;
        let vocab_name = cli.vocab.clone();
        let vocab = Vocab::tiktoken(vocab_name.clone());
        vocab.validate().map_err(|_| {
            anyhow!("unknown tokenizer vocab `{vocab_name}` (try cl100k_base or o200k_base)")
        })?;
        let actor = TokenizerActor::new(vocab.clone());
        let receipt_signer = resolve_receipt_signer(cli)?;
        let evidence_sink = open_evidence_sink(cli.evidence_log.as_ref())?;
        Ok(Self {
            printer,
            policy,
            vocab_name,
            vocab,
            actor,
            receipt_signer,
            evidence_sink,
        })
    }
}

fn resolve_receipt_signer(cli: &Cli) -> Result<Option<Arc<dyn ReceiptSigner>>> {
    if let Some(key_path) = cli.signing_key.as_ref() {
        load_signing_key(Some(key_path))
    } else if cli.sigstore_keyless {
        let signer: Arc<dyn ReceiptSigner> = Arc::new(
            SigstoreKeylessSigner::new(&OidcSource::Ambient, false)
                .map_err(|err| anyhow!("sigstore keyless: {err}"))?,
        );
        eprintln!(
            "sigstore keyless: Fulcio certificate obtained (key_id {})",
            signer.key_id()
        );
        Ok(Some(signer))
    } else {
        Ok(None)
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    let ctx = Context::resolve(&cli)?;
    match cli.command {
        Commands::Keygen(command) => proof::keygen(&ctx, &command),
        Commands::Completions(command) => {
            text::completions(&command);
            Ok(())
        }
        Commands::Tokenize(command) | Commands::Scan(command) => text::scan(ctx, &command),
        Commands::TokenizeBatch(command) => text::tokenize_batch(&ctx, &command),
        Commands::Decode(command) => text::decode(&ctx, &command),
        Commands::DecodeBatch(command) => text::decode_batch(&ctx, &command),
        Commands::Bench(command) => bench::bench(&ctx, &command),
        Commands::Telemetry(command) => bench::telemetry(&command),
        Commands::Mcp(command) => gate::mcp(ctx, command),
        Commands::Probe(command) => gate::probe(&ctx, &command),
        Commands::Multimodal(command) => gate::multimodal(ctx, command),
        Commands::VerifyReceipt(command) => proof::verify_receipt(&ctx, &command),
        Commands::Attest(command) => proof::attest(&ctx, &command),
        Commands::Perceive(command) => gate::perceive(ctx, command),
        Commands::VlmRequest(command) => gate::vlm_request(&ctx, &command),
        Commands::VerifyAttestation(command) => proof::verify_attestation(&ctx, &command),
        Commands::Sentinel(command) => gate::sentinel(ctx, &command),
        Commands::LeaseCreate(command) => proof::lease_create(&ctx, &command),
        Commands::LeaseVerify(command) => proof::lease_verify(&ctx, &command),
        Commands::EnvelopeCreate(command) => proof::envelope_create(&ctx, &command),
        Commands::EnvelopeVerify(command) => proof::envelope_verify(&ctx, &command),
        Commands::LeaseRevoke(command) => proof::lease_revoke(&ctx, &command),
    }
}
