use crate::cli::types::*;
use anyhow::{anyhow, Context, Result};
use sigil_core::engine::Sigil;
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_core::sink::{EvidenceSink, JsonlEvidenceSink};
use sigil_core::types::{EvidenceBundle, Verdict};
use sigil_core::{EcdsaP384Signer, Vocab};
use sigil_mcp::ResponseSchema;
use sigil_multimodal::MultimodalEngine;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;

pub fn load_policy(path: Option<&PathBuf>) -> Result<Policy> {
    match path {
        Some(path) => Ok(Policy::from_file(path)?),
        None => Ok(Policy::default()),
    }
}

/// Load the `--signing-key` PEM file into a shared signer, if provided.
pub fn load_signing_key(
    path: Option<&PathBuf>,
) -> Result<Option<std::sync::Arc<dyn ReceiptSigner>>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let pem =
        fs::read_to_string(path).with_context(|| format!("read signing key {}", path.display()))?;
    let signer = EcdsaP384Signer::from_pkcs8_pem(&pem)
        .map_err(|_| anyhow!("invalid PKCS#8 PEM signing key in {}", path.display()))?;
    Ok(Some(std::sync::Arc::new(signer)))
}

/// Open the shared `--evidence-log` JSONL sink, if the flag is set.
pub fn open_evidence_sink(
    path: Option<&PathBuf>,
) -> Result<Option<std::sync::Arc<std::sync::Mutex<JsonlEvidenceSink>>>> {
    path.map(|p| {
        JsonlEvidenceSink::open(p)
            .map(|sink| std::sync::Arc::new(std::sync::Mutex::new(sink)))
            .with_context(|| format!("open evidence log {}", p.display()))
    })
    .transpose()
}

/// Construct the core engine, attaching the receipt signer and evidence
/// sink when configured.
pub fn build_sigil(
    vocab: Vocab,
    policy: Policy,
    receipt_signer: Option<&std::sync::Arc<dyn ReceiptSigner>>,
    evidence_sink: Option<&std::sync::Arc<std::sync::Mutex<JsonlEvidenceSink>>>,
) -> Result<Sigil> {
    let terminal_escapes = policy.scan.terminal_escapes.enabled;
    let mut sigil = Sigil::new(vocab, policy)?;
    if let Some(signer) = receipt_signer {
        sigil = sigil.with_receipt_signer(std::sync::Arc::clone(signer));
    }
    if let Some(sink) = evidence_sink {
        let sink: std::sync::Arc<std::sync::Mutex<dyn EvidenceSink<EvidenceBundle> + Send>> =
            sink.clone();
        sigil = sigil.with_evidence_sink(sink);
    }
    if terminal_escapes {
        let scanner: std::sync::Arc<
            dyn sigil_core::terminal::TerminalSequenceScanner + Send + Sync,
        > = std::sync::Arc::new(sigil_vt::VtScanner::new());
        sigil = sigil.with_terminal_scanner(scanner);
    }
    Ok(sigil)
}

/// Construct the multimodal engine, attaching the receipt signer when configured.
pub fn build_multimodal_engine(
    policy: Policy,
    vocab: Vocab,
    receipt_signer: Option<&std::sync::Arc<dyn ReceiptSigner>>,
) -> Result<MultimodalEngine> {
    let engine = MultimodalEngine::new(policy, vocab)?;
    Ok(match receipt_signer {
        Some(signer) => engine.with_receipt_signer(std::sync::Arc::clone(signer)),
        None => engine,
    })
}

pub fn read_text(command: &TextCommand) -> Result<String> {
    read_command_text(&command.input, &command.text)
}

pub fn read_batch_text(command: &BatchTextCommand) -> Result<Vec<String>> {
    match (&command.input, command.text.is_empty()) {
        (Some(path), true) if path.as_os_str() == "-" => Ok(serde_json::from_str(&read_stdin()?)?),
        (Some(path), true) => load_json_array(Some(path)),
        (None, false) => Ok(command.text.clone()),
        (Some(_), false) => Err(anyhow!("--input and --text are mutually exclusive")),
        (None, true) => Err(anyhow!(
            "provide either --input or one or more --text values"
        )),
    }
}

pub fn read_token_ids(command: &TokenIdsCommand) -> Result<Vec<u32>> {
    if command.ids.is_empty() {
        Err(anyhow!("provide at least one --ids value"))
    } else {
        Ok(command.ids.clone())
    }
}

pub fn read_token_batches(command: &TokenIdsBatchCommand) -> Result<Vec<Vec<u32>>> {
    match command.input.as_ref() {
        Some(path) if path.as_os_str() == "-" => Ok(serde_json::from_str(&read_stdin()?)?),
        Some(path) => load_json_array(Some(path)),
        None => Err(anyhow!(
            "provide --input with a JSON array of token-id arrays"
        )),
    }
}

pub fn read_command_text(input: &Option<PathBuf>, text: &Option<String>) -> Result<String> {
    match (input, text) {
        (Some(path), None) if path.as_os_str() == "-" => read_stdin(),
        (Some(path), None) => {
            Ok(fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?)
        }
        (None, Some(text)) => Ok(text.clone()),
        (Some(_), Some(_)) => Err(anyhow!("--input and --text are mutually exclusive")),
        // Piped stdin is an implicit source so `cat payload | sigil-cli scan`
        // works; an interactive terminal errors instead of blocking. Empty
        // piped stdin still errors — a vacuous Allow must never be silent.
        (None, None) if !std::io::stdin().is_terminal() => {
            let piped = read_stdin()?;
            if piped.is_empty() {
                Err(anyhow!(
                    "stdin was empty — provide --input, --text, or piped input"
                ))
            } else {
                Ok(piped)
            }
        }
        (None, None) => Err(anyhow!("provide --input, --text, or piped stdin")),
    }
}

fn read_stdin() -> Result<String> {
    use std::io::Read;
    let mut buf = String::new();
    std::io::stdin()
        .lock()
        .read_to_string(&mut buf)
        .context("read stdin")?;
    Ok(buf)
}

/// Map an assessment verdict onto the process exit code selected by
/// --fail-on: Deny exits 2 under `deny`/`flag`, Flag exits 1 only under
/// `flag`, `never` always exits 0. Output is flushed first so emitted
/// JSON is never truncated by the early exit.
pub fn exit_on_verdict(verdict: &Verdict, fail_on: FailOn) {
    let code = match verdict {
        Verdict::Deny { .. } if fail_on != FailOn::Never => 2,
        Verdict::Flag { .. } if fail_on == FailOn::Flag => 1,
        _ => 0,
    };
    if code != 0 {
        use std::io::Write;
        let _ = std::io::stdout().flush();
        std::process::exit(code);
    }
}

pub fn parse_schema(path: &PathBuf) -> Result<ResponseSchema> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

pub fn load_json_array<T: for<'de> serde::Deserialize<'de>>(
    path: Option<&PathBuf>,
) -> Result<Vec<T>> {
    match path {
        Some(path) => {
            let text =
                fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
            Ok(serde_json::from_str(&text)?)
        }
        None => Ok(Vec::new()),
    }
}
