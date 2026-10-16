use crate::cli::helpers::*;
use crate::cli::types::*;
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use sigil_core::policy::Policy;
use sigil_core::signing::ReceiptSigner;
use sigil_core::{EcdsaP384Signer, Vocab};
use sigil_multimodal::perception::channels_to_modal_inputs;
use sigil_perception::{ImageAdapter, PerceptionAdapter};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize)]
pub struct KeygenOutcome {
    pub key_id: String,
    pub verification_key_hex: String,
    pub private_key_path: String,
    pub public_key_path: String,
}

pub fn keygen_command(command: &KeygenCommand) -> Result<KeygenOutcome> {
    let signer = EcdsaP384Signer::generate().map_err(|e| anyhow!("{e}"))?;
    let private_pem = signer.to_pkcs8_pem().map_err(|e| anyhow!("{e}"))?;
    let public_pem = signer.public_key_pem().map_err(|e| anyhow!("{e}"))?;

    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true).mode(0o600);
        let mut file = options
            .open(&command.out_private)
            .with_context(|| format!("create {}", command.out_private.display()))?;
        file.write_all(private_pem.as_bytes())
            .with_context(|| format!("write {}", command.out_private.display()))?;
    }
    #[cfg(not(unix))]
    {
        fs::write(&command.out_private, private_pem)
            .with_context(|| format!("write {}", command.out_private.display()))?;
    }
    fs::write(&command.out_public, public_pem)
        .with_context(|| format!("write {}", command.out_public.display()))?;

    Ok(KeygenOutcome {
        key_id: signer.key_id(),
        verification_key_hex: signer.verification_key_hex(),
        private_key_path: command.out_private.display().to_string(),
        public_key_path: command.out_public.display().to_string(),
    })
}

pub fn restrict_private_key_permissions(path: &PathBuf) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Outcome of `sigil-cli verify-receipt`. `valid` is true only when the
/// signature exists, the algorithm is the mandated ECDSA P-384, and the
/// signature verifies over the reconstructed receipt message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReceiptVerificationOutcome {
    pub valid: bool,
    pub algorithm: Option<String>,
    pub key_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn verify_receipt_command(
    command: &VerifyReceiptCommand,
) -> Result<ReceiptVerificationOutcome> {
    use sigil_core::signing::{receipt_message, verify_receipt_signature};

    let contents = fs::read_to_string(&command.receipt)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;
    // Unwrap the CLI envelope (`{"result": …}`) if present, then accept
    // either a bare receipt object or a full SigilOutput (`receipt` field).
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let receipt_value = value.get("receipt").unwrap_or(&value);
    let receipt: sigil_core::RepresentationReceipt = serde_json::from_value(receipt_value.clone())?;

    let Some(signature) = &receipt.signature else {
        return Ok(ReceiptVerificationOutcome {
            valid: false,
            algorithm: None,
            key_id: None,
            error: Some("receipt is unsigned".to_string()),
        });
    };

    let message = receipt_message(
        &receipt.raw_digest,
        &receipt.canonical_digest,
        &receipt.digest_algorithm,
        &receipt.normalization,
        &receipt.vocab,
        receipt.token_count,
    );

    let outcome = match verify_receipt_signature(&message, signature, &command.key) {
        Ok(()) => ReceiptVerificationOutcome {
            valid: true,
            algorithm: Some(signature.algorithm.clone()),
            key_id: Some(signature.key_id.clone()),
            error: None,
        },
        Err(err) => ReceiptVerificationOutcome {
            valid: false,
            algorithm: Some(signature.algorithm.clone()),
            key_id: Some(signature.key_id.clone()),
            error: Some(err.to_string()),
        },
    };
    Ok(outcome)
}

/// Outcome of `sigil-cli verify-attestation`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationVerificationOutcome {
    pub valid: bool,
    pub payload_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub fn attest_command(command: &AttestCommand) -> Result<sigil_core::attestation::DsseEnvelope> {
    use sigil_core::attestation::attest_receipt;

    let signer = load_signing_key(Some(&command.signing_key))?
        .ok_or_else(|| anyhow!("signing key required for attestation"))?;
    let receipt = load_receipt(&command.receipt)?;
    let signature = receipt
        .signature
        .ok_or_else(|| anyhow!("receipt is unsigned — attest a signed receipt"))?;
    let envelope = attest_receipt(
        &receipt.raw_digest,
        &receipt.canonical_digest,
        &receipt.digest_algorithm,
        &receipt.normalization,
        &receipt.vocab,
        receipt.token_count,
        signer.as_ref(),
    )
    .map_err(|e| anyhow!("{e}"))?;
    let _ = signature; // receipt signature attests provenance; DSSE covers the statement
    Ok(envelope)
}

pub fn verify_attestation_command(
    command: &VerifyAttestationCommand,
) -> Result<AttestationVerificationOutcome> {
    use sigil_core::attestation::{verify_attestation, DsseEnvelope};

    let contents = fs::read_to_string(&command.attestation)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;
    // Unwrap the CLI envelope (`{"result": …}`) if present.
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let envelope: DsseEnvelope = serde_json::from_value(value)?;
    match verify_attestation(&envelope, &command.key) {
        Ok(()) => Ok(AttestationVerificationOutcome {
            valid: true,
            payload_type: Some(envelope.payload_type),
            error: None,
        }),
        Err(err) => Ok(AttestationVerificationOutcome {
            valid: false,
            payload_type: Some(envelope.payload_type),
            error: Some(err.to_string()),
        }),
    }
}

/// Load a receipt from a bare object, a SigilOutput, or the CLI envelope.
pub fn load_receipt(path: &PathBuf) -> Result<sigil_core::RepresentationReceipt> {
    let contents = fs::read_to_string(path)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let receipt_value = value.get("receipt").unwrap_or(&value);
    Ok(serde_json::from_value(receipt_value.clone())?)
}

/// Sniff container magic to a modality name. `None` means "no opinion" —
/// unknown or text-ish bytes leave the declared hint alone.
fn sniff_modality(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n")
        || bytes.starts_with(b"\xFF\xD8\xFF")
        || bytes.starts_with(b"GIF8")
    {
        Some("image")
    } else if bytes.starts_with(b"RIFF") && bytes.len() >= 12 && &bytes[8..12] == b"WAVE"
        || bytes.starts_with(b"fLaC")
    {
        Some("audio")
    } else if bytes.len() >= 8 && &bytes[4..8] == b"ftyp" {
        Some("video")
    } else if bytes.starts_with(b"%PDF") {
        Some("document")
    } else {
        None
    }
}

/// Outcome of `sigil-cli perceive`: the adapter's channel report plus, when
/// `--analyze` is set, the kernel's fusion audit over those channels.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PerceiveOutcome {
    pub adapter_id: String,
    pub report: sigil_perception::PerceptionReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub analysis: Option<sigil_multimodal::MultimodalAssessment>,
}

pub fn perceive_command(
    command: PerceiveCommand,
    policy: Policy,
    vocab: Vocab,
    receipt_signer: Option<&std::sync::Arc<dyn ReceiptSigner>>,
) -> Result<PerceiveOutcome> {
    let bytes =
        fs::read(&command.input).with_context(|| format!("read {}", command.input.display()))?;
    let artifact = sigil_multimodal::ArtifactRef {
        source_id: command.input.display().to_string(),
        bytes: &bytes,
        media_type: None,
    };

    // Declared-vs-actual routing: a --modality hint that contradicts the
    // magic bytes should not silently decode-fail — route to the sniffed
    // adapter and record the override as evidence. Adapters produce
    // channels either way; the kernel's judgment is untouched.
    let sniffed = sniff_modality(&bytes);
    let routed = sniffed.filter(|s| *s != command.modality.as_str());
    let effective_modality = sniffed.unwrap_or(command.modality.as_str());

    // Reject adapter flags that cannot apply to the routed modality —
    // a silently-ignored flag reads as "configured" to the operator.
    for (flag, present, allowed) in [
        (
            "--ocr-binary",
            command.ocr_binary.is_some(),
            ["image", "video", "document"].as_slice(),
        ),
        (
            "--ocr-args",
            !command.ocr_args.is_empty(),
            ["image", "video", "document"].as_slice(),
        ),
        (
            "--transcript-binary",
            command.transcript_binary.is_some(),
            ["audio", "video"].as_slice(),
        ),
        (
            "--transcript-args",
            !command.transcript_args.is_empty(),
            ["audio", "video"].as_slice(),
        ),
        (
            "--render-binary",
            command.render_binary.is_some(),
            ["document"].as_slice(),
        ),
        (
            "--render-args",
            !command.render_args.is_empty(),
            ["document"].as_slice(),
        ),
        (
            "--ffmpeg-binary",
            command.ffmpeg_binary.is_some(),
            ["video"].as_slice(),
        ),
    ] {
        if present && !allowed.contains(&effective_modality) {
            return Err(anyhow!(
                "{flag} applies to --modality {}; effective modality is {effective_modality}",
                allowed.join("|"),
            ));
        }
    }

    let (adapter_id, mut report, modality) = match effective_modality {
        "audio" => {
            let transcript = match &command.transcript_binary {
                Some(binary) => Some(
                    sigil_perception::audio::ExternalTranscript::pin(
                        binary.clone(),
                        if command.transcript_args.is_empty() {
                            Vec::new()
                        } else {
                            command
                                .transcript_args
                                .split_whitespace()
                                .map(str::to_string)
                                .collect()
                        },
                        "external".to_string(),
                    )
                    .map_err(|err| anyhow!("pin transcript binary: {err}"))?,
                ),
                None => None,
            };
            let adapter = sigil_perception::audio::AudioAdapter { transcript };
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| perceive_err(err, &bytes, effective_modality))?,
                adapter.modality(),
            )
        }
        "video" => {
            // Stream extraction is opt-in via --ffmpeg-binary. OCR of the
            // frame stream needs the pipe (frames never exist without
            // ffmpeg), so --ocr-binary without it is a config error.
            let split_args = |args: &str| args.split_whitespace().map(str::to_string).collect();
            let stream_extract = match &command.ffmpeg_binary {
                Some(ffmpeg) => Some(
                    sigil_perception::video::StreamExtract::pin(
                        ffmpeg.clone(),
                        command
                            .ocr_binary
                            .clone()
                            .map(|b| (b, split_args(&command.ocr_args))),
                        command
                            .transcript_binary
                            .clone()
                            .map(|b| (b, split_args(&command.transcript_args))),
                    )
                    .map_err(|err| anyhow!("pin video stream extractors: {err}"))?,
                ),
                None => {
                    if command.ocr_binary.is_some() || command.transcript_binary.is_some() {
                        return Err(anyhow!("video stream extraction needs --ffmpeg-binary"));
                    }
                    None
                }
            };
            let adapter = sigil_perception::video::VideoAdapter { stream_extract };
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| perceive_err(err, &bytes, effective_modality))?,
                adapter.modality(),
            )
        }
        "document" => {
            // Render-compare needs both halves: a renderer (PDF → pixels)
            // and an OCR (pixels → text). Wiring only one is a config error,
            // not a silent skip.
            let render_compare = match (&command.render_binary, &command.ocr_binary) {
                (Some(renderer), Some(ocr_bin)) => {
                    if !command
                        .render_args
                        .split_whitespace()
                        .any(|a| a == "-singlefile")
                    {
                        return Err(anyhow!(
                            "render-compare renders one page per run — \
                             --render-args must include -singlefile"
                        ));
                    }
                    Some(sigil_perception::document::RenderCompare {
                        renderer: sigil_perception::ExternalPipe::pin(
                            renderer.clone(),
                            command
                                .render_args
                                .split_whitespace()
                                .map(str::to_string)
                                .collect(),
                            "external".to_string(),
                        )
                        .map_err(|err| anyhow!("pin render binary: {err}"))?,
                        ocr: sigil_perception::ExternalOcr::pin(
                            ocr_bin.clone(),
                            command
                                .ocr_args
                                .split_whitespace()
                                .map(str::to_string)
                                .collect(),
                            "external".to_string(),
                        )
                        .map_err(|err| anyhow!("pin ocr binary: {err}"))?,
                    })
                }
                (None, None) => None,
                _ => {
                    return Err(anyhow!(
                        "render-compare needs both --render-binary and --ocr-binary"
                    ))
                }
            };
            let adapter = sigil_perception::document::DocumentAdapter { render_compare };
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| perceive_err(err, &bytes, effective_modality))?,
                adapter.modality(),
            )
        }
        "code" => {
            let adapter = sigil_perception::code::CodeAdapter;
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| perceive_err(err, &bytes, effective_modality))?,
                adapter.modality(),
            )
        }
        _ => {
            let ocr = match &command.ocr_binary {
                Some(binary) => Some(
                    sigil_perception::ExternalOcr::pin(
                        binary.clone(),
                        if command.ocr_args.is_empty() {
                            Vec::new()
                        } else {
                            command
                                .ocr_args
                                .split_whitespace()
                                .map(str::to_string)
                                .collect()
                        },
                        "external".to_string(),
                    )
                    .map_err(|err| anyhow!("pin ocr binary: {err}"))?,
                ),
                None => None,
            };
            let adapter = ImageAdapter { ocr };
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| perceive_err(err, &bytes, effective_modality))?,
                adapter.modality(),
            )
        }
    };

    if let Some(sniffed) = routed {
        report.properties.push((
            "sigil.modality_routed".to_string(),
            format!(
                "declared {} but magic says {sniffed} — routed to {sniffed}",
                command.modality
            ),
        ));
    }

    let analysis = if command.analyze {
        let inputs = channels_to_modal_inputs(&report, modality);
        let engine = build_multimodal_engine(policy, vocab, receipt_signer)?;
        Some(engine.analyze(&inputs)?)
    } else {
        None
    };

    Ok(PerceiveOutcome {
        adapter_id,
        report,
        analysis,
    })
}

/// Decode failures name the routed modality and suggest a fix — bare
/// "artifact decoding failed" is not actionable for a new user. Input
/// bytes are never echoed into the error.
fn perceive_err(
    err: sigil_multimodal::perception::PerceptionError,
    bytes: &[u8],
    modality: &str,
) -> anyhow::Error {
    use sigil_multimodal::perception::PerceptionError;
    match err {
        PerceptionError::DecodeFailed => {
            let hint = if std::str::from_utf8(bytes).is_ok() {
                "the input is UTF-8 text; try --modality document or --modality code"
            } else {
                "the bytes do not match the routed adapter's format; \
                 check the file or pick a different --modality"
            };
            anyhow!("cannot decode input as {modality}: {hint}")
        }
        other => anyhow!("{other}"),
    }
}

/// Outcome of sigil-cli lease-verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LeaseVerificationOutcome {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub depth: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegatee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_ceiling: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_length: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Outcome of sigil-cli envelope-verify.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnvelopeVerificationOutcome {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub envelope_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delegatee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub representation_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn load_receipt_from_path(path: &std::path::Path) -> Result<sigil_core::RepresentationReceipt> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read receipt from {}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parse receipt JSON from {}", path.display()))?;
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let receipt_value = value.get("receipt").unwrap_or(&value);
    let receipt: sigil_core::RepresentationReceipt = serde_json::from_value(receipt_value.clone())
        .with_context(|| format!("deserialize RepresentationReceipt from {}", path.display()))?;
    Ok(receipt)
}

fn load_lease_from_path(path: &std::path::Path) -> Result<sigil_core::CapabilityLease> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("read lease from {}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parse lease JSON from {}", path.display()))?;
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let lease_value = value.get("lease").unwrap_or(&value);
    let lease: sigil_core::CapabilityLease = serde_json::from_value(lease_value.clone())
        .with_context(|| format!("deserialize CapabilityLease from {}", path.display()))?;
    Ok(lease)
}

fn load_envelope_from_path(path: &std::path::Path) -> Result<sigil_core::AgentEnvelope> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read envelope from {}", path.display()))?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)
        .with_context(|| format!("parse envelope JSON from {}", path.display()))?;
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let envelope: sigil_core::AgentEnvelope = serde_json::from_value(value)
        .with_context(|| format!("deserialize AgentEnvelope from {}", path.display()))?;
    Ok(envelope)
}

fn load_revocation_registry_from_path(
    path: &std::path::Path,
) -> Result<sigil_core::RevocationRegistry> {
    let contents = fs::read_to_string(path)
        .with_context(|| format!("read revocation registry from {}", path.display()))?;
    let registry: sigil_core::RevocationRegistry = serde_json::from_str(&contents)
        .with_context(|| format!("parse RevocationRegistry JSON from {}", path.display()))?;
    Ok(registry)
}

/// Creates a new root or delegated capability lease.
pub fn lease_create_command(
    command: &LeaseCreateCommand,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<sigil_core::CapabilityLease> {
    use sigil_core::{
        create_root_lease, delegate, Capability, CapabilityLease, DelegationRequest,
        RootLeaseParams,
    };
    use std::collections::BTreeSet;
    use std::time::{SystemTime, UNIX_EPOCH};

    let representation_digest = if let Some(ref receipt_path) = command.receipt {
        let receipt = load_receipt_from_path(receipt_path)?;
        receipt.canonical_digest
    } else if let Some(ref digest) = command.representation_digest {
        digest.clone()
    } else {
        return Err(anyhow!(
            "either --receipt or --representation-digest must be provided"
        ));
    };

    let capabilities: BTreeSet<Capability> = command.capabilities.iter().cloned().collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let lease: CapabilityLease = if let Some(ref parent_path) = command.parent {
        let parent_lease = load_lease_from_path(parent_path)?;
        let request = DelegationRequest {
            delegatee: command.delegatee.clone(),
            capabilities,
            authority_ceiling: command.ceiling,
            representation_digest,
            validity_seconds: command.validity,
        };
        delegate(
            &parent_lease,
            &request,
            now,
            parent_lease.revocation_epoch,
            signer,
        )
        .map_err(|e| anyhow!("delegation failed: {e}"))?
    } else {
        let principal = command
            .principal
            .clone()
            .unwrap_or_else(|| "agent://root".to_string());
        let mut params = RootLeaseParams::new(principal, &command.delegatee, representation_digest);
        params.capabilities = capabilities;
        params.authority_ceiling = command.ceiling;
        params.max_depth = command.max_depth;
        params.validity_seconds = command.validity;
        params.issued_at = now;
        params.revocation_epoch = 1;
        create_root_lease(params, signer)
    };

    if let Some(ref out_path) = command.out {
        let json = serde_json::to_string_pretty(&lease)?;
        fs::write(out_path, json).with_context(|| format!("write {}", out_path.display()))?;
    }

    Ok(lease)
}

/// Verifies a capability lease or full delegation chain.
pub fn lease_verify_command(command: &LeaseVerifyCommand) -> Result<LeaseVerificationOutcome> {
    use sigil_core::{validate_chain, validate_lease, CapabilityLease};
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = command.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let registry = if let Some(ref reg_path) = command.revocation_registry {
        Some(load_revocation_registry_from_path(reg_path)?)
    } else {
        None
    };

    if let Some(ref chain_path) = command.chain {
        let contents = fs::read_to_string(chain_path)
            .with_context(|| format!("read chain from {}", chain_path.display()))?;
        let chain: Vec<CapabilityLease> = serde_json::from_str(&contents)
            .with_context(|| format!("parse chain JSON from {}", chain_path.display()))?;
        let outcome = match validate_chain(&chain, now, registry.as_ref(), command.key.as_deref()) {
            Ok(()) => LeaseVerificationOutcome {
                valid: true,
                lease_id: chain.last().map(|l| l.lease_id.clone()),
                depth: chain.last().map(|l| l.depth),
                delegatee: chain.last().map(|l| l.delegatee.clone()),
                authority_ceiling: chain.last().map(|l| l.authority_ceiling.to_string()),
                chain_length: Some(chain.len()),
                error: None,
            },
            Err(e) => LeaseVerificationOutcome {
                valid: false,
                lease_id: chain.last().map(|l| l.lease_id.clone()),
                depth: chain.last().map(|l| l.depth),
                delegatee: chain.last().map(|l| l.delegatee.clone()),
                authority_ceiling: chain.last().map(|l| l.authority_ceiling.to_string()),
                chain_length: Some(chain.len()),
                error: Some(e.to_string()),
            },
        };
        Ok(outcome)
    } else if let Some(ref lease_path) = command.lease {
        let lease = load_lease_from_path(lease_path)?;
        let outcome = match validate_lease(&lease, now, registry.as_ref(), command.key.as_deref()) {
            Ok(()) => LeaseVerificationOutcome {
                valid: true,
                lease_id: Some(lease.lease_id.clone()),
                depth: Some(lease.depth),
                delegatee: Some(lease.delegatee.clone()),
                authority_ceiling: Some(lease.authority_ceiling.to_string()),
                chain_length: Some(1),
                error: None,
            },
            Err(e) => LeaseVerificationOutcome {
                valid: false,
                lease_id: Some(lease.lease_id.clone()),
                depth: Some(lease.depth),
                delegatee: Some(lease.delegatee.clone()),
                authority_ceiling: Some(lease.authority_ceiling.to_string()),
                chain_length: Some(1),
                error: Some(e.to_string()),
            },
        };
        Ok(outcome)
    } else {
        Err(anyhow!("either --lease or --chain must be specified"))
    }
}

/// Creates and signs an agent envelope binding a task receipt to a lease.
pub fn envelope_create_command(
    command: &EnvelopeCreateCommand,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<sigil_core::AgentEnvelope> {
    use sha2::{Digest, Sha384};
    use sigil_core::signing::{hex_digest, ReceiptSignature};
    use sigil_core::AgentEnvelope;
    use std::time::{SystemTime, UNIX_EPOCH};

    let lease = load_lease_from_path(&command.lease)?;
    let receipt = load_receipt_from_path(&command.receipt)?;

    if lease.representation_digest != receipt.canonical_digest {
        return Err(anyhow!(
            "representation digest mismatch: lease specifies {}, receipt canonical digest is {}",
            lease.representation_digest,
            receipt.canonical_digest
        ));
    }

    let payload = if let Some(ref p) = command.payload {
        p.clone()
    } else if let Some(ref path) = command.payload_file {
        fs::read_to_string(path).with_context(|| format!("read payload file {}", path.display()))?
    } else {
        String::new()
    };

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let seed = format!(
        "envelope|{}|{}|{}|{}",
        lease.lease_id,
        receipt.canonical_digest,
        payload.len(),
        now
    );
    let mut hasher = Sha384::new();
    hasher.update(seed.as_bytes());
    let id_hash = hex_digest(&hasher.finalize());
    let envelope_id = format!("env_{}", &id_hash[..16]);

    let mut envelope = AgentEnvelope {
        envelope_id,
        lease,
        receipt,
        payload,
        signature: None,
    };

    if let Some(s) = signer {
        let msg = envelope.canonical_message();
        let sig_bytes = s.sign(msg.as_bytes());
        envelope.signature = Some(ReceiptSignature {
            algorithm: s.algorithm(),
            key_id: s.key_id(),
            signature: hex_digest(&sig_bytes),
        });
    }

    if let Some(ref out_path) = command.out {
        let json = serde_json::to_string_pretty(&envelope)?;
        fs::write(out_path, json).with_context(|| format!("write {}", out_path.display()))?;
    }

    Ok(envelope)
}

/// Verifies an agent envelope and its bound representation receipt.
pub fn envelope_verify_command(
    command: &EnvelopeVerifyCommand,
) -> Result<EnvelopeVerificationOutcome> {
    use sigil_core::validate_envelope;
    use std::time::{SystemTime, UNIX_EPOCH};

    let envelope = load_envelope_from_path(&command.envelope)?;
    let now = command.now.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    });

    let registry = if let Some(ref reg_path) = command.revocation_registry {
        Some(load_revocation_registry_from_path(reg_path)?)
    } else {
        None
    };

    let outcome = match validate_envelope(&envelope, now, registry.as_ref(), command.key.as_deref())
    {
        Ok(()) => EnvelopeVerificationOutcome {
            valid: true,
            envelope_id: Some(envelope.envelope_id.clone()),
            lease_id: Some(envelope.lease.lease_id.clone()),
            delegatee: Some(envelope.lease.delegatee.clone()),
            representation_digest: Some(envelope.lease.representation_digest.clone()),
            error: None,
        },
        Err(e) => EnvelopeVerificationOutcome {
            valid: false,
            envelope_id: Some(envelope.envelope_id.clone()),
            lease_id: Some(envelope.lease.lease_id.clone()),
            delegatee: Some(envelope.lease.delegatee.clone()),
            representation_digest: Some(envelope.lease.representation_digest.clone()),
            error: Some(e.to_string()),
        },
    };

    Ok(outcome)
}

/// Revokes a capability lease in a revocation registry and optionally advances epoch.
pub fn lease_revoke_command(
    command: &LeaseRevokeCommand,
) -> Result<sigil_core::RevocationRegistry> {
    use sigil_core::RevocationRegistry;

    let mut registry = if command.registry.exists() {
        load_revocation_registry_from_path(&command.registry)?
    } else {
        RevocationRegistry::new()
    };

    registry.revoke(&command.lease_id);
    if let Some(ref parent) = command.parent_id {
        registry.record_lineage(&command.lease_id, parent);
    }
    if command.advance_epoch {
        registry.advance_epoch();
    }

    let out_path = command.out.as_ref().unwrap_or(&command.registry);
    let json = serde_json::to_string_pretty(&registry)?;
    fs::write(out_path, json)
        .with_context(|| format!("write revocation registry {}", out_path.display()))?;

    Ok(registry)
}
