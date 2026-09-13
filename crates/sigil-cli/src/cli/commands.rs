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

    fs::write(&command.out_private, private_pem)
        .with_context(|| format!("write {}", command.out_private.display()))?;
    // Private key material: restrict to the owner (best-effort on all platforms).
    restrict_private_key_permissions(&command.out_private);
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

    let (adapter_id, report, modality) = match command.modality.as_str() {
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
                    .map_err(|err| anyhow!("{err}"))?,
                adapter.modality(),
            )
        }
        "video" => {
            let adapter = sigil_perception::video::VideoAdapter;
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| anyhow!("{err}"))?,
                adapter.modality(),
            )
        }
        "document" => {
            let adapter = sigil_perception::document::DocumentAdapter;
            (
                adapter.adapter_id().to_string(),
                adapter
                    .perceive(&artifact)
                    .map_err(|err| anyhow!("{err}"))?,
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
                    .map_err(|err| anyhow!("{err}"))?,
                adapter.modality(),
            )
        }
    };

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
