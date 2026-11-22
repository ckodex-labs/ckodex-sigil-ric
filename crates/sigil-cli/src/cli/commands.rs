use crate::cli::helpers::*;
use crate::cli::types::*;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sigil_core::EcdsaP384Signer;
use sigil_core::signing::ReceiptSigner;
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
    use sigil_core::receipt::{ReceiptVerifyError, verify_receipt};

    let contents = fs::read_to_string(&command.receipt)?;
    let mut value: serde_json::Value = serde_json::from_str(&contents)?;
    // Unwrap the CLI envelope (`{"result": …}`) if present, then accept
    // either a bare receipt object or a full SigilOutput (`receipt` field).
    if let Some(result) = value.get("result") {
        value = result.clone();
    }
    let receipt_value = value.get("receipt").unwrap_or(&value);
    let receipt: sigil_core::RepresentationReceipt = serde_json::from_value(receipt_value.clone())?;

    // The message is chosen by receipt_version: v2 receipts keep verifying,
    // v4 receipts also bind their consumed block.
    let error = verify_receipt(&receipt, &command.key)
        .err()
        .map(|err: ReceiptVerifyError| err.to_string());
    let signature = receipt.signature.as_ref();
    Ok(ReceiptVerificationOutcome {
        valid: error.is_none(),
        algorithm: signature.map(|s| s.algorithm.clone()),
        key_id: signature.map(|s| s.key_id.clone()),
        error,
    })
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
    // The in-toto predicate (ric/receipt/v2) has no consumed field: attesting
    // a media receipt would silently drop what the model was shown.
    if receipt.consumed.is_some() {
        return Err(anyhow!(
            "the attestation predicate cannot carry the receipt's consumed block yet"
        ));
    }
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
    use sigil_core::attestation::{DsseEnvelope, verify_attestation};

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
pub use super::delegation::*;
pub use super::perceive::*;
