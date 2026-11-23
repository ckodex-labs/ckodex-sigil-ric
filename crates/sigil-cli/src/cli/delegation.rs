//! `sigil-cli` lease and envelope commands (RIC §4.4).

use crate::cli::types::*;
use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use sigil_core::signing::ReceiptSigner;
use std::fs;

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

/// Seconds since the Unix epoch, or 0 when the clock is before it.
fn unix_now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Writes `value` as pretty JSON to `path`.
fn write_pretty_json<T: Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    fs::write(path, json).with_context(|| format!("write {}", path.display()))
}

/// Creates a new root or delegated capability lease.
pub fn lease_create_command(
    command: &LeaseCreateCommand,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<sigil_core::CapabilityLease> {
    use sigil_core::{Capability, CapabilityLease};
    use std::collections::BTreeSet;

    let representation_digest = lease_representation_digest(command)?;
    let capabilities: BTreeSet<Capability> = command.capabilities.iter().cloned().collect();
    let now = unix_now_secs();

    let lease: CapabilityLease = if let Some(ref parent_path) = command.parent {
        let parent_lease = load_lease_from_path(parent_path)?;
        delegate_lease(
            command,
            &parent_lease,
            capabilities,
            representation_digest,
            now,
            signer,
        )?
    } else {
        issue_root_lease(command, capabilities, representation_digest, now, signer)
    };

    if let Some(ref out_path) = command.out {
        write_pretty_json(out_path, &lease)?;
    }

    Ok(lease)
}

/// The digest a new lease binds to: from `--receipt` when given, else `--representation-digest`.
fn lease_representation_digest(command: &LeaseCreateCommand) -> Result<String> {
    if let Some(ref receipt_path) = command.receipt {
        let receipt = load_receipt_from_path(receipt_path)?;
        Ok(receipt.canonical_digest)
    } else if let Some(ref digest) = command.representation_digest {
        Ok(digest.clone())
    } else {
        Err(anyhow!(
            "either --receipt or --representation-digest must be provided"
        ))
    }
}

fn delegate_lease(
    command: &LeaseCreateCommand,
    parent_lease: &sigil_core::CapabilityLease,
    capabilities: std::collections::BTreeSet<sigil_core::Capability>,
    representation_digest: String,
    now: u64,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<sigil_core::CapabilityLease> {
    use sigil_core::{DelegationRequest, delegate};

    let request = DelegationRequest {
        delegatee: command.delegatee.clone(),
        capabilities,
        authority_ceiling: command.ceiling,
        representation_digest,
        validity_seconds: command.validity,
    };
    delegate(
        parent_lease,
        &request,
        now,
        parent_lease.revocation_epoch,
        signer,
    )
    .map_err(|e| anyhow!("delegation failed: {e}"))
}

fn issue_root_lease(
    command: &LeaseCreateCommand,
    capabilities: std::collections::BTreeSet<sigil_core::Capability>,
    representation_digest: String,
    now: u64,
    signer: Option<&dyn ReceiptSigner>,
) -> sigil_core::CapabilityLease {
    use sigil_core::{RootLeaseParams, create_root_lease};

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
}

/// Verifies a capability lease or full delegation chain.
pub fn lease_verify_command(command: &LeaseVerifyCommand) -> Result<LeaseVerificationOutcome> {
    use sigil_core::{CapabilityLease, validate_chain, validate_lease};

    let now = command.now.unwrap_or_else(unix_now_secs);

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
        let verdict = validate_chain(&chain, now, registry.as_ref(), command.key.as_deref());
        Ok(lease_outcome(chain.last(), chain.len(), verdict))
    } else if let Some(ref lease_path) = command.lease {
        let lease = load_lease_from_path(lease_path)?;
        let verdict = validate_lease(&lease, now, registry.as_ref(), command.key.as_deref());
        Ok(lease_outcome(Some(&lease), 1, verdict))
    } else {
        Err(anyhow!("either --lease or --chain must be specified"))
    }
}

/// Reports a validation verdict against the lease at the end of the chain.
fn lease_outcome<E: std::fmt::Display>(
    lease: Option<&sigil_core::CapabilityLease>,
    chain_length: usize,
    verdict: std::result::Result<(), E>,
) -> LeaseVerificationOutcome {
    LeaseVerificationOutcome {
        valid: verdict.is_ok(),
        lease_id: lease.map(|l| l.lease_id.clone()),
        depth: lease.map(|l| l.depth),
        delegatee: lease.map(|l| l.delegatee.clone()),
        authority_ceiling: lease.map(|l| l.authority_ceiling.to_string()),
        chain_length: Some(chain_length),
        error: verdict.err().map(|e| e.to_string()),
    }
}

/// Creates and signs an agent envelope binding a task receipt to a lease.
pub fn envelope_create_command(
    command: &EnvelopeCreateCommand,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<sigil_core::AgentEnvelope> {
    use sigil_core::AgentEnvelope;

    let lease = load_lease_from_path(&command.lease)?;
    let receipt = load_receipt_from_path(&command.receipt)?;

    if lease.representation_digest != receipt.canonical_digest {
        return Err(anyhow!(
            "representation digest mismatch: lease specifies {}, receipt canonical digest is {}",
            lease.representation_digest,
            receipt.canonical_digest
        ));
    }

    let payload = envelope_payload(command)?;
    let envelope_id = new_envelope_id(&lease, &receipt, payload.len(), unix_now_secs());

    let mut envelope = AgentEnvelope {
        envelope_id,
        lease,
        receipt,
        payload,
        signature: None,
    };
    if let Some(signer) = signer {
        sign_envelope(&mut envelope, signer);
    }

    if let Some(ref out_path) = command.out {
        write_pretty_json(out_path, &envelope)?;
    }

    Ok(envelope)
}

/// The task payload: `--payload`, else the contents of `--payload-file`, else empty.
fn envelope_payload(command: &EnvelopeCreateCommand) -> Result<String> {
    if let Some(ref p) = command.payload {
        Ok(p.clone())
    } else if let Some(ref path) = command.payload_file {
        fs::read_to_string(path).with_context(|| format!("read payload file {}", path.display()))
    } else {
        Ok(String::new())
    }
}

fn new_envelope_id(
    lease: &sigil_core::CapabilityLease,
    receipt: &sigil_core::RepresentationReceipt,
    payload_len: usize,
    now: u64,
) -> String {
    use sha2::{Digest, Sha384};
    use sigil_core::signing::hex_digest;

    let seed = format!(
        "envelope|{}|{}|{}|{}",
        lease.lease_id, receipt.canonical_digest, payload_len, now
    );
    let mut hasher = Sha384::new();
    hasher.update(seed.as_bytes());
    let id_hash = hex_digest(&hasher.finalize());
    format!("env_{}", &id_hash[..16])
}

fn sign_envelope(envelope: &mut sigil_core::AgentEnvelope, signer: &dyn ReceiptSigner) {
    use sigil_core::signing::{ReceiptSignature, hex_digest};

    let msg = envelope.canonical_message();
    let sig_bytes = signer.sign(msg.as_bytes());
    envelope.signature = Some(ReceiptSignature {
        algorithm: signer.algorithm(),
        key_id: signer.key_id(),
        signature: hex_digest(&sig_bytes),
    });
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
