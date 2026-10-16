use crate::delegation::types::*;
use crate::signing::{hex_digest, verify_receipt_signature, ReceiptSignature, ReceiptSigner};
use sha2::{Digest, Sha384};

/// Creates a new root capability lease.
pub fn create_root_lease(
    params: RootLeaseParams,
    signer: Option<&dyn ReceiptSigner>,
) -> CapabilityLease {
    let expires_at = params.issued_at.saturating_add(params.validity_seconds);

    let seed = format!(
        "root|{}|{}|{}|{}|{}",
        params.principal,
        params.delegatee,
        params.representation_digest,
        params.issued_at,
        expires_at
    );
    let mut hasher = Sha384::new();
    hasher.update(seed.as_bytes());
    let id_hash = hex_digest(&hasher.finalize());
    let lease_id = format!("lease_root_{}", &id_hash[..16]);

    let mut lease = CapabilityLease {
        lease_id,
        parent_lease_id: None,
        principal: params.principal,
        delegatee: params.delegatee,
        depth: 0,
        max_depth: params.max_depth,
        capabilities: params.capabilities,
        authority_ceiling: params.authority_ceiling,
        representation_digest: params.representation_digest,
        issued_at: params.issued_at,
        expires_at,
        revocation_epoch: params.revocation_epoch,
        signature: None,
    };

    if let Some(s) = signer {
        let msg = lease.canonical_message();
        let sig_bytes = s.sign(msg.as_bytes());
        lease.signature = Some(ReceiptSignature {
            algorithm: s.algorithm(),
            key_id: s.key_id(),
            signature: hex_digest(&sig_bytes),
        });
    }

    lease
}

/// Delegates an attenuated child lease from an active parent lease.
pub fn delegate(
    parent: &CapabilityLease,
    request: &DelegationRequest,
    now: u64,
    epoch: u64,
    signer: Option<&dyn ReceiptSigner>,
) -> Result<CapabilityLease, DelegationError> {
    if now > parent.expires_at {
        return Err(DelegationError::LeaseExpired {
            now,
            expires_at: parent.expires_at,
        });
    }
    if now < parent.issued_at {
        return Err(DelegationError::LeasePremature {
            now,
            issued_at: parent.issued_at,
        });
    }

    let child_depth = parent.depth.saturating_add(1);
    if child_depth > parent.max_depth {
        return Err(DelegationError::MaxDepthExceeded {
            depth: parent.depth,
            max_depth: parent.max_depth,
        });
    }

    if request.representation_digest.trim().is_empty() {
        return Err(DelegationError::RepresentationMismatch {
            expected: parent.representation_digest.clone(),
            actual: "empty".to_string(),
        });
    }

    if let Err(unauthorized_cap) = is_attenuated(&request.capabilities, &parent.capabilities) {
        return Err(DelegationError::CapabilityEscalation {
            requested: unauthorized_cap,
        });
    }

    if !parent.authority_ceiling.permits(request.authority_ceiling) {
        return Err(DelegationError::AuthorityCeilingEscalation {
            child: request.authority_ceiling,
            parent: parent.authority_ceiling,
        });
    }

    let child_expires_at = now
        .saturating_add(request.validity_seconds)
        .min(parent.expires_at);

    let seed = format!(
        "child|{}|{}|{}|{}|{}",
        parent.lease_id, request.delegatee, request.representation_digest, now, child_expires_at
    );
    let mut hasher = Sha384::new();
    hasher.update(seed.as_bytes());
    let id_hash = hex_digest(&hasher.finalize());
    let lease_id = format!("lease_d{}_{}", child_depth, &id_hash[..16]);

    let mut lease = CapabilityLease {
        lease_id,
        parent_lease_id: Some(parent.lease_id.clone()),
        principal: parent.delegatee.clone(),
        delegatee: request.delegatee.clone(),
        depth: child_depth,
        max_depth: parent.max_depth,
        capabilities: request.capabilities.clone(),
        authority_ceiling: request.authority_ceiling,
        representation_digest: request.representation_digest.clone(),
        issued_at: now,
        expires_at: child_expires_at,
        revocation_epoch: epoch,
        signature: None,
    };

    if let Some(s) = signer {
        let msg = lease.canonical_message();
        let sig_bytes = s.sign(msg.as_bytes());
        lease.signature = Some(ReceiptSignature {
            algorithm: s.algorithm(),
            key_id: s.key_id(),
            signature: hex_digest(&sig_bytes),
        });
    }

    Ok(lease)
}

/// Validates a single capability lease for validity, epoch, revocation, and signature.
pub fn validate_lease(
    lease: &CapabilityLease,
    now: u64,
    registry: Option<&RevocationRegistry>,
    public_key: Option<&str>,
) -> Result<(), DelegationError> {
    if now < lease.issued_at {
        return Err(DelegationError::LeasePremature {
            now,
            issued_at: lease.issued_at,
        });
    }
    if now > lease.expires_at {
        return Err(DelegationError::LeaseExpired {
            now,
            expires_at: lease.expires_at,
        });
    }

    if let Some(reg) = registry {
        if lease.revocation_epoch < reg.current_epoch {
            return Err(DelegationError::RevocationEpochExpired {
                lease_epoch: lease.revocation_epoch,
                current_epoch: reg.current_epoch,
            });
        }
        if reg.is_revoked(lease) {
            return Err(DelegationError::LeaseRevoked {
                lease_id: lease.lease_id.clone(),
            });
        }
    }

    if let Some(pk) = public_key {
        let sig = lease
            .signature
            .as_ref()
            .ok_or_else(|| DelegationError::MissingSignature(lease.lease_id.clone()))?;
        let msg = lease.canonical_message();
        verify_receipt_signature(msg.as_bytes(), sig, pk)
            .map_err(|e| DelegationError::Signature(e.to_string()))?;
    }

    Ok(())
}

/// Validates an entire recursive delegation chain from root to leaf.
pub fn validate_chain(
    chain: &[CapabilityLease],
    now: u64,
    registry: Option<&RevocationRegistry>,
    root_public_key: Option<&str>,
) -> Result<(), DelegationError> {
    if chain.is_empty() {
        return Err(DelegationError::BrokenChain {
            expected: None,
            actual: "empty_chain".to_string(),
        });
    }

    let root = &chain[0];
    if root.parent_lease_id.is_some() || root.depth != 0 {
        return Err(DelegationError::BrokenChain {
            expected: None,
            actual: root.lease_id.clone(),
        });
    }

    validate_lease(root, now, registry, root_public_key)?;

    for i in 1..chain.len() {
        let parent = &chain[i - 1];
        let child = &chain[i];

        if child.parent_lease_id.as_deref() != Some(&parent.lease_id) {
            return Err(DelegationError::BrokenChain {
                expected: Some(parent.lease_id.clone()),
                actual: child.lease_id.clone(),
            });
        }

        if child.principal != parent.delegatee {
            return Err(DelegationError::BrokenChain {
                expected: Some(parent.delegatee.clone()),
                actual: child.principal.clone(),
            });
        }

        if child.depth != parent.depth + 1 {
            return Err(DelegationError::MaxDepthExceeded {
                depth: child.depth,
                max_depth: parent.max_depth,
            });
        }

        if child.max_depth > parent.max_depth {
            return Err(DelegationError::MaxDepthExceeded {
                depth: child.max_depth,
                max_depth: parent.max_depth,
            });
        }

        if child.depth > child.max_depth {
            return Err(DelegationError::MaxDepthExceeded {
                depth: child.depth,
                max_depth: child.max_depth,
            });
        }

        if let Err(cap) = is_attenuated(&child.capabilities, &parent.capabilities) {
            return Err(DelegationError::CapabilityEscalation { requested: cap });
        }

        if !parent.authority_ceiling.permits(child.authority_ceiling) {
            return Err(DelegationError::AuthorityCeilingEscalation {
                child: child.authority_ceiling,
                parent: parent.authority_ceiling,
            });
        }

        if child.expires_at > parent.expires_at {
            return Err(DelegationError::LeaseExpired {
                now: child.expires_at,
                expires_at: parent.expires_at,
            });
        }

        validate_lease(child, now, registry, None)?;
    }

    Ok(())
}

/// Validates an agent wire envelope, binding the active lease to the representation receipt.
pub fn validate_envelope(
    envelope: &AgentEnvelope,
    now: u64,
    registry: Option<&RevocationRegistry>,
    public_key: Option<&str>,
) -> Result<(), DelegationError> {
    validate_lease(&envelope.lease, now, registry, public_key)?;

    if envelope.lease.representation_digest != envelope.receipt.canonical_digest {
        return Err(DelegationError::RepresentationMismatch {
            expected: envelope.lease.representation_digest.clone(),
            actual: envelope.receipt.canonical_digest.clone(),
        });
    }

    if let Some(pk) = public_key {
        let sig = envelope
            .signature
            .as_ref()
            .ok_or_else(|| DelegationError::Signature("missing envelope signature".to_string()))?;
        let msg = envelope.canonical_message();
        verify_receipt_signature(msg.as_bytes(), sig, pk)
            .map_err(|e| DelegationError::Signature(e.to_string()))?;
    }

    Ok(())
}
