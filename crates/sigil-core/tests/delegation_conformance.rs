//! RIC v0.2 Conformance Vectors (CV-RIC-009 .. CV-RIC-014).
//!
//! Executable pins for Agent-to-Agent (A2A) recursive delegation leases
//! and representation integrity envelopes across autonomous agent boundaries.

use sigil_core::delegation::{
    create_root_lease, delegate, validate_chain, validate_envelope, validate_lease, AgentEnvelope,
    AuthorityCeiling, Capability, CapabilityLease, DelegationError, DelegationRequest,
    RevocationRegistry, RootLeaseParams,
};
use sigil_core::signing::{EcdsaP384Signer, ReceiptSignature, ReceiptSigner};
use sigil_core::types::RepresentationReceipt;
use std::collections::BTreeSet;

fn test_signer() -> EcdsaP384Signer {
    EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid deterministic test key")
}

#[allow(clippy::too_many_arguments)]
fn make_root(
    principal: &str,
    delegatee: &str,
    caps: BTreeSet<Capability>,
    ceiling: AuthorityCeiling,
    digest: &str,
    max_depth: u32,
    validity: u64,
    now: u64,
    epoch: u64,
    signer: Option<&EcdsaP384Signer>,
) -> CapabilityLease {
    create_root_lease(
        RootLeaseParams {
            principal: principal.to_string(),
            delegatee: delegatee.to_string(),
            capabilities: caps,
            authority_ceiling: ceiling,
            representation_digest: digest.to_string(),
            max_depth,
            validity_seconds: validity,
            issued_at: now,
            revocation_epoch: epoch,
        },
        signer.map(|s| s as &dyn sigil_core::signing::ReceiptSigner),
    )
}

/// CV-RIC-009: Valid multi-hop recursive delegation chain with monotonic attenuation.
/// Demonstrates Root (Act) -> Planner (Draft) -> Worker (Observe).
#[test]
fn cv_ric_009_valid_recursive_delegation_chain() {
    let signer = test_signer();
    let pubkey_hex = signer.verification_key_hex();
    let now = 1_000_000;

    let mut root_caps = BTreeSet::new();
    root_caps.insert(Capability::Read {
        path: "repo/*".to_string(),
    });
    root_caps.insert(Capability::Write {
        path: "repo/src/*".to_string(),
    });
    root_caps.insert(Capability::Execute {
        command: "cargo test".to_string(),
    });
    root_caps.insert(Capability::Tool {
        name: "mcp:*".to_string(),
    });

    // 1. Root lease
    let root = make_root(
        "agent://human-operator",
        "agent://orchestrator",
        root_caps,
        AuthorityCeiling::Act,
        "digest_root_intent_384",
        4, // max_depth
        7200,
        now,
        1,
        Some(&signer),
    );

    assert_eq!(root.depth, 0);
    assert_eq!(root.parent_lease_id, None);
    assert!(root.signature.is_some());

    // 2. Child delegation to Planner (attenuates to Read + Tool, ceiling Draft)
    let mut planner_caps = BTreeSet::new();
    planner_caps.insert(Capability::Read {
        path: "repo/src/*".to_string(),
    });
    planner_caps.insert(Capability::Tool {
        name: "mcp:search".to_string(),
    });

    let planner_req = DelegationRequest {
        delegatee: "agent://planner".to_string(),
        capabilities: planner_caps.clone(),
        authority_ceiling: AuthorityCeiling::Draft,
        representation_digest: "digest_planner_intent_384".to_string(),
        validity_seconds: 3600,
    };

    let planner_lease =
        delegate(&root, &planner_req, now + 10, 1, Some(&signer)).expect("planner delegation");
    assert_eq!(planner_lease.depth, 1);
    assert_eq!(planner_lease.parent_lease_id, Some(root.lease_id.clone()));
    assert_eq!(planner_lease.authority_ceiling, AuthorityCeiling::Draft);

    // 3. Child delegation to Researcher (attenuates to Read only, ceiling Observe)
    let mut researcher_caps = BTreeSet::new();
    researcher_caps.insert(Capability::Read {
        path: "repo/src/lib.rs".to_string(),
    });

    let researcher_req = DelegationRequest {
        delegatee: "agent://researcher".to_string(),
        capabilities: researcher_caps,
        authority_ceiling: AuthorityCeiling::Observe,
        representation_digest: "digest_research_intent_384".to_string(),
        validity_seconds: 1800,
    };

    let researcher_lease = delegate(&planner_lease, &researcher_req, now + 20, 1, Some(&signer))
        .expect("researcher delegation");
    assert_eq!(researcher_lease.depth, 2);
    assert_eq!(
        researcher_lease.parent_lease_id,
        Some(planner_lease.lease_id.clone())
    );
    assert_eq!(
        researcher_lease.authority_ceiling,
        AuthorityCeiling::Observe
    );

    // Verify entire recursive chain
    let chain = vec![root, planner_lease, researcher_lease];
    let result = validate_chain(&chain, now + 50, None, Some(&pubkey_hex));
    assert!(
        result.is_ok(),
        "chain must validate cryptographically and structurally"
    );
}

/// CV-RIC-010: Monotonic capability attenuation. A child agent cannot claim
/// a capability that was not granted to its delegating parent.
#[test]
fn cv_ric_010_capability_escalation_denied() {
    let now = 1_000_000;
    let mut root_caps = BTreeSet::new();
    root_caps.insert(Capability::Read {
        path: "public/*".to_string(),
    });

    let root = make_root(
        "agent://root",
        "agent://reader",
        root_caps,
        AuthorityCeiling::Act,
        "digest_root",
        3,
        3600,
        now,
        1,
        None,
    );

    // Subagent attempts to claim Write access
    let mut escalated_caps = BTreeSet::new();
    escalated_caps.insert(Capability::Read {
        path: "public/file.txt".to_string(),
    });
    escalated_caps.insert(Capability::Write {
        path: "public/file.txt".to_string(),
    });

    let req = DelegationRequest {
        delegatee: "agent://writer".to_string(),
        capabilities: escalated_caps,
        authority_ceiling: AuthorityCeiling::Draft,
        representation_digest: "digest_child".to_string(),
        validity_seconds: 1800,
    };

    let result = delegate(&root, &req, now + 5, 1, None);
    assert!(
        matches!(result, Err(DelegationError::CapabilityEscalation { .. })),
        "attempting to claim ungranted capability must fail with CapabilityEscalation"
    );
}

/// CV-RIC-011: Authority ceiling monotonicity. A child agent cannot be granted
/// a higher authority ceiling than its parent possesses.
#[test]
fn cv_ric_011_authority_ceiling_escalation_denied() {
    let now = 1_000_000;
    let caps = BTreeSet::new();

    let root = make_root(
        "agent://root",
        "agent://observer",
        caps.clone(),
        AuthorityCeiling::Observe,
        "digest_root",
        3,
        3600,
        now,
        1,
        None,
    );

    // Child requests Act ceiling from an Observe parent
    let req = DelegationRequest {
        delegatee: "agent://actor".to_string(),
        capabilities: caps,
        authority_ceiling: AuthorityCeiling::Act,
        representation_digest: "digest_child".to_string(),
        validity_seconds: 1800,
    };

    let result = delegate(&root, &req, now + 5, 1, None);
    assert!(
        matches!(
            result,
            Err(DelegationError::AuthorityCeilingEscalation { .. })
        ),
        "requesting Act from Observe parent must fail with AuthorityCeilingEscalation"
    );
}

/// CV-RIC-012: Bounded recursion depth limit. Recursive delegation ceases once
/// max_depth is reached, preventing runaway agent spawn loops.
#[test]
fn cv_ric_012_max_depth_enforced() {
    let now = 1_000_000;
    let caps = BTreeSet::new();

    // Max depth set to 2
    let root = make_root(
        "agent://root",
        "agent://tier1",
        caps.clone(),
        AuthorityCeiling::Act,
        "digest_0",
        2,
        3600,
        now,
        1,
        None,
    );

    // Tier 1 -> Tier 2 (depth = 1, allowed)
    let tier1 = delegate(
        &root,
        &DelegationRequest {
            delegatee: "agent://tier2".to_string(),
            capabilities: caps.clone(),
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_1".to_string(),
            validity_seconds: 1800,
        },
        now + 1,
        1,
        None,
    )
    .expect("tier 1 delegation succeeds");
    assert_eq!(tier1.depth, 1);

    // Tier 2 -> Tier 3 (depth = 2, allowed)
    let tier2 = delegate(
        &tier1,
        &DelegationRequest {
            delegatee: "agent://tier3".to_string(),
            capabilities: caps.clone(),
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_2".to_string(),
            validity_seconds: 900,
        },
        now + 2,
        1,
        None,
    )
    .expect("tier 2 delegation succeeds");
    assert_eq!(tier2.depth, 2);

    // Tier 3 -> Tier 4 (depth = 3 > max_depth 2, MUST FAIL)
    let result = delegate(
        &tier2,
        &DelegationRequest {
            delegatee: "agent://tier4".to_string(),
            capabilities: caps,
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_3".to_string(),
            validity_seconds: 450,
        },
        now + 3,
        1,
        None,
    );

    assert!(
        matches!(result, Err(DelegationError::MaxDepthExceeded { .. })),
        "exceeding max depth must fail with MaxDepthExceeded"
    );
}

/// CV-RIC-013: Representation binding. An agent wire envelope is rejected if
/// the admitted representation receipt digest does not match the lease digest.
#[test]
fn cv_ric_013_representation_binding_divergence_denied() {
    let now = 1_000_000;
    let lease = make_root(
        "agent://root",
        "agent://worker",
        BTreeSet::new(),
        AuthorityCeiling::Act,
        "canonical_digest_task_approved",
        2,
        3600,
        now,
        1,
        None,
    );

    let matching_receipt = RepresentationReceipt {
        raw_digest: "raw_384".to_string(),
        canonical_digest: "canonical_digest_task_approved".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 15,
        signature: None,
    };

    let valid_envelope = AgentEnvelope {
        envelope_id: "env_approved".to_string(),
        lease: lease.clone(),
        receipt: matching_receipt,
        payload: "legitimate task instructions".to_string(),
        signature: None,
    };

    assert!(
        validate_envelope(&valid_envelope, now + 1, None, None).is_ok(),
        "matching representation digest envelope must pass validation"
    );

    let tampered_receipt = RepresentationReceipt {
        raw_digest: "raw_384".to_string(),
        canonical_digest: "canonical_digest_injected_exploit".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 15,
        signature: None,
    };

    let tampered_envelope = AgentEnvelope {
        envelope_id: "env_tampered".to_string(),
        lease,
        receipt: tampered_receipt,
        payload: "unauthorized altered instructions".to_string(),
        signature: None,
    };

    let result = validate_envelope(&tampered_envelope, now + 1, None, None);
    assert!(
        matches!(result, Err(DelegationError::RepresentationMismatch { .. })),
        "mismatched representation digest must fail with RepresentationMismatch"
    );
}

/// CV-RIC-014: Revocation cascade. Revoking an ancestor lease in the registry
/// immediately invalidates all active descendant child leases.
#[test]
fn cv_ric_014_revocation_cascade_invalidates_descendants() {
    let now = 1_000_000;
    let caps = BTreeSet::new();

    let root = make_root(
        "agent://root",
        "agent://planner",
        caps.clone(),
        AuthorityCeiling::Act,
        "digest_root",
        3,
        3600,
        now,
        1,
        None,
    );

    let child = delegate(
        &root,
        &DelegationRequest {
            delegatee: "agent://worker".to_string(),
            capabilities: caps.clone(),
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_child".to_string(),
            validity_seconds: 1800,
        },
        now + 10,
        1,
        None,
    )
    .expect("child delegation");

    let mut registry = RevocationRegistry::new();
    assert!(
        validate_lease(&child, now + 20, Some(&registry), None).is_ok(),
        "unrevoked child lease must be valid"
    );

    // Revoking parent lease cascades to invalidate child
    registry.revoke(&root.lease_id);
    let result = validate_lease(&child, now + 20, Some(&registry), None);
    assert!(
        matches!(result, Err(DelegationError::LeaseRevoked { .. })),
        "revoking ancestor lease must cascade and invalidate child lease"
    );

    // Advancing revocation epoch invalidates all leases issued under older epochs
    let epoch_registry = RevocationRegistry {
        current_epoch: 2, // Registry advanced to epoch 2
        revoked_lease_ids: BTreeSet::new(),
        parent_map: std::collections::BTreeMap::new(),
    };

    let epoch_result = validate_lease(&root, now + 20, Some(&epoch_registry), None);
    assert!(
        matches!(
            epoch_result,
            Err(DelegationError::RevocationEpochExpired { .. })
        ),
        "lease issued under older revocation epoch must be rejected"
    );
}

/// Security regression test for CRIT-01: Agent envelope payload malleability.
/// Tampering with payload content while preserving character length MUST invalidate the signature.
#[test]
fn sec_audit_crit_01_payload_malleability_rejected() {
    let now = 1_000_000;
    let signer = EcdsaP384Signer::generate().expect("generate signer");
    let pubkey_hex = signer.verification_key_hex();

    let root = make_root(
        "agent://root",
        "agent://worker",
        BTreeSet::new(),
        AuthorityCeiling::Act,
        "task_rep_digest_384",
        1,
        3600,
        now,
        1,
        Some(&signer),
    );

    let receipt = RepresentationReceipt {
        raw_digest: "raw_384".to_string(),
        canonical_digest: "task_rep_digest_384".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 5,
        signature: None,
    };

    let mut envelope = AgentEnvelope {
        envelope_id: "env_audit_crit01".to_string(),
        lease: root,
        receipt,
        payload: "clean task instruction".to_string(),
        signature: None,
    };

    let msg = envelope.canonical_message();
    let sig_bytes = signer.sign(msg.as_bytes());
    envelope.signature = Some(ReceiptSignature {
        algorithm: signer.algorithm(),
        key_id: signer.key_id(),
        signature: sigil_core::signing::hex_digest(&sig_bytes),
    });

    // Valid envelope must pass
    assert!(validate_envelope(&envelope, now + 1, None, Some(&pubkey_hex)).is_ok());

    // Adversary replaces payload with same-length malicious instructions
    assert_eq!(
        "clean task instruction".len(),
        "MALICIOUS INJECTIONS!!".len()
    );
    envelope.payload = "MALICIOUS INJECTIONS!!".to_string();

    // Must fail signature verification
    let result = validate_envelope(&envelope, now + 1, None, Some(&pubkey_hex));
    assert!(
        matches!(result, Err(DelegationError::Signature(_))),
        "same-length payload tampering must fail signature verification"
    );
}

/// Security regression test for CRIT-02: Envelope signature verification omission.
/// Unsigned envelope MUST be rejected when public key is provided.
#[test]
fn sec_audit_crit_02_unsigned_envelope_rejected() {
    let now = 1_000_000;
    let signer = EcdsaP384Signer::generate().expect("generate signer");
    let pubkey_hex = signer.verification_key_hex();

    let root = make_root(
        "agent://root",
        "agent://worker",
        BTreeSet::new(),
        AuthorityCeiling::Act,
        "task_rep_digest_384",
        1,
        3600,
        now,
        1,
        Some(&signer),
    );

    let receipt = RepresentationReceipt {
        raw_digest: "raw_384".to_string(),
        canonical_digest: "task_rep_digest_384".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 5,
        signature: None,
    };

    let unsigned_envelope = AgentEnvelope {
        envelope_id: "env_unsigned".to_string(),
        lease: root,
        receipt,
        payload: "instruction".to_string(),
        signature: None,
    };

    let result = validate_envelope(&unsigned_envelope, now + 1, None, Some(&pubkey_hex));
    assert!(
        matches!(result, Err(DelegationError::Signature(_))),
        "unsigned envelope must be rejected when public_key is provided"
    );
}

/// Security regression test for CRIT-04: Grandparent revocation cascade.
/// Revoking root lease must revoke depth 2+ descendant leases when lineage is recorded.
#[test]
fn sec_audit_crit_04_grandparent_revocation_cascades() {
    let now = 1_000_000;
    let caps = BTreeSet::new();

    let root = make_root(
        "agent://root",
        "agent://tier1",
        caps.clone(),
        AuthorityCeiling::Act,
        "digest_0",
        3,
        3600,
        now,
        1,
        None,
    );

    let child = delegate(
        &root,
        &DelegationRequest {
            delegatee: "agent://tier2".to_string(),
            capabilities: caps.clone(),
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_1".to_string(),
            validity_seconds: 1800,
        },
        now + 1,
        1,
        None,
    )
    .expect("tier 1 delegation");

    let grandchild = delegate(
        &child,
        &DelegationRequest {
            delegatee: "agent://tier3".to_string(),
            capabilities: caps,
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "digest_2".to_string(),
            validity_seconds: 900,
        },
        now + 2,
        1,
        None,
    )
    .expect("tier 2 delegation");
    assert_eq!(grandchild.depth, 2);

    let mut registry = RevocationRegistry::new();
    registry.record_lineage(&child.lease_id, &root.lease_id);
    registry.record_lineage(&grandchild.lease_id, &child.lease_id);

    // Revoke root (grandparent of grandchild)
    registry.revoke(&root.lease_id);

    let result = validate_lease(&grandchild, now + 5, Some(&registry), None);
    assert!(
        matches!(result, Err(DelegationError::LeaseRevoked { .. })),
        "revoking root lease must cascade and invalidate grandchild lease"
    );
}

/// Security regression test for HIGH-01: Capability pattern path traversal and command chaining.
#[test]
fn sec_audit_high_01_capability_path_traversal_and_chaining_blocked() {
    // 1. Path traversal escape rejected
    let parent_read = Capability::Read {
        path: "src/*".to_string(),
    };
    let child_traversal = Capability::Read {
        path: "src/../../etc/shadow".to_string(),
    };
    assert!(
        !child_traversal.is_covered_by(&parent_read),
        "path traversal component `..` must not be covered by directory wildcard"
    );

    let child_null_byte = Capability::Read {
        path: "src/\0etc/shadow".to_string(),
    };
    assert!(
        !child_null_byte.is_covered_by(&parent_read),
        "null byte in path must be rejected"
    );

    let child_legit = Capability::Read {
        path: "src/sub/lib.rs".to_string(),
    };
    assert!(
        child_legit.is_covered_by(&parent_read),
        "nested path within directory must be covered"
    );

    // 2. Command chaining escape rejected
    let parent_exec = Capability::Execute {
        command: "cargo test*".to_string(),
    };
    let child_chain = Capability::Execute {
        command: "cargo test; rm -rf /".to_string(),
    };
    assert!(
        !child_chain.is_covered_by(&parent_exec),
        "semicolon command chaining must not be covered"
    );

    let child_pipe = Capability::Execute {
        command: "cargo test | cat".to_string(),
    };
    assert!(
        !child_pipe.is_covered_by(&parent_exec),
        "pipe command chaining must not be covered"
    );

    // 3. Network domain fronting
    let parent_net = Capability::Network {
        host: "*.example.com".to_string(),
    };
    let child_sub = Capability::Network {
        host: "api.example.com".to_string(),
    };
    assert!(
        child_sub.is_covered_by(&parent_net),
        "valid subdomain must be covered"
    );

    let child_evil = Capability::Network {
        host: "example.com.evil.com".to_string(),
    };
    assert!(
        !child_evil.is_covered_by(&parent_net),
        "domain fronting suffix must not be covered"
    );
}

/// Security regression test for HIGH-05: Delegator continuity in delegation chain.
#[test]
fn sec_audit_high_05_delegator_continuity_enforced() {
    let now = 1_000_000;
    let root = make_root(
        "agent://root",
        "agent://authorized_worker",
        BTreeSet::new(),
        AuthorityCeiling::Act,
        "digest_0",
        2,
        3600,
        now,
        1,
        None,
    );

    // Fabricated child claims principal is agent://imposter instead of agent://authorized_worker
    let fabricated_child = CapabilityLease {
        lease_id: "lease_d1_fake".to_string(),
        parent_lease_id: Some(root.lease_id.clone()),
        principal: "agent://imposter".to_string(),
        delegatee: "agent://leaf".to_string(),
        depth: 1,
        max_depth: 2,
        capabilities: BTreeSet::new(),
        authority_ceiling: AuthorityCeiling::Act,
        representation_digest: "digest_1".to_string(),
        issued_at: now + 1,
        expires_at: now + 1800,
        revocation_epoch: 1,
        signature: None,
    };

    let chain = vec![root, fabricated_child];
    let result = validate_chain(&chain, now + 5, None, None);
    assert!(
        matches!(result, Err(DelegationError::BrokenChain { .. })),
        "broken delegator continuity in chain must be rejected"
    );
}
