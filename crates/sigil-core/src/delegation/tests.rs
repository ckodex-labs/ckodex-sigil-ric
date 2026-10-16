use super::types::*;
use super::validator::*;
use crate::signing::EcdsaP384Signer;
use crate::types::RepresentationReceipt;
use std::collections::BTreeSet;

fn test_signer() -> EcdsaP384Signer {
    EcdsaP384Signer::from_private_key_bytes(&[7u8; 48]).expect("valid test key")
}

#[allow(clippy::too_many_arguments)]
fn test_root(
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
        signer.map(|s| s as &dyn crate::signing::ReceiptSigner),
    )
}

#[test]
fn root_lease_creation_and_verification() {
    let signer = test_signer();
    let mut caps = BTreeSet::new();
    caps.insert(Capability::Read {
        path: "crates/*".to_string(),
    });
    caps.insert(Capability::Tool {
        name: "mcp:*".to_string(),
    });

    let now = 1000;
    let root = test_root(
        "agent://orchestrator",
        "agent://planner",
        caps,
        AuthorityCeiling::Act,
        "digest384_root",
        3,
        3600,
        now,
        1,
        Some(&signer),
    );

    assert_eq!(root.depth, 0);
    assert_eq!(root.parent_lease_id, None);
    assert!(root.signature.is_some());

    let pubkey_hex = signer.verification_key_hex();
    let result = validate_lease(&root, now + 10, None, Some(&pubkey_hex));
    assert!(result.is_ok());
}

#[test]
fn recursive_delegation_and_chain_validation() {
    let signer = test_signer();
    let pubkey_hex = signer.verification_key_hex();
    let now = 1000;

    let mut root_caps = BTreeSet::new();
    root_caps.insert(Capability::Read {
        path: "*".to_string(),
    });
    root_caps.insert(Capability::Write {
        path: "crates/*".to_string(),
    });

    let root = test_root(
        "agent://orchestrator",
        "agent://lead-dev",
        root_caps,
        AuthorityCeiling::Act,
        "rep_digest_task_0",
        3,
        3600,
        now,
        1,
        Some(&signer),
    );

    // Lead dev delegates to researcher (read-only, Draft ceiling)
    let mut child_caps = BTreeSet::new();
    child_caps.insert(Capability::Read {
        path: "crates/sigil-core/*".to_string(),
    });

    let req_child = DelegationRequest {
        delegatee: "agent://researcher".to_string(),
        capabilities: child_caps.clone(),
        authority_ceiling: AuthorityCeiling::Draft,
        representation_digest: "rep_digest_task_1".to_string(),
        validity_seconds: 1800,
    };

    let child = delegate(&root, &req_child, now + 10, 1, Some(&signer)).expect("valid delegation");
    assert_eq!(child.depth, 1);
    assert_eq!(child.parent_lease_id, Some(root.lease_id.clone()));
    assert_eq!(child.authority_ceiling, AuthorityCeiling::Draft);

    // Researcher delegates to sub-worker (further attenuated to Observe)
    let req_grandchild = DelegationRequest {
        delegatee: "agent://indexer".to_string(),
        capabilities: child_caps,
        authority_ceiling: AuthorityCeiling::Observe,
        representation_digest: "rep_digest_task_2".to_string(),
        validity_seconds: 600,
    };

    let grandchild =
        delegate(&child, &req_grandchild, now + 20, 1, Some(&signer)).expect("valid grandchild");
    assert_eq!(grandchild.depth, 2);
    assert_eq!(grandchild.parent_lease_id, Some(child.lease_id.clone()));

    // Verify entire chain
    let chain = vec![root, child, grandchild];
    let validation = validate_chain(&chain, now + 30, None, Some(&pubkey_hex));
    assert!(validation.is_ok());
}

#[test]
fn capability_escalation_rejected() {
    let now = 1000;
    let mut root_caps = BTreeSet::new();
    root_caps.insert(Capability::Read {
        path: "crates/*".to_string(),
    });

    let root = test_root(
        "agent://orchestrator",
        "agent://worker",
        root_caps,
        AuthorityCeiling::Draft,
        "rep_1",
        2,
        3600,
        now,
        1,
        None,
    );

    // Child requests Write, which root does not possess
    let mut bad_caps = BTreeSet::new();
    bad_caps.insert(Capability::Write {
        path: "crates/*".to_string(),
    });

    let req = DelegationRequest {
        delegatee: "agent://rogue".to_string(),
        capabilities: bad_caps,
        authority_ceiling: AuthorityCeiling::Draft,
        representation_digest: "rep_2".to_string(),
        validity_seconds: 600,
    };

    let err = delegate(&root, &req, now + 1, 1, None).unwrap_err();
    assert!(matches!(err, DelegationError::CapabilityEscalation { .. }));
}

#[test]
fn authority_ceiling_escalation_rejected() {
    let now = 1000;
    let mut root_caps = BTreeSet::new();
    root_caps.insert(Capability::Read {
        path: "*".to_string(),
    });

    let root = test_root(
        "agent://orchestrator",
        "agent://observer",
        root_caps.clone(),
        AuthorityCeiling::Observe,
        "rep_1",
        2,
        3600,
        now,
        1,
        None,
    );

    // Child requests Act when parent is only Observe
    let req = DelegationRequest {
        delegatee: "agent://actor".to_string(),
        capabilities: root_caps,
        authority_ceiling: AuthorityCeiling::Act,
        representation_digest: "rep_2".to_string(),
        validity_seconds: 600,
    };

    let err = delegate(&root, &req, now + 1, 1, None).unwrap_err();
    assert!(matches!(
        err,
        DelegationError::AuthorityCeilingEscalation { .. }
    ));
}

#[test]
fn max_depth_exceeded_rejected() {
    let now = 1000;
    let caps = BTreeSet::new();

    let root = test_root(
        "agent://root",
        "agent://d1",
        caps.clone(),
        AuthorityCeiling::Act,
        "rep_0",
        1, // Max depth is 1
        3600,
        now,
        1,
        None,
    );

    let req1 = DelegationRequest {
        delegatee: "agent://d2".to_string(),
        capabilities: caps.clone(),
        authority_ceiling: AuthorityCeiling::Act,
        representation_digest: "rep_1".to_string(),
        validity_seconds: 1000,
    };

    let child = delegate(&root, &req1, now + 1, 1, None).expect("child at depth 1 is ok");
    assert_eq!(child.depth, 1);

    // Attempting depth 2 should fail
    let req2 = DelegationRequest {
        delegatee: "agent://d3".to_string(),
        capabilities: caps,
        authority_ceiling: AuthorityCeiling::Act,
        representation_digest: "rep_2".to_string(),
        validity_seconds: 500,
    };

    let err = delegate(&child, &req2, now + 2, 1, None).unwrap_err();
    assert!(matches!(err, DelegationError::MaxDepthExceeded { .. }));
}

#[test]
fn revocation_cascade_invalidates_descendants() {
    let now = 1000;
    let caps = BTreeSet::new();

    let root = test_root(
        "agent://root",
        "agent://lead",
        caps.clone(),
        AuthorityCeiling::Act,
        "rep_0",
        3,
        3600,
        now,
        1,
        None,
    );

    let child = delegate(
        &root,
        &DelegationRequest {
            delegatee: "agent://sub".to_string(),
            capabilities: caps,
            authority_ceiling: AuthorityCeiling::Act,
            representation_digest: "rep_1".to_string(),
            validity_seconds: 1000,
        },
        now + 1,
        1,
        None,
    )
    .expect("valid child");

    let mut registry = RevocationRegistry::new();
    assert!(validate_lease(&child, now + 10, Some(&registry), None).is_ok());

    // Revoking root lease invalidates child
    registry.revoke(&root.lease_id);
    let err = validate_lease(&child, now + 10, Some(&registry), None).unwrap_err();
    assert!(matches!(err, DelegationError::LeaseRevoked { .. }));
}

#[test]
fn envelope_representation_mismatch_denied() {
    let now = 1000;
    let root = test_root(
        "agent://root",
        "agent://worker",
        BTreeSet::new(),
        AuthorityCeiling::Act,
        "admitted_digest_abc",
        2,
        3600,
        now,
        1,
        None,
    );

    // Receipt with matching digest
    let good_receipt = RepresentationReceipt {
        raw_digest: "raw123".to_string(),
        canonical_digest: "admitted_digest_abc".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 10,
        signature: None,
    };

    let good_envelope = AgentEnvelope {
        envelope_id: "env_1".to_string(),
        lease: root.clone(),
        receipt: good_receipt,
        payload: "legitimate payload".to_string(),
        signature: None,
    };

    assert!(validate_envelope(&good_envelope, now + 5, None, None).is_ok());

    // Receipt with tampered/divergent digest
    let bad_receipt = RepresentationReceipt {
        raw_digest: "raw123".to_string(),
        canonical_digest: "tampered_digest_xyz".to_string(),
        digest_algorithm: "sha384".to_string(),
        normalization: "nfc".to_string(),
        vocab: "cl100k_base".to_string(),
        token_count: 10,
        signature: None,
    };

    let bad_envelope = AgentEnvelope {
        envelope_id: "env_2".to_string(),
        lease: root,
        receipt: bad_receipt,
        payload: "divergent payload".to_string(),
        signature: None,
    };

    let err = validate_envelope(&bad_envelope, now + 5, None, None).unwrap_err();
    assert!(matches!(
        err,
        DelegationError::RepresentationMismatch { .. }
    ));
}
