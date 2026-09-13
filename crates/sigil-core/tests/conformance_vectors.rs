//! RIC conformance vectors.
//!
//! Executable pins for the Representation Integrity Contract
//! (docs/RIC-CONTRACT.md). Each vector names the rule it enforces. These are
//! the behaviors any conforming SIGIL build must exhibit; CI treats failures
//! here as conformance failures, not warnings.

use sigil_core::{
    merge::security_aware_merge,
    policy::{IntakePolicy, InvisibleCharPolicy, Mode, Policy},
    types::{DetectorId, Provenance, Severity, TextSegment, TrustLevel, Verdict},
    Sigil, Vocab,
};

fn policy(mode: Mode, invisible: InvisibleCharPolicy) -> Policy {
    Policy {
        sigil: sigil_core::policy::SigilSection {
            mode,
            ..Default::default()
        },
        intake: IntakePolicy {
            invisible_chars: invisible,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// CV-RIC-001 (with CV-RIC-006): Unicode Tags U+E0000–E007F are detected as
/// invisible control characters. Under Flag policy the finding is Medium; the
/// verdict flags but does not deny.
#[test]
fn cv_ric_001_unicode_tags_are_detected() {
    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine");

    // Tag-encoded ASCII "Hi" smuggled between visible words.
    let smuggled = "hello \u{E0048}\u{E0069} world".to_string();
    let output = engine.scan_text(&smuggled).expect("scan");

    assert!(
        output.annotations.iter().any(|annotation| annotation
            .threat
            .detectors
            .contains(&DetectorId::UnicodeControl)),
        "tag characters must produce a UnicodeControl finding"
    );
    assert!(output.assessment.max_severity >= Severity::Medium);
    assert!(matches!(output.assessment.verdict, Verdict::Flag { .. }));
}

/// CV-RIC-001 + INV-005: under Deny policy, invisible tag characters are a
/// Critical finding, and no policy configuration may override the Deny.
#[test]
fn cv_ric_001b_unicode_tags_deny_verdict() {
    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Deny),
    )
    .expect("engine");

    let output = engine
        .scan_text("hello \u{E0048}\u{E0069} world")
        .expect("scan");
    assert_eq!(output.assessment.max_severity, Severity::Critical);
    assert!(matches!(output.assessment.verdict, Verdict::Deny { .. }));
    assert!(
        output.evidence.is_some(),
        "Deny must produce evidence (INV-006)"
    );
}

/// CV-RIC-002 + RIC-R-1: strip policy removes invisible-only graphemes from
/// the token stream while the receipt still digests the RAW input bytes.
#[test]
fn cv_ric_002_strip_preserves_raw_digest() {
    let invisible = "\u{200B}";
    let clean = "hello world";
    let dirty = format!("hello{invisible} world");

    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Strip),
    )
    .expect("engine");

    let clean_output = engine.scan_text(clean).expect("scan");
    let dirty_output = engine.scan_text(&dirty).expect("scan");

    // Raw digests differ (raw bytes differ), even though the stripped
    // canonical streams are equivalent.
    assert_ne!(
        clean_output.receipt.raw_digest,
        dirty_output.receipt.raw_digest
    );
    assert_eq!(
        clean_output.receipt.canonical_digest, dirty_output.receipt.canonical_digest,
        "stripped canonical streams must be identical"
    );
}

/// CV-RIC-003 (RIC-R-5): default policy suppresses cross-provenance merges;
/// no token may span a provenance boundary and every suppression is recorded.
#[test]
fn cv_ric_003_merge_suppression_records_boundaries() {
    let engine = Sigil::new(Vocab::tiktoken("cl100k_base"), Policy::default()).expect("engine");

    let output = engine
        .process_text_segments(&[
            TextSegment {
                text: "sys ",
                provenance: Provenance::System,
            },
            TextSegment {
                text: "user",
                provenance: Provenance::User,
            },
        ])
        .expect("process");

    // No token spans the boundary at byte 4.
    for annotation in &output.annotations {
        assert!(
            annotation.byte_range.end <= 4 || annotation.byte_range.start >= 4,
            "token spans provenance boundary: {annotation:?}"
        );
    }
    assert!(
        output.annotations.iter().any(|annotation| annotation
            .threat
            .detectors
            .contains(&DetectorId::MergeBoundary)),
        "suppressed merges must be recorded as MergeBoundary findings"
    );
    // Provenance survives: system tokens carry System provenance.
    assert!(output
        .annotations
        .iter()
        .any(|annotation| annotation.provenance == Provenance::System));
}

/// CV-RIC-003b: with suppression disabled by policy, the crossing is
/// permitted but flagged High — the unsafe-merge condition itself.
#[test]
fn cv_ric_003b_unsuppressed_crossing_is_high_severity() {
    let vocab = Vocab::tiktoken("cl100k_base");
    let graphemes: Vec<sigil_core::types::TaintedGrapheme> =
        [("sys ", Provenance::System), ("user", Provenance::User)]
            .iter()
            .enumerate()
            .map(|(idx, (text, provenance))| {
                let start = idx * 4;
                sigil_core::types::TaintedGrapheme {
                    grapheme: sigil_core::types::Grapheme {
                        text: text.to_string(),
                        byte_range: sigil_core::types::ByteRange::new(start, start + text.len()),
                        normalized: false,
                    },
                    provenance: *provenance,
                    trust_level: provenance.default_trust(),
                    boundary_context: sigil_core::types::BoundaryContext::Interior,
                    threat: sigil_core::types::ScanFinding::none(
                        sigil_core::types::ByteRange::new(start, start + text.len()),
                    ),
                }
            })
            .collect();

    let (tokens, findings) = security_aware_merge(&vocab, &graphemes, false);

    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].severity, Severity::High);
    assert!(tokens
        .iter()
        .any(|token| token.byte_range.start < 4 && token.byte_range.end > 4));
}

/// CV-RIC-004 (RIC-R-1..R-4): receipts are deterministic functions of
/// (input, policy) and bind raw bytes, canonical stream, normalization
/// profile, and tokenizer identity.
#[test]
fn cv_ric_004_receipt_is_deterministic_and_binding() {
    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine");

    let first = engine.scan_text("determinism probe").expect("scan");
    let second = engine.scan_text("determinism probe").expect("scan");
    assert_eq!(first.receipt, second.receipt);

    let other = engine.scan_text("determinism probf").expect("scan");
    assert_ne!(first.receipt.raw_digest, other.receipt.raw_digest);

    assert_eq!(first.receipt.normalization, "nfc");
    assert_eq!(first.receipt.vocab, engine.vocab().name.clone());
}

/// CV-RIC-005 (INV-007 end-to-end): token annotations reference byte ranges
/// in the RAW input even when normalization changes byte length, and the
/// receipt digests are populated.
#[test]
fn cv_ric_005_annotations_trace_to_raw_input() {
    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine");

    // Decomposed é: raw bytes 0..3 normalize to a 2-byte canonical form.
    let raw = "caf\u{0065}\u{0301} noir";
    let output = engine.scan_text(raw).expect("scan");

    assert!(!output.annotations.is_empty());
    for annotation in &output.annotations {
        let slice = &raw[annotation.byte_range.start..annotation.byte_range.end];
        assert!(
            !slice.is_empty(),
            "annotation range must be a valid raw slice"
        );
    }
    assert!(!output.receipt.raw_digest.is_empty());
    assert!(!output.receipt.canonical_digest.is_empty());
}

/// CV-RIC-006 (RIC-R-8): trust composition is restrictive — combining
/// content across trust levels yields the LOWER trust, never higher.
#[test]
fn cv_ric_006_trust_composition_is_restrictive() {
    use sigil_core::taint::combine_trust;

    assert_eq!(
        combine_trust(TrustLevel::Privileged, TrustLevel::Untrusted),
        TrustLevel::Untrusted
    );
    assert_eq!(
        combine_trust(TrustLevel::Bounded, TrustLevel::Trusted),
        TrustLevel::Bounded
    );
}

/// CV-RIC-007 (DEV-1): evidence emission is policy-gated. The default
/// `non-allow` mode preserves INV-006 (no bundle on Allow); the `always`
/// mode produces an evidence bundle for every admission, including clean
/// ones, bound to the same receipt digests.
#[test]
fn cv_ric_007_evidence_mode_gates_always_on_attestation() {
    use sigil_core::policy::{EmitPolicy, EvidenceMode};

    // Prose: stays clear of the contiguous-run base64 heuristic (D-9).
    let clean = "hello world";

    // Default policy: Allow verdict carries no evidence bundle (INV-006).
    let lazy_engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine");
    let lazy_output = lazy_engine.scan_text(clean).expect("scan");
    assert!(matches!(lazy_output.assessment.verdict, Verdict::Allow));
    assert!(
        lazy_output.evidence.is_none(),
        "non-allow mode must stay lazy on Allow"
    );

    // Always mode: the same clean input produces an evidence bundle whose
    // verdict matches and whose receipt is unchanged.
    let mut always_policy = policy(Mode::Monitor, InvisibleCharPolicy::Flag);
    always_policy.emit = EmitPolicy {
        evidence_mode: EvidenceMode::Always,
        ..Default::default()
    };
    let always_engine = Sigil::new(Vocab::tiktoken("cl100k_base"), always_policy).expect("engine");
    let always_output = always_engine.scan_text(clean).expect("scan");
    assert!(matches!(always_output.assessment.verdict, Verdict::Allow));
    let bundle = always_output
        .evidence
        .expect("always mode must emit evidence on Allow");
    assert_eq!(bundle.verdict, Verdict::Allow);
    assert_eq!(always_output.receipt, lazy_output.receipt);
}

/// CV-RIC-008 (DEV-3): receipts are signable. With a signer attached, every
/// receipt carries an ECDSA P-384 signature that verifies against the
/// signer's pinned verification key; any tampering with the receipt content
/// breaks it.
#[test]
fn cv_ric_008_receipts_are_signed_and_verifiable() {
    use sigil_core::signing::{receipt_message, EcdsaP384Signer};
    use std::sync::Arc;

    let signer =
        Arc::new(EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar"));
    let verification_key = signer.verification_key_hex();

    let engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine")
    .with_receipt_signer(signer);

    let output = engine.scan_text("signed receipt probe").expect("scan");
    let signature = output
        .receipt
        .signature
        .as_ref()
        .expect("signer attached: receipt must be signed");
    assert_eq!(signature.algorithm, "ecdsa-p384-sha384");

    let message = receipt_message(
        &output.receipt.raw_digest,
        &output.receipt.canonical_digest,
        &output.receipt.digest_algorithm,
        &output.receipt.normalization,
        &output.receipt.vocab,
        output.receipt.token_count,
    );
    assert_eq!(output.receipt.digest_algorithm, "sha384");
    assert_eq!(
        sigil_core::signing::verify_receipt_signature(&message, signature, &verification_key),
        Ok(())
    );

    // Tampering with any receipt field invalidates the signature.
    let mut tampered = output.receipt.clone();
    tampered.token_count += 1;
    let tampered_message = receipt_message(
        &tampered.raw_digest,
        &tampered.canonical_digest,
        &tampered.digest_algorithm,
        &tampered.normalization,
        &tampered.vocab,
        tampered.token_count,
    );
    assert_ne!(
        sigil_core::signing::verify_receipt_signature(
            &tampered_message,
            signature,
            &verification_key
        ),
        Ok(())
    );

    // Engines without a signer emit unsigned receipts.
    let unsigned_engine = Sigil::new(
        Vocab::tiktoken("cl100k_base"),
        policy(Mode::Monitor, InvisibleCharPolicy::Flag),
    )
    .expect("engine");
    let unsigned = unsigned_engine
        .scan_text("signed receipt probe")
        .expect("scan");
    assert!(unsigned.receipt.signature.is_none());
}
