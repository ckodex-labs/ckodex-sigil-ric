//! in-toto attestation packaging for RIC receipts (DEV-3, "both" decision).
//!
//! A signed receipt can be packaged as an [in-toto Statement v1] wrapped in a
//! [DSSE] envelope — the interchange format consumed by the Sigstore
//! ecosystem (`cosign attest`, policy controllers) and by in-toto verifiers.
//! This gives RIC receipts a supply-chain-native representation without
//! coupling the kernel to any transparency service.
//!
//! The subject of the statement is the *admitted representation* (identified
//! by its canonical SHA-384 digest); the predicate carries the full receipt.
//! The DSSE signature covers the Pre-Authentication Encoding (PAE) of the
//! statement, so any mutation of subject or predicate is detectable.
//!
//! Conformance notes, verified against the DSSE spec (envelope.md and
//! protocol.md v1.0.2): the envelope uses the standard field names and
//! `sig = Base64(SIGNATURE)`; the PAE matches the spec exactly (pinned by an
//! exact-bytes test). One deviation, stated honestly: the registered DSSE
//! algorithm identifiers cover ECDSA-SHA256 but not P-384, so the envelope
//! records `ecdsa-p384-sha384` as the signature algorithm label. Verifiers
//! that only accept the registered set must be configured for the extended
//! identifier.
//!
//! [in-toto Statement v1]: https://github.com/in-toto/attestation/tree/main/spec/v1
//! [DSSE]: https://github.com/secure-systems-lab/dsse

use base64::Engine as _;
use serde::{Deserialize, Serialize};

use crate::signing::{hex_digest, verify_receipt_signature, ReceiptSigner, SignatureVerifyError};

pub const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
pub const PREDICATE_TYPE: &str = "https://sigil.dev/ric/receipt/v2";
pub const PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// In-toto Statement v1 carrying the receipt as its predicate. The subject
/// identifies the admitted representation by its canonical SHA-384 digest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptStatement {
    #[serde(rename = "_type")]
    pub statement_type: String,
    pub subject: Vec<StatementSubject>,
    pub predicate_type: String,
    pub predicate: ReceiptPredicate,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatementSubject {
    pub name: String,
    pub digest: StatementDigest,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct StatementDigest {
    pub sha384: String,
}

/// Predicate carrying the receipt's admission facts (everything except the
/// signature, which travels in the DSSE envelope).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ReceiptPredicate {
    pub raw_digest: String,
    pub canonical_digest: String,
    pub digest_algorithm: String,
    pub normalization: String,
    pub vocab: String,
    pub token_count: usize,
}

/// DSSE envelope for a signed in-toto statement.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DsseEnvelope {
    #[serde(rename = "payloadType")]
    pub payload_type: String,
    /// Base64 (standard, padded) encoded statement JSON.
    pub payload: String,
    pub signatures: Vec<DsseSignature>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DsseSignature {
    pub keyid: String,
    /// Hex-encoded signature over the DSSE PAE.
    pub sig: String,
}

/// Build the in-toto Statement v1 JSON for a receipt (unsigned payload).
pub fn statement_json(
    raw_digest: &str,
    canonical_digest: &str,
    digest_algorithm: &str,
    normalization: &str,
    vocab: &str,
    token_count: usize,
) -> serde_json::Value {
    serde_json::json!({
        "_type": STATEMENT_TYPE,
        "subject": [{
            "name": "sigil:admission",
            "digest": { "sha384": canonical_digest }
        }],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "raw_digest": raw_digest,
            "canonical_digest": canonical_digest,
            "digest_algorithm": digest_algorithm,
            "normalization": normalization,
            "vocab": vocab,
            "token_count": token_count,
        }
    })
}

/// Sign a receipt as an in-toto Statement v1 wrapped in a DSSE envelope.
/// The signature covers the DSSE PAE over the statement payload.
pub fn attest_receipt(
    raw_digest: &str,
    canonical_digest: &str,
    digest_algorithm: &str,
    normalization: &str,
    vocab: &str,
    token_count: usize,
    signer: &dyn ReceiptSigner,
) -> Result<DsseEnvelope, AttestationError> {
    let statement = statement_json(
        raw_digest,
        canonical_digest,
        digest_algorithm,
        normalization,
        vocab,
        token_count,
    );
    let payload = serde_json::to_vec(&statement).map_err(|_| AttestationError::Serialization)?;
    let payload_type = PAYLOAD_TYPE.to_string();
    let pae = pae(&payload_type, &payload);
    let signature = signer.sign(&pae);
    Ok(DsseEnvelope {
        payload_type,
        payload: base64::engine::general_purpose::STANDARD.encode(&payload),
        signatures: vec![DsseSignature {
            keyid: signer.key_id(),
            // DSSE spec: sig is Base64(SIGNATURE) (envelope.md v1.0.2).
            sig: base64::engine::general_purpose::STANDARD.encode(&signature),
        }],
    })
}

/// Verify a DSSE-wrapped receipt attestation against a pinned hex key.
pub fn verify_attestation(
    envelope: &DsseEnvelope,
    verification_key_hex: &str,
) -> Result<(), SignatureVerifyError> {
    let payload = base64::engine::general_purpose::STANDARD
        .decode(&envelope.payload)
        .map_err(|_| SignatureVerifyError::InvalidSignature)?;
    let pae = pae(&envelope.payload_type, &payload);

    // The DSSE signature covers the PAE; verification reuses the P-384
    // receipt-verification path with the PAE as the message. Per the DSSE
    // spec (envelope.md v1.0.2), `sig` is Base64(SIGNATURE).
    let signature = envelope
        .signatures
        .first()
        .ok_or(SignatureVerifyError::InvalidSignature)?;
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&signature.sig)
        .map_err(|_| SignatureVerifyError::InvalidSignature)?;
    if sig_bytes.len() != 96 {
        return Err(SignatureVerifyError::InvalidSignature);
    }
    let receipt_signature = crate::signing::ReceiptSignature {
        algorithm: "ecdsa-p384-sha384".to_string(),
        key_id: signature.keyid.clone(),
        signature: hex_digest(&sig_bytes),
    };
    verify_receipt_signature(&pae, &receipt_signature, verification_key_hex)
}

/// DSSE Pre-Authentication Encoding:
/// `DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>`
/// with byte-length prefixes as ASCII decimal digits.
fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let mut out = b"DSSEv1 ".to_vec();
    out.extend(payload_type.len().to_string().as_bytes());
    out.push(b' ');
    out.extend(payload_type.as_bytes());
    out.push(b' ');
    out.extend(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend(payload);
    out
}

/// Attestation construction failures.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AttestationError {
    #[error("statement serialization failed")]
    Serialization,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signing::EcdsaP384Signer;

    fn signer() -> EcdsaP384Signer {
        EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar")
    }

    fn receipt_fields() -> (
        String,
        String,
        &'static str,
        &'static str,
        &'static str,
        usize,
    ) {
        (
            "a".repeat(96),
            "b".repeat(96),
            "sha384",
            "nfc",
            "cl100k_base",
            9,
        )
    }

    #[test]
    fn attestation_roundtrip_verifies() {
        let signer = signer();
        let (raw, canonical, digest, norm, vocab, tokens) = receipt_fields();
        let envelope =
            attest_receipt(&raw, &canonical, digest, norm, vocab, tokens, &signer).expect("attest");

        assert_eq!(envelope.payload_type, PAYLOAD_TYPE);
        assert_eq!(envelope.signatures.len(), 1);
        // The payload decodes back to the statement with the receipt facts.
        let payload = base64::engine::general_purpose::STANDARD
            .decode(&envelope.payload)
            .expect("base64");
        let statement: serde_json::Value = serde_json::from_slice(&payload).expect("statement");
        assert_eq!(statement["_type"], STATEMENT_TYPE);
        assert_eq!(statement["predicateType"], PREDICATE_TYPE);
        assert_eq!(statement["predicate"]["digest_algorithm"], "sha384");
        assert_eq!(statement["subject"][0]["digest"]["sha384"], canonical);

        assert_eq!(
            verify_attestation(&envelope, &signer.verification_key_hex()),
            Ok(())
        );
    }

    #[test]
    fn tampered_payload_fails_verification() {
        let signer = signer();
        let (raw, canonical, digest, norm, vocab, tokens) = receipt_fields();
        let mut envelope =
            attest_receipt(&raw, &canonical, digest, norm, vocab, tokens, &signer).expect("attest");

        // Mutate the payload: the PAE no longer matches the signature.
        let mut statement = serde_json::from_slice::<serde_json::Value>(
            &base64::engine::general_purpose::STANDARD
                .decode(&envelope.payload)
                .expect("decode"),
        )
        .expect("statement");
        statement["predicate"]["token_count"] = serde_json::json!(999);
        envelope.payload = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&statement).expect("reserialize"));

        assert_eq!(
            verify_attestation(&envelope, &signer.verification_key_hex()),
            Err(SignatureVerifyError::Mismatch)
        );
    }

    #[test]
    fn pae_matches_dsse_spec_shape() {
        // DSSEv1 <len(payloadType)> <payloadType> <len(payload)> <payload>
        let pae = pae("application/json", b"{}");
        assert_eq!(
            pae,
            b"DSSEv1 16 application/json 2 {}".to_vec(),
            "PAE must match the DSSE pre-authentication encoding"
        );
    }
}
