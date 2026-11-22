//! The retrieval and embedding boundary (RIC-SPEC §4.3, RIC-MM-001 WP7).
//!
//! A retriever or embedding filter is an interpreter: it reads a
//! representation and its output (a ranking, a similarity score) decides what
//! reaches the model. Three rules follow:
//!
//! - RIC-RET-1: the embedding model's identity (weights, tokenizer, pooling,
//!   dimensions) and the representation it consumed are bound.
//! - RIC-RET-2: retrieval never upgrades source authority. A retrieved
//!   chunk's trust and ceiling are at most its source's.
//! - RIC-RET-3: a similarity score never raises a ceiling. An unbound
//!   embedding, or one that consumed a sibling of the admitted
//!   representation, leaves the retrieval interpreter unresolved, and
//!   authority is capped at observe (RIC-R-8).
//!
//! This module is kernel logic: adapters report facts, the kernel judges.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha384};

use crate::delegation::AuthorityCeiling;
use crate::receipt::{ReceiptVerifyError, put_str, put_u64};
use crate::signing::{ReceiptSignature, ReceiptSigner, hex_digest, verify_receipt_signature};
use crate::types::{Provenance, RepresentationReceipt, TrustLevel};

/// Version of the retrieval receipt and its signing message.
pub const RETRIEVAL_RECEIPT_VERSION: u32 = 1;
const RETRIEVAL_DOMAIN: &str = "sigil-retrieval-v1";
const MODEL_DOMAIN: &str = "sigil-embedding-model-v1";

/// How token vectors become one embedding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pooling {
    Mean,
    Cls,
    LastToken,
    Max,
}

impl Pooling {
    /// The label signed into receipts (the serialized form).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::Mean => "mean",
            Self::Cls => "cls",
            Self::LastToken => "last_token",
            Self::Max => "max",
        }
    }
}

/// The identity of an embedding model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingModel {
    /// A label; the digest is the identity.
    pub name: String,
    /// SHA-384 over the weights file(s).
    pub weights_digest: String,
    /// SHA-384 over the tokenizer or vocabulary the model reads text with.
    pub tokenizer_digest: String,
    pub pooling: Pooling,
    pub dimensions: u64,
}

impl EmbeddingModel {
    /// SHA-384 over the model's fields, length-prefixed under its domain.
    #[must_use]
    pub fn identity_digest(&self) -> String {
        let mut out = Vec::new();
        put_str(&mut out, MODEL_DOMAIN);
        put_model(&mut out, self);
        hex_digest(&Sha384::digest(&out))
    }
}

fn put_model(out: &mut Vec<u8>, model: &EmbeddingModel) {
    put_str(out, &model.name);
    put_str(out, &model.weights_digest);
    put_str(out, &model.tokenizer_digest);
    put_str(out, model.pooling.label());
    put_u64(out, model.dimensions);
}

/// What the embedding model actually consumed, as its adapter reports it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddedInput {
    /// Canonical digest of the admitted text the model was given (the
    /// chunk receipt's `canonical_digest`).
    pub admitted_digest: String,
    /// SHA-384 over what the model consumed (token IDs as little-endian
    /// `u32` for subword models, the in-vocabulary words for word models).
    pub consumed_digest: String,
    /// Tokens or words the model consumed.
    pub consumed_units: u64,
    /// Bytes of the admitted text the model's tokenizer discarded
    /// (out-of-vocabulary words, unmapped characters).
    pub dropped_bytes: u64,
}

impl EmbeddedInput {
    /// The input a subword model consumed as token IDs. A byte-level BPE
    /// maps every byte, so nothing is dropped; a tokenizer that can drop
    /// content must report it in `dropped_bytes` instead.
    #[must_use]
    pub fn from_token_ids(admitted_digest: &str, ids: &[u32]) -> Self {
        let bytes: Vec<u8> = ids.iter().flat_map(|id| id.to_le_bytes()).collect();
        Self {
            admitted_digest: admitted_digest.to_string(),
            consumed_digest: hex_digest(&Sha384::digest(&bytes)),
            consumed_units: ids.len() as u64,
            dropped_bytes: 0,
        }
    }
}

/// A bound embedding: the model, what it consumed, and the score it gave.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmbeddingBinding {
    pub model: EmbeddingModel,
    pub input: EmbeddedInput,
    /// The similarity score. Recorded and signed; never raises authority.
    pub score: f64,
}

/// A retrieved chunk as it reaches the model-input boundary.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetrievedChunk {
    /// Where the chunk came from (document id, URL, index key).
    pub source_id: String,
    /// Trust of the source the chunk was indexed from.
    pub source_trust: TrustLevel,
    /// Ceiling of the source the chunk was indexed from.
    pub source_ceiling: AuthorityCeiling,
    /// The chunk's own representation receipt, from admitting its text.
    pub receipt: RepresentationReceipt,
    /// The embedding that ranked or filtered it. `None`: unbound.
    pub embedding: Option<EmbeddingBinding>,
}

/// What the kernel found at the retrieval boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetrievalFinding {
    /// No embedding identity or consumed representation was bound.
    UnboundEmbedding,
    /// The model was given text other than the admitted representation.
    EmbeddedSiblingRepresentation,
    /// The model's tokenizer discarded part of the admitted text, so its
    /// score is about a representation the model will not receive.
    EmbeddingDroppedContent,
}

/// The kernel's judgment of a retrieved chunk.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetrievalAssessment {
    pub trust: TrustLevel,
    pub ceiling: AuthorityCeiling,
    pub findings: Vec<RetrievalFinding>,
}

/// Judge a retrieved chunk. `content_ceiling` is the ceiling SIGIL's scan
/// of the chunk's text produced. The result is never above the source's
/// trust or ceiling (RIC-RET-2), and the similarity score is not read
/// (RIC-RET-3): only binding resolves the interpreter.
#[must_use]
pub fn assess_retrieval(
    chunk: &RetrievedChunk,
    content_ceiling: AuthorityCeiling,
) -> RetrievalAssessment {
    let trust = chunk
        .source_trust
        .min(Provenance::Retrieval.default_trust());
    let mut ceiling = content_ceiling.min(chunk.source_ceiling);
    let findings = binding_findings(chunk);
    if !findings.is_empty() {
        ceiling = ceiling.min(AuthorityCeiling::Observe);
    }
    RetrievalAssessment {
        trust,
        ceiling,
        findings,
    }
}

fn binding_findings(chunk: &RetrievedChunk) -> Vec<RetrievalFinding> {
    let Some(binding) = &chunk.embedding else {
        return vec![RetrievalFinding::UnboundEmbedding];
    };
    let mut findings = Vec::new();
    if binding.input.admitted_digest != chunk.receipt.canonical_digest {
        findings.push(RetrievalFinding::EmbeddedSiblingRepresentation);
    }
    if binding.input.dropped_bytes > 0 {
        findings.push(RetrievalFinding::EmbeddingDroppedContent);
    }
    findings
}

/// A signed record of one bound retrieval decision.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RetrievalReceipt {
    pub retrieval_version: u32,
    pub source_id: String,
    pub source_trust: TrustLevel,
    pub source_ceiling: AuthorityCeiling,
    /// Canonical digest of the chunk's admitted representation.
    pub chunk_digest: String,
    pub model: EmbeddingModel,
    /// `model.identity_digest()`, recorded for lookup; verification
    /// recomputes it.
    pub model_identity: String,
    pub input: EmbeddedInput,
    pub score: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ReceiptSignature>,
}

fn trust_label(trust: TrustLevel) -> &'static str {
    match trust {
        TrustLevel::Untrusted => "untrusted",
        TrustLevel::Bounded => "bounded",
        TrustLevel::Trusted => "trusted",
        TrustLevel::Privileged => "privileged",
    }
}

/// The retrieval signing message: length-prefixed fields under its domain;
/// the score as its IEEE-754 binary64 bits, big-endian.
#[must_use]
pub fn retrieval_message(receipt: &RetrievalReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    put_str(&mut out, RETRIEVAL_DOMAIN);
    put_str(&mut out, &receipt.source_id);
    put_str(&mut out, trust_label(receipt.source_trust));
    put_str(&mut out, &receipt.source_ceiling.to_string());
    put_str(&mut out, &receipt.chunk_digest);
    put_model(&mut out, &receipt.model);
    put_str(&mut out, &receipt.model_identity);
    put_str(&mut out, &receipt.input.admitted_digest);
    put_str(&mut out, &receipt.input.consumed_digest);
    put_u64(&mut out, receipt.input.consumed_units);
    put_u64(&mut out, receipt.input.dropped_bytes);
    out.extend_from_slice(&receipt.score.to_bits().to_be_bytes());
    out
}

/// Build and sign the retrieval receipt of a bound chunk. `None` for an
/// unbound chunk or a non-finite score: there is nothing bound to record.
#[must_use]
pub fn sign_retrieval(
    chunk: &RetrievedChunk,
    signer: &dyn ReceiptSigner,
) -> Option<RetrievalReceipt> {
    let binding = chunk.embedding.as_ref().filter(|b| b.score.is_finite())?;
    let mut receipt = RetrievalReceipt {
        retrieval_version: RETRIEVAL_RECEIPT_VERSION,
        source_id: chunk.source_id.clone(),
        source_trust: chunk.source_trust,
        source_ceiling: chunk.source_ceiling,
        chunk_digest: chunk.receipt.canonical_digest.clone(),
        model: binding.model.clone(),
        model_identity: binding.model.identity_digest(),
        input: binding.input.clone(),
        score: binding.score,
        signature: None,
    };
    let message = retrieval_message(&receipt);
    receipt.signature = Some(ReceiptSignature {
        algorithm: signer.algorithm(),
        key_id: signer.key_id(),
        signature: hex_digest(&signer.sign(&message)),
    });
    Some(receipt)
}

/// Verify a retrieval receipt.
///
/// # Errors
/// `Unsigned`; `UnsupportedVersion` for any version but 1; a signature
/// `Mismatch` when any field, or a recorded `model_identity` that is not the
/// model's own digest, differs from what was signed.
pub fn verify_retrieval_receipt(
    receipt: &RetrievalReceipt,
    verification_key: &str,
) -> Result<(), ReceiptVerifyError> {
    let signature = receipt
        .signature
        .as_ref()
        .ok_or(ReceiptVerifyError::Unsigned)?;
    if receipt.retrieval_version != RETRIEVAL_RECEIPT_VERSION {
        return Err(ReceiptVerifyError::UnsupportedVersion(
            receipt.retrieval_version,
        ));
    }
    if receipt.model_identity != receipt.model.identity_digest() {
        return Err(ReceiptVerifyError::InconsistentModelIdentity);
    }
    verify_receipt_signature(&retrieval_message(receipt), signature, verification_key)?;
    Ok(())
}
