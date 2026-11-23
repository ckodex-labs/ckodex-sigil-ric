//! Receipt versions and the consumed media block (RIC-MM-001 WP5).
//!
//! One frozen signing-message builder per receipt version:
//!
//! - v2 is the pipe-delimited `sigil-receipt-v2` message (RIC-SPEC §5.1). It
//!   is frozen: receipts signed before v4 keep verifying.
//! - v3 is reserved for the remediation line and is not defined in this build.
//! - v4 adds the `consumed` block, the representation SIGIL produced for the
//!   model under a preprocessor profile (docs/ADR-001). Its message is a
//!   length-prefixed encoding under the domain `sigil-receipt-v4`, so no
//!   field value can shift a boundary and no v4 message equals a v2 one.

use serde::{Deserialize, Serialize};

use crate::signing::{
    ReceiptSignature, SignatureVerifyError, receipt_message, verify_receipt_signature,
};
use crate::types::RepresentationReceipt;

/// The receipt version this build emits.
pub const RECEIPT_VERSION: u32 = 4;
/// The version a receipt without a `receipt_version` field carries.
pub const LEGACY_RECEIPT_VERSION: u32 = 2;
const V4_DOMAIN: &str = "sigil-receipt-v4";

/// What is known about a consumed representation's fidelity to the
/// reference implementation of the model's preprocessor (docs/ADR-001).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ConsumedParity {
    /// A parity vector against the real reference passes bit for bit, and
    /// this input lies where the reference's behaviour is known.
    ReferenceMatched,
    /// Parity not shown for this input: authority is capped at observe.
    Approximate,
}

impl ConsumedParity {
    /// The label signed into a v4 receipt (the serialized form).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::ReferenceMatched => "reference-matched",
            Self::Approximate => "approximate",
        }
    }
}

/// How the model's engine obtained the consumed representation (RIC-SPEC
/// §5.1, decision O-5). Parity answers whether the profile matches the
/// reference preprocessor; delivery answers who produced the bytes the engine
/// consumed. It is evidence for a verifier and never raises authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Delivery {
    /// The engine runs its own preprocessor on the raw input; SIGIL's view
    /// reproduces it, as faithfully as `parity` states.
    EngineProcessed,
    /// The engine consumes SIGIL's view bytes unchanged (for example SGLang's
    /// `processor_output`): the view is the model's input by construction.
    SigilSupplied,
}

impl Delivery {
    /// The label signed into a v4 receipt (the serialized form).
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            Self::EngineProcessed => "engine-processed",
            Self::SigilSupplied => "sigil-supplied",
        }
    }

    /// Parse a label as [`Delivery::label`] writes it.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "engine-processed" => Some(Self::EngineProcessed),
            "sigil-supplied" => Some(Self::SigilSupplied),
            _ => None,
        }
    }
}

/// The consumed representation: what the model receives, produced by SIGIL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumedView {
    /// Profile name (a label).
    pub profile: String,
    /// The profile's SHA-384 identity.
    pub profile_digest: String,
    /// SHA-384 over the consumed bytes: row-major RGB8 for images, int16 LE
    /// samples for audio.
    pub digest: String,
    /// Parity of the consumed bytes with the reference preprocessor.
    pub parity: ConsumedParity,
    /// Identity digest of the extractor that read this view. `None`: nothing
    /// scanned it, and an unscanned view resolves nothing (P-MM-1 binds what
    /// SIGIL scanned), so the kernel treats it as no profile at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extractor: Option<String>,
    /// Vision-language placeholder tokens the view expands to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholders: Option<u64>,
    /// SHA-384 over the placeholder token-ID stream (vision start, the
    /// placeholders, vision end) as little-endian `u32`. `None` without a
    /// pinned model interpreter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placeholder_stream_digest: Option<String>,
    /// Identity digest of the model interpreter (tokenizer, chat template,
    /// processor and model config, each digest-pinned) the placeholder
    /// stream was computed with (RIC-MM-001 WP6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<String>,
    /// How the engine obtained these bytes, when the caller stated it.
    /// `None`: not stated. Never changes the authority cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
}

impl ConsumedView {
    /// True when an extractor read a reference-matched view: the only case
    /// in which the consumed representation resolves the interpreter.
    #[must_use]
    pub fn resolves_interpreter(&self) -> bool {
        self.extractor.is_some() && self.parity == ConsumedParity::ReferenceMatched
    }
}

/// Why a receipt could not be verified.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReceiptVerifyError {
    #[error("receipt is unsigned")]
    Unsigned,
    #[error("unsupported receipt version {0}")]
    UnsupportedVersion(u32),
    #[error("a v2 receipt cannot carry a consumed block: v2 does not sign it")]
    UnsignedConsumedBlock,
    #[error("the recorded model identity is not the model's own digest")]
    InconsistentModelIdentity,
    #[error(transparent)]
    Signature(#[from] SignatureVerifyError),
}

/// The signing message for a receipt, chosen by its `receipt_version`.
///
/// # Errors
/// `UnsupportedVersion` for any version but 2 and 4, and
/// `UnsignedConsumedBlock` for a v2 receipt that carries a consumed block
/// (its message would not cover it).
pub fn signing_message(receipt: &RepresentationReceipt) -> Result<Vec<u8>, ReceiptVerifyError> {
    match receipt.receipt_version {
        LEGACY_RECEIPT_VERSION if receipt.consumed.is_some() => {
            Err(ReceiptVerifyError::UnsignedConsumedBlock)
        }
        LEGACY_RECEIPT_VERSION => Ok(receipt_message(
            &receipt.raw_digest,
            &receipt.canonical_digest,
            &receipt.digest_algorithm,
            &receipt.normalization,
            &receipt.vocab,
            receipt.token_count,
        )),
        RECEIPT_VERSION => Ok(v4_message(receipt)),
        other => Err(ReceiptVerifyError::UnsupportedVersion(other)),
    }
}

/// The v4 signing message. Every field is length-prefixed (`u64` big-endian)
/// after the domain; optional fields carry a presence byte.
#[must_use]
pub fn v4_message(receipt: &RepresentationReceipt) -> Vec<u8> {
    let mut out = Vec::new();
    put_str(&mut out, V4_DOMAIN);
    for field in [
        &receipt.raw_digest,
        &receipt.canonical_digest,
        &receipt.digest_algorithm,
        &receipt.normalization,
        &receipt.vocab,
    ] {
        put_str(&mut out, field);
    }
    put_u64(&mut out, receipt.token_count as u64);
    match &receipt.consumed {
        None => out.push(0),
        Some(view) => {
            out.push(1);
            put_str(&mut out, &view.profile);
            put_str(&mut out, &view.profile_digest);
            put_str(&mut out, &view.digest);
            put_str(&mut out, view.parity.label());
            put_opt_str(&mut out, view.extractor.as_deref());
            match view.placeholders {
                None => out.push(0),
                Some(count) => {
                    out.push(1);
                    put_u64(&mut out, count);
                }
            }
            put_opt_str(&mut out, view.placeholder_stream_digest.as_deref());
            put_opt_str(&mut out, view.interpreter.as_deref());
            put_opt_str(&mut out, view.delivery.map(Delivery::label));
        }
    }
    out
}

/// Verify a receipt's signature over the message its version defines.
///
/// # Errors
/// `Unsigned`, a version error from [`signing_message`], or the signature
/// failure.
pub fn verify_receipt<'r>(
    receipt: &'r RepresentationReceipt,
    verification_key: &str,
) -> Result<&'r ReceiptSignature, ReceiptVerifyError> {
    let signature = receipt
        .signature
        .as_ref()
        .ok_or(ReceiptVerifyError::Unsigned)?;
    let message = signing_message(receipt)?;
    verify_receipt_signature(&message, signature, verification_key)?;
    Ok(signature)
}

pub(crate) fn legacy_receipt_version() -> u32 {
    LEGACY_RECEIPT_VERSION
}

pub(crate) fn put_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

pub(crate) fn put_str(out: &mut Vec<u8>, value: &str) {
    put_u64(out, value.len() as u64);
    out.extend_from_slice(value.as_bytes());
}

fn put_opt_str(out: &mut Vec<u8>, value: Option<&str>) {
    match value {
        None => out.push(0),
        Some(text) => {
            out.push(1);
            put_str(out, text);
        }
    }
}
