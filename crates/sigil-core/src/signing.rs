//! Receipt signing (RIC DEV-3).
//!
//! The kernel defines a signer *port*; key material never enters `Policy`
//! (which is plain serializable data). Deployments attach a signer to the
//! engine explicitly; the reference adapter is **ECDSA P-384** (NIST
//! P-384 / secp384r1) with SHA-384 and deterministic nonces per RFC 6979 —
//! no RNG dependency, deterministic signatures. Sigstore keyless and HSM
//! signers are future adapters of the same port.
//!
//! The signed message is the canonical receipt content — raw digest,
//! canonical digest, normalization profile, tokenizer identity, and token
//! count — so any tampering with the admitted-representation binding is
//! detectable (docs/RIC-CONTRACT.md RIC-R-1..R-4).

use p384::ecdsa::{
    signature::Signer as _, signature::Verifier as _, Signature, SigningKey, VerifyingKey,
};
use p384::elliptic_curve::generic_array::GenericArray;
use p384::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Signature attached to a `RepresentationReceipt`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReceiptSignature {
    /// Signature algorithm identifier (e.g. "ecdsa-p384-sha384").
    pub algorithm: String,
    /// Identifier of the signing key (derived from the verification key).
    pub key_id: String,
    /// Signature bytes (r||s, 96 bytes for P-384), hex-encoded.
    pub signature: String,
}

/// Verification failures. Malformed inputs are distinct from cryptographic
/// mismatches so operators can tell misconfiguration from tampering.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum SignatureVerifyError {
    #[error("unsupported signature algorithm: {0}")]
    UnsupportedAlgorithm(String),
    #[error("invalid verification key encoding")]
    InvalidKey,
    #[error("invalid signature encoding")]
    InvalidSignature,
    #[error("signature does not match the receipt content")]
    Mismatch,
}

/// Signer port. Implementations hold key material; the kernel only calls
/// `sign`, and records `algorithm` and `key_id` with the receipt.
pub trait ReceiptSigner: std::fmt::Debug + Send + Sync {
    /// Signature algorithm identifier recorded on the receipt
    /// (e.g. "ecdsa-p384-sha384").
    fn algorithm(&self) -> String;
    fn key_id(&self) -> String;
    fn sign(&self, message: &[u8]) -> Vec<u8>;
    /// DER-encoded signing certificate chain, when the signer is
    /// certificate-bearing (Sigstore keyless signers return the Fulcio
    /// chain; file-based signers return `None`). Verification of a
    /// keyless receipt requires the certificate to establish identity.
    fn certificate_chain(&self) -> Option<Vec<u8>> {
        None
    }
}

/// Deterministic message binding a receipt's content. Versioned so the
/// scheme can evolve without ambiguity about what was signed. v2 adds the
/// digest algorithm label to the signed content (SHA-384 mandate, RIC §5).
pub fn receipt_message(
    raw_digest: &str,
    canonical_digest: &str,
    digest_algorithm: &str,
    normalization: &str,
    vocab: &str,
    token_count: usize,
) -> Vec<u8> {
    format!(
        "sigil-receipt-v2|raw={raw_digest}|canonical={canonical_digest}|digest={digest_algorithm}|norm={normalization}|vocab={vocab}|tokens={token_count}"
    )
    .into_bytes()
}

/// ECDSA P-384 reference signer (NIST P-384 / secp384r1, SHA-384, RFC 6979
/// deterministic nonces). Constructed from a 48-byte private scalar; key
/// generation belongs to deployment tooling, not to this library.
#[derive(Clone)]
pub struct EcdsaP384Signer {
    signing_key: SigningKey,
    key_id: String,
}

/// Invalid private-key material (zero scalar or out of range).
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid ECDSA P-384 private key bytes")]
pub struct InvalidSigningKey;

impl std::fmt::Debug for EcdsaP384Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("EcdsaP384Signer")
            .field("key_id", &self.key_id)
            .finish()
    }
}

impl ReceiptSigner for EcdsaP384Signer {
    fn algorithm(&self) -> String {
        "ecdsa-p384-sha384".to_string()
    }

    fn key_id(&self) -> String {
        self.key_id.clone()
    }

    fn sign(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.signing_key.sign(message);
        signature.to_bytes().to_vec()
    }
}

impl EcdsaP384Signer {
    /// Build a signer from a 48-byte P-384 private scalar.
    pub fn from_private_key_bytes(bytes: &[u8; 48]) -> Result<Self, InvalidSigningKey> {
        let signing_key = SigningKey::from_bytes(GenericArray::from_slice(bytes))
            .map_err(|_| InvalidSigningKey)?;
        let key_id = key_id_for(signing_key.verifying_key());
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Generate a fresh key pair from OS entropy. The scalar is redrawn on
    /// the (astronomically unlikely) event of an out-of-range value.
    pub fn generate() -> Result<Self, InvalidSigningKey> {
        loop {
            let mut bytes = [0u8; 48];
            getrandom::getrandom(&mut bytes).map_err(|_| InvalidSigningKey)?;
            if let Ok(signer) = Self::from_private_key_bytes(&bytes) {
                return Ok(signer);
            }
        }
    }

    /// Load a signer from an unencrypted PKCS#8 PEM private key
    /// (OpenSSL-interoperable: `openssl pkcs8 -topk8 -nocrypt`).
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, InvalidSigningKey> {
        let signing_key = SigningKey::from_pkcs8_pem(pem).map_err(|_| InvalidSigningKey)?;
        let key_id = key_id_for(signing_key.verifying_key());
        Ok(Self {
            signing_key,
            key_id,
        })
    }

    /// Serialize the private key as unencrypted PKCS#8 PEM.
    pub fn to_pkcs8_pem(&self) -> Result<String, InvalidSigningKey> {
        self.signing_key
            .to_pkcs8_pem(LineEnding::LF)
            .map(|pem| pem.to_string())
            .map_err(|_| InvalidSigningKey)
    }

    /// Serialize the verification key as SPKI PEM (public material).
    pub fn public_key_pem(&self) -> Result<String, InvalidSigningKey> {
        self.signing_key
            .verifying_key()
            .to_public_key_pem(LineEnding::LF)
            .map_err(|_| InvalidSigningKey)
    }

    /// Hex-encoded verification key (uncompressed SEC1 point, 97 bytes)
    /// to pin in verifiers.
    pub fn verification_key_hex(&self) -> String {
        let point = self.signing_key.verifying_key().to_encoded_point(false);
        hex_digest(point.as_bytes())
    }
}

/// Verify a receipt signature against a hex-encoded ECDSA P-384
/// verification key (uncompressed SEC1 point).
pub fn verify_receipt_signature(
    message: &[u8],
    signature: &ReceiptSignature,
    verification_key_hex: &str,
) -> Result<(), SignatureVerifyError> {
    if signature.algorithm != "ecdsa-p384-sha384" {
        return Err(SignatureVerifyError::UnsupportedAlgorithm(
            signature.algorithm.clone(),
        ));
    }
    let key_bytes = decode_hex(verification_key_hex).ok_or(SignatureVerifyError::InvalidKey)?;
    let verifying_key =
        VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| SignatureVerifyError::InvalidKey)?;
    let sig_bytes =
        decode_hex(&signature.signature).ok_or(SignatureVerifyError::InvalidSignature)?;
    let signature =
        Signature::from_slice(&sig_bytes).map_err(|_| SignatureVerifyError::InvalidSignature)?;
    verifying_key
        .verify(message, &signature)
        .map_err(|_| SignatureVerifyError::Mismatch)
}

fn key_id_for(verifying_key: &VerifyingKey) -> String {
    let point = verifying_key.to_encoded_point(false);
    let mut hasher = Sha256::new();
    hasher.update(point.as_bytes());
    let digest = hasher.finalize();
    hex_digest(&digest[..8])
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

pub fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signer() -> EcdsaP384Signer {
        EcdsaP384Signer::from_private_key_bytes(&[42u8; 48]).expect("valid scalar")
    }

    fn message() -> Vec<u8> {
        let raw = "a".repeat(96);
        let canonical = "b".repeat(96);
        receipt_message(&raw, &canonical, "sha384", "nfc", "cl100k_base", 9)
    }

    fn signed_receipt_signature(s: &EcdsaP384Signer, msg: &[u8]) -> ReceiptSignature {
        ReceiptSignature {
            algorithm: s.algorithm(),
            key_id: s.key_id(),
            signature: hex_digest(&s.sign(msg)),
        }
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let signer = signer();
        let receipt_signature = signed_receipt_signature(&signer, &message());
        assert_eq!(
            verify_receipt_signature(
                &message(),
                &receipt_signature,
                &signer.verification_key_hex()
            ),
            Ok(())
        );
    }

    #[test]
    fn tampered_message_fails_verification() {
        let signer = signer();
        let receipt_signature = signed_receipt_signature(&signer, &message());
        let tampered = receipt_message(
            &"c".repeat(96),
            &"b".repeat(96),
            "sha384",
            "nfc",
            "cl100k_base",
            9,
        );
        assert_eq!(
            verify_receipt_signature(
                &tampered,
                &receipt_signature,
                &signer.verification_key_hex()
            ),
            Err(SignatureVerifyError::Mismatch)
        );
    }

    #[test]
    fn wrong_key_fails_verification() {
        let signer = signer();
        let other = EcdsaP384Signer::from_private_key_bytes(&[7u8; 48]).expect("valid scalar");
        let receipt_signature = signed_receipt_signature(&signer, &message());
        assert_ne!(
            verify_receipt_signature(
                &message(),
                &receipt_signature,
                &other.verification_key_hex()
            ),
            Ok(())
        );
    }

    #[test]
    fn garbage_signature_hex_is_rejected() {
        let signer = signer();
        let receipt_signature = ReceiptSignature {
            algorithm: "ecdsa-p384-sha384".to_string(),
            key_id: signer.key_id(),
            signature: "zz".to_string(),
        };
        assert_eq!(
            verify_receipt_signature(
                &message(),
                &receipt_signature,
                &signer.verification_key_hex()
            ),
            Err(SignatureVerifyError::InvalidSignature)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let signer = signer();
        let receipt_signature = ReceiptSignature {
            algorithm: "ed25519".to_string(),
            key_id: signer.key_id(),
            signature: hex_digest(&signer.sign(&message())),
        };
        assert_eq!(
            verify_receipt_signature(
                &message(),
                &receipt_signature,
                &signer.verification_key_hex()
            ),
            Err(SignatureVerifyError::UnsupportedAlgorithm(
                "ed25519".to_string()
            ))
        );
    }

    #[test]
    fn signatures_are_deterministic_and_key_ids_stable() {
        let signer = signer();
        assert_eq!(signer.sign(&message()), signer.sign(&message()));
        assert_eq!(
            signer.key_id(),
            EcdsaP384Signer::from_private_key_bytes(&[42u8; 48])
                .expect("valid scalar")
                .key_id()
        );
        assert_ne!(
            signer.key_id(),
            EcdsaP384Signer::from_private_key_bytes(&[43u8; 48])
                .expect("valid scalar")
                .key_id()
        );
    }

    #[test]
    fn zero_scalar_is_rejected() {
        assert_eq!(
            EcdsaP384Signer::from_private_key_bytes(&[0u8; 48]).err(),
            Some(InvalidSigningKey)
        );
    }

    #[test]
    fn pkcs8_pem_roundtrip_preserves_key_identity() {
        let signer = EcdsaP384Signer::generate().expect("generate");
        let pem = signer.to_pkcs8_pem().expect("pkcs8 pem");
        assert!(pem.contains("BEGIN PRIVATE KEY"));
        let reloaded = EcdsaP384Signer::from_pkcs8_pem(&pem).expect("parse pem");
        assert_eq!(signer.key_id(), reloaded.key_id());
        assert_eq!(
            signer.verification_key_hex(),
            reloaded.verification_key_hex()
        );
        // Signatures from the reloaded key verify against the original key.
        let msg = b"pkcs8 roundtrip";
        let receipt_signature = ReceiptSignature {
            algorithm: reloaded.algorithm(),
            key_id: reloaded.key_id(),
            signature: hex_digest(&reloaded.sign(msg)),
        };
        assert_eq!(
            verify_receipt_signature(msg, &receipt_signature, &signer.verification_key_hex()),
            Ok(())
        );
    }

    #[test]
    fn public_key_pem_is_valid_spki() {
        let signer = EcdsaP384Signer::generate().expect("generate");
        let pem = signer.public_key_pem().expect("spki pem");
        assert!(pem.contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn generated_keys_are_unique() {
        let a = EcdsaP384Signer::generate().expect("generate");
        let b = EcdsaP384Signer::generate().expect("generate");
        assert_ne!(a.key_id(), b.key_id());
    }
}
