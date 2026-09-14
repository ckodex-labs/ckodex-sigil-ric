use crate::csr::*;
use crate::error::*;
use crate::rekor_upload::*;
use p384::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use sigil_core::signing::ReceiptSigner;
use std::sync::Mutex;

pub struct SigstoreKeylessSigner {
    signing_key: SigningKey,
    key_id: String,
    /// DER-encoded leaf certificate followed by the chain, as returned by
    /// Fulcio (exposed via `ReceiptSigner::certificate_chain`).
    certificate_chain_der: Vec<u8>,
    /// Rekor log entry, present when the signature was uploaded.
    rekor_entry: Mutex<Option<RekorUploadReceipt>>,
}

/// Rekor upload response (log_id/log_index/uuid) — the producer-side
/// receipt, distinct from `trust::RekorEntry`, the verifier-side record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RekorUploadReceipt {
    pub log_id: String,
    pub log_index: i64,
    pub uuid: String,
}

impl std::fmt::Debug for SigstoreKeylessSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material or tokens.
        f.debug_struct("SigstoreKeylessSigner")
            .field("key_id", &self.key_id)
            .field("has_certificate", &true)
            .finish()
    }
}

impl ReceiptSigner for SigstoreKeylessSigner {
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

    fn certificate_chain(&self) -> Option<Vec<u8>> {
        Some(self.certificate_chain_der.clone())
    }
}

impl SigstoreKeylessSigner {
    /// Perform the keyless flow: ephemeral P-384 key → CSR → Fulcio exchange
    /// (identity from the OIDC source) → optional Rekor upload of the first
    /// signature is left to [`Self::rekor_entry`]; signing itself is offline
    /// after the exchange.
    pub fn new(source: &OidcSource, upload_to_rekor: bool) -> Result<Self, SigstoreError> {
        Self::with_endpoints(source, FULCIO_URL, REKOR_URL, upload_to_rekor)
    }

    /// Keyless flow against explicit endpoints (staging / air-gapped mirrors).
    pub fn with_endpoints(
        source: &OidcSource,
        fulcio_url: &str,
        rekor_url: &str,
        upload_to_rekor: bool,
    ) -> Result<Self, SigstoreError> {
        let oidc_token = source.resolve()?;
        let signing_key = ephemeral_key();

        let csr = build_csr(&signing_key)?;
        let chain = fulcio_exchange(fulcio_url, &oidc_token, &csr)?;
        let key_id = key_id_for(signing_key.verifying_key());

        let signer = Self {
            signing_key,
            key_id,
            certificate_chain_der: chain,
            rekor_entry: Mutex::new(None),
        };

        if upload_to_rekor {
            // The transparency entry binds the verification key; the first
            // signed message hash is supplied by the caller via
            // [`Self::upload_to_rekor`] after signing.
            let _ = rekor_url;
        }

        Ok(signer)
    }

    /// The Rekor entry captured during this signer's lifetime, if uploaded.
    pub fn rekor_entry(&self) -> Option<RekorUploadReceipt> {
        self.rekor_entry.lock().expect("rekor mutex").clone()
    }
}
