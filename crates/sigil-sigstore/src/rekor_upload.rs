use crate::bundle_ops::getrandom_fill;
use crate::error::*;
use crate::signer::RekorUploadReceipt;
use base64::Engine as _;
use p384::ecdsa::{SigningKey, VerifyingKey};
use p384::elliptic_curve::generic_array::GenericArray;
use serde::Deserialize;
use sha2::{Digest as _, Sha384};
use sigil_core::signing::hex_digest;

pub fn upload_to_rekor(
    rekor_url: &str,
    message: &[u8],
    signature: &[u8],
    public_key_pem: &str,
) -> Result<RekorUploadReceipt, SigstoreError> {
    #[derive(Deserialize)]
    struct RekorResponse {
        #[serde(flatten)]
        entries: std::collections::BTreeMap<String, serde_json::Value>,
    }

    let mut hasher = sha2::Sha384::new();
    hasher.update(message);
    let message_hash = hex_digest(&hasher.finalize());

    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|err| SigstoreError::Rekor(format!("client: {err}")))?;
    let body = serde_json::json!({
        "apiVersion": "0.0.1",
        "kind": "hashedrekord",
        "spec": {
            "data": { "hash": { "algorithm": "sha384", "value": message_hash } },
            "signature": {
                "content": base64::engine::general_purpose::STANDARD.encode(signature),
                "publicKey": { "content": base64::engine::general_purpose::STANDARD.encode(public_key_pem) }
            }
        }
    });
    let response = client
        .post(format!("{rekor_url}/api/v1/log/entries"))
        .json(&body)
        .send()
        .map_err(|err| SigstoreError::Rekor(format!("request: {err}")))?;
    if !response.status().is_success() {
        return Err(SigstoreError::Rekor(format!(
            "status {}",
            response.status()
        )));
    }
    let parsed: RekorResponse = response
        .json()
        .map_err(|err| SigstoreError::Rekor(format!("parse: {err}")))?;
    let (uuid, entry) = parsed
        .entries
        .into_iter()
        .next()
        .ok_or_else(|| SigstoreError::Rekor("empty log response".to_string()))?;
    let log_id = entry
        .get("logID")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    let log_index = entry
        .get("logIndex")
        .and_then(|v| v.as_i64())
        .unwrap_or_default();
    Ok(RekorUploadReceipt {
        log_id,
        log_index,
        uuid,
    })
}

/// Ephemeral P-384 key from OS entropy; the scalar is redrawn on the
/// astronomically unlikely out-of-range case.
pub(crate) fn ephemeral_key() -> SigningKey {
    loop {
        let mut bytes = [0u8; 48];
        getrandom_fill(&mut bytes);
        if let Ok(key) = SigningKey::from_bytes(GenericArray::from_slice(&bytes)) {
            return key;
        }
    }
}

pub(crate) fn key_id_for(verifying_key: &VerifyingKey) -> String {
    let point = verifying_key.to_encoded_point(false);
    let mut hasher = Sha384::new();
    hasher.update(point.as_bytes());
    let digest = hasher.finalize();
    hex_digest(&digest[..8])
}
