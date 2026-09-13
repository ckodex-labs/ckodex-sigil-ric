use crate::bundle_types::*;
use crate::error::*;
use base64::Engine as _;
use sha2::{Digest as _, Sha384};
use sigil_core::signing::{hex_digest, SignatureVerifyError};

pub fn build_bundle(
    message: &[u8],
    signature: &[u8],
    certificate_chain_der: &[u8],
) -> Result<SigstoreBundle, SigstoreError> {
    let certificates = split_der_chain(certificate_chain_der)?
        .into_iter()
        .map(|der| BundleCertificate {
            raw_bytes: base64::engine::general_purpose::STANDARD.encode(der),
        })
        .collect();
    let mut hasher = Sha384::new();
    hasher.update(message);
    Ok(SigstoreBundle {
        media_type: BUNDLE_MEDIA_TYPE.to_string(),
        verification_material: BundleVerificationMaterial {
            x509_certificate_chain: BundleX509Chain { certificates },
        },
        message_signature: BundleMessageSignature {
            message_digest: BundleMessageDigest {
                algorithm: "SHA2_384".to_string(),
                digest: base64::engine::general_purpose::STANDARD.encode(hasher.finalize()),
            },
            signature: base64::engine::general_purpose::STANDARD.encode(signature),
        },
    })
}

/// Split a concatenated DER chain (leaf first) into individual certificates
/// by parsing each SEQUENCE length. The Fulcio response concatenates DER
/// blobs without framing, so length-walking is required.
fn split_der_chain(der: &[u8]) -> Result<Vec<Vec<u8>>, SigstoreError> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while cursor < der.len() {
        let rest = &der[cursor..];
        // SEQUENCE tag (0x30) + DER length.
        if rest.first() != Some(&0x30) {
            return Err(SigstoreError::Fulcio(
                "certificate chain is not a DER SEQUENCE sequence".to_string(),
            ));
        }
        let (length, header_len) = decode_der_length(rest)?;
        let total = header_len + length;
        if cursor + total > der.len() {
            return Err(SigstoreError::Fulcio(
                "certificate chain truncated".to_string(),
            ));
        }
        out.push(rest[..total].to_vec());
        cursor += total;
    }
    if out.is_empty() {
        return Err(SigstoreError::Fulcio("empty certificate chain".to_string()));
    }
    Ok(out)
}

/// Decode a DER length field (short or long form). Returns (length, header bytes).
fn decode_der_length(bytes: &[u8]) -> Result<(usize, usize), SigstoreError> {
    let first = *bytes
        .get(1)
        .ok_or(SigstoreError::Fulcio("truncated DER".to_string()))?;
    if first < 0x80 {
        Ok((first as usize, 2))
    } else {
        let num_bytes = (first & 0x7f) as usize;
        if num_bytes == 0 || num_bytes > 4 || bytes.len() < 2 + num_bytes {
            return Err(SigstoreError::Fulcio("invalid DER length".to_string()));
        }
        let mut length = 0usize;
        for byte in &bytes[2..2 + num_bytes] {
            length = (length << 8) | *byte as usize;
        }
        Ok((length, 2 + num_bytes))
    }
}

/// Verify a Sigstore bundle against the expected message: the leaf
/// certificate's public key must verify the signature over the message.
///
/// Scope, stated honestly: this verifies the *signature binding* (message →
/// leaf certificate key). Full keyless verification additionally requires
/// (a) validating the Fulcio chain up to a pinned trust root, (b) checking
/// the leaf certificate's SAN identity and validity window, and (c) checking
/// the Rekor inclusion proof — those are the next increment and are NOT
/// performed by this function.
pub fn verify_bundle(bundle: &SigstoreBundle, message: &[u8]) -> Result<(), SignatureVerifyError> {
    use der::Decode;
    use sigil_core::signing::ReceiptSignature;

    if bundle.media_type != BUNDLE_MEDIA_TYPE {
        return Err(SignatureVerifyError::UnsupportedAlgorithm(
            bundle.media_type.clone(),
        ));
    }
    let certificates = &bundle
        .verification_material
        .x509_certificate_chain
        .certificates;
    let leaf = certificates
        .first()
        .ok_or(SignatureVerifyError::InvalidKey)?;
    let leaf_der = base64::engine::general_purpose::STANDARD
        .decode(&leaf.raw_bytes)
        .map_err(|_| SignatureVerifyError::InvalidKey)?;

    // Extract the leaf's public key point from the certificate SPKI.
    let certificate: x509_cert::certificate::Certificate =
        x509_cert::certificate::Certificate::from_der(&leaf_der)
            .map_err(|_| SignatureVerifyError::InvalidKey)?;
    let point = certificate
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(SignatureVerifyError::InvalidKey)?;
    let verification_key_hex = hex_digest(point);

    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&bundle.message_signature.signature)
        .map_err(|_| SignatureVerifyError::InvalidSignature)?;
    let receipt_signature = ReceiptSignature {
        algorithm: "ecdsa-p384-sha384".to_string(),
        key_id: String::new(),
        signature: hex_digest(&sig_bytes),
    };
    sigil_core::signing::verify_receipt_signature(
        message,
        &receipt_signature,
        &verification_key_hex,
    )
}

pub(crate) fn getrandom_fill(bytes: &mut [u8]) {
    getrandom::getrandom(bytes).expect("OS entropy unavailable");
}
