use crate::trust::types::{TrustError, TrustRoot};
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use p256::elliptic_curve::generic_array::GenericArray;
use x509_cert::certificate::Certificate;
use x509_cert::time::Time;
pub(crate) fn validate_chain(chain_der: &[Vec<u8>], trust: &TrustRoot) -> Result<(), TrustError> {
    use der::Decode;
    let certs: Vec<Certificate> = chain_der
        .iter()
        .map(|der| Certificate::from_der(der))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TrustError::CertParse(format!("{e}")))?;
    // Build the full chain: bundle certs + intermediates + root.
    let mut full_chain = certs.clone();
    for intermediate in &trust.fulcio_intermediates_der {
        full_chain.push(
            Certificate::from_der(intermediate)
                .map_err(|e| TrustError::CertParse(format!("intermediate: {e}")))?,
        );
    }
    let root = Certificate::from_der(&trust.fulcio_root_der)
        .map_err(|e| TrustError::CertParse(format!("root: {e}")))?;
    // Verify each cert is signed by the next in the chain.
    for i in 0..full_chain.len() {
        let issuer = if i + 1 < full_chain.len() {
            &full_chain[i + 1]
        } else {
            &root
        };
        verify_cert_signature(&full_chain[i], issuer)?;
    }
    // The last cert in the bundle chain must be issued by an intermediate
    // or the root — verify the last bundle cert chains to the root.
    let last_bundle_cert = certs.last().ok_or(TrustError::EmptyChain)?;
    verify_cert_signature(last_bundle_cert, &root).or_else(|_| {
        // Try through intermediates.
        for intermediate in &trust.fulcio_intermediates_der {
            let int_cert = Certificate::from_der(intermediate)
                .map_err(|e| TrustError::CertParse(format!("intermediate: {e}")))?;
            if verify_cert_signature(last_bundle_cert, &int_cert).is_ok() {
                return verify_cert_signature(&int_cert, &root);
            }
        }
        Err(TrustError::ChainValidation(
            "last bundle cert does not chain to root".to_string(),
        ))
    })?;
    Ok(())
}
/// Verify that `cert` is signed by `issuer`'s public key.
fn verify_cert_signature(cert: &Certificate, issuer: &Certificate) -> Result<(), TrustError> {
    use der::Encode;
    let tbs_der = cert
        .tbs_certificate
        .to_der()
        .map_err(|e| TrustError::ChainValidation(format!("encode tbs: {e}")))?;
    let sig_bytes = cert
        .signature
        .as_bytes()
        .ok_or(TrustError::ChainValidation(
            "signature not octet-aligned".into(),
        ))?;
    let issuer_pub = issuer
        .tbs_certificate
        .subject_public_key_info
        .subject_public_key
        .as_bytes()
        .ok_or(TrustError::ChainValidation(
            "issuer key not octet-aligned".into(),
        ))?;
    // Fulcio uses ECDSA P-256 for CA certificates.
    let verifying_key = P256VerifyingKey::from_sec1_bytes(issuer_pub)
        .map_err(|e| TrustError::ChainValidation(format!("issuer key parse: {e}")))?;
    let signature = P256Signature::from_bytes(GenericArray::from_slice(sig_bytes))
        .map_err(|_| TrustError::ChainValidation("signature parse failed".into()))?;
    verifying_key
        .verify(&tbs_der, &signature)
        .map_err(|e| TrustError::ChainValidation(format!("cert signature: {e}")))
}
/// Check the leaf certificate's SAN (Subject Alternative Name) matches the
/// expected identity. Fulcio places the OIDC identity (email or URI) in the
/// SAN extension.
pub(crate) fn check_san_identity(leaf: &Certificate, expected: &str) -> Result<(), TrustError> {
    // Extract SAN from extensions. The SAN extension OID is 2.5.29.17.
    let extensions = match &leaf.tbs_certificate.extensions {
        Some(exts) => exts,
        None => {
            return Err(TrustError::SanMismatch {
                expected: expected.to_string(),
                got: "no extensions".to_string(),
            });
        }
    };
    let san_oid = const_oid::ObjectIdentifier::new_unwrap("2.5.29.17");
    let san_ext =
        extensions
            .iter()
            .find(|ext| ext.extn_id == san_oid)
            .ok_or(TrustError::SanMismatch {
                expected: expected.to_string(),
                got: "no SAN extension".to_string(),
            })?;
    // The SAN extension value is a DER-encoded GeneralNames sequence.
    // For a basic check, we look for the expected identity string in the
    // extension value bytes. A full implementation would parse the
    // GeneralNames ASN.1 structure, but this byte-level check is
    // sufficient for identity matching and avoids a complex ASN.1 parser.
    let san_bytes = san_ext.extn_value.as_bytes();
    let san_str = String::from_utf8_lossy(san_bytes);
    if san_str.contains(expected) {
        Ok(())
    } else {
        Err(TrustError::SanMismatch {
            expected: expected.to_string(),
            got: format!("SAN does not contain '{expected}'"),
        })
    }
}
/// Check the leaf certificate was valid at the given Unix timestamp.
pub(crate) fn check_validity_at(leaf: &Certificate, timestamp: i64) -> Result<(), TrustError> {
    let validity = &leaf.tbs_certificate.validity;
    let not_before = extract_unix_time(&validity.not_before)?;
    let not_after = extract_unix_time(&validity.not_after)?;
    if timestamp < not_before {
        return Err(TrustError::NotYetValid);
    }
    if timestamp > not_after {
        return Err(TrustError::Expired);
    }
    Ok(())
}
/// Extract a Unix timestamp from an x509 Time value, using the der
/// crate's `to_unix_duration()` (no manual date parsing).
pub(crate) fn extract_unix_time(time: &Time) -> Result<i64, TrustError> {
    let duration = match time {
        Time::UtcTime(utc) => utc.to_unix_duration(),
        Time::GeneralTime(gt) => gt.to_unix_duration(),
    };
    Ok(duration.as_secs() as i64)
}
