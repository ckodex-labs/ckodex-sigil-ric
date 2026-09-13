use crate::error::*;
use base64::Engine as _;
use p384::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use x509_cert::attr::Attributes;
use x509_cert::name::RdnSequence;
use x509_cert::request::{CertReq, CertReqInfo};
use x509_cert::spki::{AlgorithmIdentifierOwned, SubjectPublicKeyInfoOwned};

pub(crate) fn build_csr(signing_key: &SigningKey) -> Result<Vec<u8>, SigstoreError> {
    use der::asn1::BitString;
    use der::Encode;

    let public_key = p384::PublicKey::from(signing_key.verifying_key());
    let spki =
        SubjectPublicKeyInfoOwned::from_key(public_key).map_err(|_| SigstoreError::CsrFailed)?;
    let info = CertReqInfo {
        version: x509_cert::request::Version::V1,
        subject: RdnSequence::default(),
        public_key: spki,
        attributes: Attributes::default(),
    };
    let info_der = info.to_der().map_err(|_| SigstoreError::CsrFailed)?;

    let signature: Signature = signing_key.sign(&info_der);
    let algorithm = AlgorithmIdentifierOwned {
        oid: const_oid::db::rfc5912::ECDSA_WITH_SHA_384,
        parameters: None,
    };
    let cert_req = CertReq {
        info,
        algorithm,
        signature: BitString::new(0, signature.to_bytes().to_vec())
            .map_err(|_| SigstoreError::CsrFailed)?,
    };
    cert_req.to_der().map_err(|_| SigstoreError::CsrFailed)
}

/// Wrap a DER PKCS#10 CSR in PEM framing (Fulcio v2 expects PEM-encoded
/// CSRs in the `certificateSigningRequest` bytes field).
pub(crate) fn pem_csr(csr_der: &[u8]) -> Result<String, SigstoreError> {
    use der::{Decode, EncodePem};
    use p384::pkcs8::LineEnding;
    use x509_cert::request::CertReq;
    let cert_req = CertReq::from_der(csr_der).map_err(|_| SigstoreError::CsrFailed)?;
    cert_req
        .to_pem(LineEnding::LF)
        .map_err(|_| SigstoreError::CsrFailed)
}

/// Exchange the CSR + OIDC token for a Fulcio certificate chain (DER).
pub(crate) fn fulcio_exchange(
    fulcio_url: &str,
    oidc_token: &str,
    csr_der: &[u8],
) -> Result<Vec<u8>, SigstoreError> {
    // Fulcio v2 (fulcio.proto CreateSigningCertificateRequest): the OIDC
    // token travels in the body (credentials.oidcIdentityToken); the CSR is
    // PKCS#10 PEM-encoded, base64'd again by the proto-JSON bytes mapping.
    // Verified against sigstore/fulcio fulcio.proto (main, 2026-09).
    #[derive(Serialize)]
    struct FulcioCredentials<'a> {
        #[serde(rename = "oidcIdentityToken")]
        oidc_identity_token: &'a str,
    }
    #[derive(Serialize)]
    struct FulcioRequest<'a> {
        credentials: FulcioCredentials<'a>,
        #[serde(rename = "certificateSigningRequest")]
        certificate_signing_request: &'a str,
    }
    #[derive(Deserialize)]
    struct FulcioResponse {
        #[serde(rename = "signedCertificateEmbeddedSct")]
        signed_certificate_embedded_sct: Option<FulcioSignedCertificate>,
        #[serde(rename = "signedCertificate")]
        signed_certificate: Option<FulcioSignedCertificate>,
    }
    #[derive(Deserialize)]
    struct FulcioSignedCertificate {
        chain: FulcioChain,
    }
    #[derive(Deserialize)]
    struct FulcioChain {
        certificates: Vec<String>,
    }

    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|err| SigstoreError::Fulcio(format!("client: {err}")))?;
    let csr_pem = pem_csr(csr_der)?;
    let body = FulcioRequest {
        credentials: FulcioCredentials {
            oidc_identity_token: oidc_token,
        },
        certificate_signing_request: &base64::engine::general_purpose::STANDARD
            .encode(csr_pem.as_bytes()),
    };
    let response = client
        .post(format!("{fulcio_url}/api/v2/signingCert"))
        .json(&body)
        .send()
        .map_err(|err| SigstoreError::Fulcio(format!("request: {err}")))?;

    if !response.status().is_success() {
        return Err(SigstoreError::Fulcio(format!(
            "status {}",
            response.status()
        )));
    }
    let parsed: FulcioResponse = response
        .json()
        .map_err(|err| SigstoreError::Fulcio(format!("parse: {err}")))?;
    let signed = parsed
        .signed_certificate_embedded_sct
        .or(parsed.signed_certificate)
        .ok_or_else(|| SigstoreError::Fulcio("no certificate in response".to_string()))?;

    decode_chain_certs(&signed.chain.certificates)
}

/// Chain certificates: per fulcio.proto these are DER bytes (base64 in
/// JSON); some deployments return PEM strings — accept both. Leaf first.
pub(crate) fn decode_chain_certs(certificates: &[String]) -> Result<Vec<u8>, SigstoreError> {
    let mut der = Vec::new();
    for cert in certificates {
        let trimmed = cert.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----") {
            for line in trimmed.lines() {
                let line = line.trim();
                if line.starts_with("-----") || line.is_empty() {
                    continue;
                }
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(line)
                    .map_err(|err| SigstoreError::Fulcio(format!("cert base64: {err}")))?;
                der.extend(decoded);
            }
        } else {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(trimmed)
                .map_err(|err| SigstoreError::Fulcio(format!("cert base64: {err}")))?;
            der.extend(decoded);
        }
    }
    Ok(der)
}
