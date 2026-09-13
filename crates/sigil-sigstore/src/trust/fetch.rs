use crate::trust::types::TrustError;
use crate::SigstoreError;
use base64::Engine as _;
use serde::Deserialize;
use x509_cert::certificate::Certificate;
pub(crate) fn parse_cert(der: &[u8]) -> Result<Certificate, TrustError> {
    use der::Decode;
    Certificate::from_der(der).map_err(|e| TrustError::CertParse(format!("{e}")))
}
/// Fetch the Fulcio trust bundle (root + intermediate PEMs) from
/// `GET /api/v2/trustBundle`. Returns DER-encoded certificates.
pub fn fetch_trust_bundle(fulcio_url: &str) -> Result<Vec<Vec<u8>>, SigstoreError> {
    #[derive(Deserialize)]
    struct TrustBundleResponse {
        chains: Vec<TrustChain>,
    }
    #[derive(Deserialize)]
    struct TrustChain {
        certificates: Vec<String>,
    }
    let client = reqwest::blocking::Client::builder()
        .build()
        .map_err(|e| SigstoreError::Fulcio(format!("client: {e}")))?;
    let response = client
        .get(format!("{fulcio_url}/api/v2/trustBundle"))
        .send()
        .map_err(|e| SigstoreError::Fulcio(format!("request: {e}")))?;
    if !response.status().is_success() {
        return Err(SigstoreError::Fulcio(format!(
            "status {}",
            response.status()
        )));
    }
    let parsed: TrustBundleResponse = response
        .json()
        .map_err(|e| SigstoreError::Fulcio(format!("parse: {e}")))?;
    let mut der_certs = Vec::new();
    for chain in &parsed.chains {
        for pem in &chain.certificates {
            // Strip PEM framing and decode base64.
            for line in pem.lines() {
                let line = line.trim();
                if line.starts_with("-----") || line.is_empty() {
                    continue;
                }
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(line)
                    .map_err(|e| SigstoreError::Fulcio(format!("cert base64: {e}")))?;
                der_certs.push(decoded);
            }
        }
    }
    if der_certs.is_empty() {
        return Err(SigstoreError::Fulcio("empty trust bundle".to_string()));
    }
    Ok(der_certs)
}
