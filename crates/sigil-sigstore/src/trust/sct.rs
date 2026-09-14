//! RFC 6962 v1 embedded-SCT verification for Fulcio leaf certificates.
//!
//! Fulcio issues certificates via precertificates: the leaf carries an
//! embedded SignedCertificateTimestampList (OID 1.3.6.1.4.1.11129.2.4.2).
//! The SCT binds the certificate to a Certificate Transparency log that
//! observed the precertificate — a certificate chaining to the Fulcio root
//! that was never CT-logged must be rejected.
//!
//! Upstream status: `sigstore-rs` performs SCT verification inside its
//! cosign `verify` feature; `sigstore-types`/`sigstore-crypto` (already in
//! this tree via `sigstore-trust-root`) expose no standalone SCT helper,
//! so the RFC 6962 plumbing lives here. The CT keys themselves come from
//! `sigstore-trust-root` (`TrustedRoot::ctfe_keys_with_ids`), not from a
//! hand-maintained key set.

use crate::trust::types::{TrustError, TrustRoot};
use der::asn1::OctetString;
use der::{Decode as _, Encode as _};
use p256::ecdsa::{
    signature::Verifier as _, Signature as P256Signature, VerifyingKey as P256VerifyingKey,
};
use sha2::{Digest as _, Sha256};
use x509_cert::certificate::Certificate;
use x509_cert::spki::SubjectPublicKeyInfoOwned;

/// OID 1.3.6.1.4.1.11129.2.4.2 — embedded SCT list extension (RFC 6962 §3.3).
const SCT_LIST_OID: const_oid::ObjectIdentifier =
    const_oid::ObjectIdentifier::new_unwrap("1.3.6.1.4.1.11129.2.4.2");

/// A parsed RFC 6962 v1 SCT.
struct Sct {
    log_id: [u8; 32],
    timestamp_ms: u64,
    extensions: Vec<u8>,
    signature_der: Vec<u8>,
}

fn sct_err(msg: impl Into<String>) -> TrustError {
    TrustError::SctFailed(msg.into())
}

/// Parse the SCT list extension: extn_value is a DER OCTET STRING wrapping
/// a SerializedSCTList (`u16 total_len || [u16 entry_len || SCT]*`).
fn parse_sct_list(ext: &x509_cert::ext::Extension) -> Result<Vec<Sct>, TrustError> {
    let inner = OctetString::from_der(ext.extn_value.as_bytes()).map_err(|e| {
        sct_err(format!(
            "SCT list extn_value is not a DER OCTET STRING: {e}"
        ))
    })?;
    let list = inner.as_bytes();
    if list.len() < 2 {
        return Err(sct_err("SCT list truncated"));
    }
    let declared = u16::from_be_bytes([list[0], list[1]]) as usize;
    if declared != list.len() - 2 {
        return Err(sct_err("SCT list length mismatch"));
    }
    let mut scts = Vec::new();
    let mut pos = 2;
    while pos < list.len() {
        if pos + 2 > list.len() {
            return Err(sct_err("SCT entry length field truncated"));
        }
        let entry_len = u16::from_be_bytes([list[pos], list[pos + 1]]) as usize;
        pos += 2;
        let end = pos
            .checked_add(entry_len)
            .filter(|end| *end <= list.len())
            .ok_or_else(|| sct_err("SCT entry overruns list"))?;
        scts.push(parse_sct(&list[pos..end])?);
        pos = end;
    }
    Ok(scts)
}

/// Parse one SCT (RFC 6962 v1 wire format):
/// `version(1) || log_id(32) || timestamp_ms(8) || ext_len(2) || exts ||
///  hash_alg(1) || sig_alg(1) || sig_len(2) || signature`.
fn parse_sct(bytes: &[u8]) -> Result<Sct, TrustError> {
    const MIN_LEN: usize = 1 + 32 + 8 + 2 + 4;
    if bytes.len() < MIN_LEN {
        return Err(sct_err("SCT truncated"));
    }
    if bytes[0] != 0 {
        return Err(sct_err("unsupported SCT version (only v1)"));
    }
    let log_id: [u8; 32] = bytes[1..33]
        .try_into()
        .map_err(|_| sct_err("log_id slice length"))?;
    let timestamp_ms = u64::from_be_bytes(
        bytes[33..41]
            .try_into()
            .map_err(|_| sct_err("timestamp slice length"))?,
    );
    let ext_len = u16::from_be_bytes([bytes[41], bytes[42]]) as usize;
    let ds = 43usize
        .checked_add(ext_len)
        .filter(|d| *d + 4 <= bytes.len())
        .ok_or_else(|| sct_err("SCT extensions overrun entry"))?;
    let extensions = bytes[43..ds].to_vec();
    // DigitallySigned: hash_alg must be 4 (SHA-256), sig_alg 3 (ECDSA) —
    // the only pairing Sigstore CT logs issue.
    if bytes[ds] != 4 {
        return Err(sct_err("SCT hash algorithm is not SHA-256"));
    }
    if bytes[ds + 1] != 3 {
        return Err(sct_err("SCT signature algorithm is not ECDSA"));
    }
    let sig_len = u16::from_be_bytes([bytes[ds + 2], bytes[ds + 3]]) as usize;
    if ds + 4 + sig_len != bytes.len() {
        return Err(sct_err("SCT signature length mismatch"));
    }
    Ok(Sct {
        log_id,
        timestamp_ms,
        extensions,
        signature_der: bytes[ds + 4..].to_vec(),
    })
}

/// DER-encode the leaf's TBS with the SCT extension removed — the
/// precertificate the CT log actually signed (RFC 6962 §3.5).
fn precert_tbs_der(leaf: &Certificate) -> Result<Vec<u8>, TrustError> {
    let mut tbs = leaf.tbs_certificate.clone();
    if let Some(exts) = tbs.extensions.take() {
        let kept: Vec<_> = exts
            .into_iter()
            .filter(|e| e.extn_id != SCT_LIST_OID)
            .collect();
        tbs.extensions = if kept.is_empty() { None } else { Some(kept) };
    }
    tbs.to_der()
        .map_err(|e| sct_err(format!("precert TBS encode: {e}")))
}

/// RFC 6962 §3.5 digitally-signed input for a precertificate entry:
/// `version || signature_type || timestamp || entry_type ||
///  issuer_key_hash || tbs_precert || extensions_len || extensions`.
fn sct_signature_input(sct: &Sct, issuer_spki_der: &[u8], precert_tbs: &[u8]) -> Vec<u8> {
    let mut input =
        Vec::with_capacity(1 + 1 + 8 + 2 + 32 + precert_tbs.len() + 2 + sct.extensions.len());
    input.push(0u8); // Version::v1
    input.push(0u8); // SignatureType::certificate_timestamp
    input.extend_from_slice(&sct.timestamp_ms.to_be_bytes());
    input.extend_from_slice(&[0x04, 0x01]); // LogEntryType::precert_entry
    input.extend_from_slice(&Sha256::digest(issuer_spki_der));
    input.extend_from_slice(precert_tbs);
    input.extend_from_slice(&(sct.extensions.len() as u16).to_be_bytes());
    input.extend_from_slice(&sct.extensions);
    input
}

/// Verify the leaf certificate's embedded SCTs against the CT log keys in
/// `trust`. Required semantics: when the trust root provisions CT log keys
/// (`ctfe_keys` non-empty), the leaf MUST carry an embedded SCT list and at
/// least one entry MUST verify against a trusted log. An empty `ctfe_keys`
/// means CT is not provisioned for this root (synthetic fixtures only) and
/// the check is skipped — the embedded production root always carries keys.
pub(crate) fn verify_embedded_scts(
    leaf: &Certificate,
    issuer: &Certificate,
    trust: &TrustRoot,
) -> Result<(), TrustError> {
    if trust.ctfe_keys.is_empty() {
        return Ok(());
    }
    let exts = leaf
        .tbs_certificate
        .extensions
        .as_ref()
        .ok_or(TrustError::MissingSct)?;
    let sct_ext = exts
        .iter()
        .find(|e| e.extn_id == SCT_LIST_OID)
        .ok_or(TrustError::MissingSct)?;
    let scts = parse_sct_list(sct_ext)?;
    if scts.is_empty() {
        return Err(TrustError::MissingSct);
    }
    let issuer_spki_der = issuer
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .map_err(|e| sct_err(format!("issuer SPKI encode: {e}")))?;
    let precert = precert_tbs_der(leaf)?;
    // Sanity: the SCT timestamp should sit inside the certificate's
    // validity window, allowing for precert logging before issuance.
    let not_before =
        crate::trust::chain::extract_unix_time(&leaf.tbs_certificate.validity.not_before)?;
    let not_after =
        crate::trust::chain::extract_unix_time(&leaf.tbs_certificate.validity.not_after)?;
    for sct in &scts {
        let ts_secs = (sct.timestamp_ms / 1000) as i64;
        if ts_secs < not_before - 3600 || ts_secs > not_after {
            return Err(sct_err("SCT timestamp outside certificate validity window"));
        }
    }
    let mut verified = false;
    for sct in &scts {
        let Some((_, key_der)) = trust
            .ctfe_keys
            .iter()
            .find(|(id, _)| id.as_slice() == sct.log_id)
        else {
            continue;
        };
        let spki = SubjectPublicKeyInfoOwned::from_der(key_der)
            .map_err(|e| sct_err(format!("CT key SPKI parse: {e}")))?;
        let point = spki
            .subject_public_key
            .as_bytes()
            .ok_or_else(|| sct_err("CT key not octet-aligned"))?;
        let vk = P256VerifyingKey::from_sec1_bytes(point)
            .map_err(|e| sct_err(format!("CT key parse: {e}")))?;
        let sig = P256Signature::from_der(&sct.signature_der)
            .map_err(|_| sct_err("SCT signature is not DER"))?;
        let input = sct_signature_input(sct, &issuer_spki_der, &precert);
        if vk.verify(&input, &sig).is_ok() {
            verified = true;
        }
    }
    if verified {
        Ok(())
    } else {
        Err(sct_err(
            "no embedded SCT verifies against a trusted CT log key",
        ))
    }
}
