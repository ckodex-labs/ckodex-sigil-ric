use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SigstoreBundle {
    #[serde(rename = "mediaType")]
    pub media_type: String,
    #[serde(rename = "verificationMaterial")]
    pub verification_material: BundleVerificationMaterial,
    #[serde(rename = "messageSignature")]
    pub message_signature: BundleMessageSignature,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleVerificationMaterial {
    #[serde(rename = "x509CertificateChain")]
    pub x509_certificate_chain: BundleX509Chain,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleX509Chain {
    /// DER-encoded certificates, leaf first (base64 in JSON).
    pub certificates: Vec<BundleCertificate>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleCertificate {
    #[serde(rename = "rawBytes")]
    pub raw_bytes: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleMessageSignature {
    #[serde(rename = "messageDigest")]
    pub message_digest: BundleMessageDigest,
    /// Base64-encoded signature over the message.
    pub signature: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BundleMessageDigest {
    /// Protobuf-specs HashAlgorithm enum label ("SHA2_384").
    pub algorithm: String,
    /// Base64-encoded digest.
    pub digest: String,
}

pub const BUNDLE_MEDIA_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
