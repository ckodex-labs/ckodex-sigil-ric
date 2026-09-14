//! Sigstore keyless signing for RIC receipts (DEV-3, "both" decision).
//!
//! Implements the `ReceiptSigner` port with a Sigstore keyless identity:
//! an ambient OIDC token (CI workload identity, e.g. `SIGSTORE_ID_TOKEN`)
//! is exchanged at **Fulcio** for a short-lived P-384 signing certificate;
//! receipts are signed with the ephemeral key; the signature is optionally
//! uploaded to **Rekor** as a `hashedrekord` entry.
//!
//! Verification of a keyless receipt requires the Fulcio certificate chain
//! (exposed via `ReceiptSigner::certificate_chain`) plus the Rekor inclusion
//! proof — the offline-verification path is specified in
//! docs/PERCEPTION-ADAPTERS.md §5 and is a planned increment.
//!
//! Decision points realized here (docs/PERCEPTION-ADAPTERS.md §5):
//! - Credential source: **ambient OIDC** (`SIGSTORE_ID_TOKEN`) or explicit token
//! - Trust root: Fulcio production endpoints by default, overridable for
//!   staging/air-gapped mirrors
//! - Rekor: upload is opt-in (`upload_to_rekor`), so signing works in
//!   network-restricted environments with the transparency step explicit

pub mod trust;
pub mod tuf;

mod bundle_convert;
mod bundle_ops;
mod bundle_types;
mod csr;
mod error;
mod rekor_upload;
mod signer;

pub use bundle_convert::parse_upstream_bundle;
pub use bundle_ops::{build_bundle, verify_bundle};
pub use bundle_types::{
    BundleCertificate, BundleMessageDigest, BundleMessageSignature, BundleVerificationMaterial,
    BundleX509Chain, SigstoreBundle, BUNDLE_MEDIA_TYPE,
};
pub use error::{OidcSource, SigstoreError, FULCIO_URL, REKOR_URL};
pub use rekor_upload::upload_to_rekor;
pub use signer::{RekorEntry, SigstoreKeylessSigner};

#[cfg(test)]
mod bundle_tests;
#[cfg(test)]
mod tests_lib;
