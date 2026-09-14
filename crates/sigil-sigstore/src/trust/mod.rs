mod chain;
mod fetch;
mod rekor;
mod sct;
mod types;
mod verify;

pub use fetch::fetch_trust_bundle;
pub use types::{InclusionProof, RekorEntry, TrustError, TrustRoot};
pub use verify::{verify_bundle_with_trust, verify_upstream_bundle};

#[cfg(test)]
pub(crate) mod e2e_tests;
#[cfg(test)]
mod interop_tests;
#[cfg(test)]
mod tests;
