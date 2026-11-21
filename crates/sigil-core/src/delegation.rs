//! Agent-to-Agent (A2A) recursive delegation leases (RIC v0.2).
//!
//! Provides cryptographically bound, monotonically attenuated capability leases
//! and wire envelopes across autonomous agent execution boundaries.

pub mod types;
pub mod validator;

#[cfg(test)]
mod tests;

pub use types::{
    is_attenuated, AgentEnvelope, AuthorityCeiling, Capability, CapabilityLease, DelegationError,
    DelegationRequest, RevocationRegistry, RootLeaseParams,
};
pub use validator::{
    create_root_lease, delegate, validate_chain, validate_envelope, validate_lease,
};
