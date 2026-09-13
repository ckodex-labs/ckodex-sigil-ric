//! SIGIL PROBE.
//!
//! Behavioral model-health monitoring for the Ckodex containment plane.

mod engine;
mod signals;
mod types;

pub use engine::ProbeEngine;
pub use types::{
    BaselineProfile, BoundaryProbe, CanaryCase, DriftAssessment, DriftCategory, FingerprintProbe,
    HealthAction, HealthReport, ProbeConfig, ProbeEvidence, ProbeSample, ShieldTriggerEvidence,
    SignalAssessment, SignalKind,
};

#[cfg(test)]
mod tests;
