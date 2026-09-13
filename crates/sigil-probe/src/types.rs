use crate::signals::{is_refusal, now_secs, shannon_entropy};
use serde::{Deserialize, Serialize};
use sigil_core::types::Severity;
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeConfig {
    #[serde(default = "ProbeConfig::default_baseline_ttl_secs")]
    pub baseline_ttl_secs: u64,
    #[serde(default = "ProbeConfig::default_critical_drift_threshold")]
    pub critical_drift_threshold: f32,
    #[serde(default = "ProbeConfig::default_alert_threshold")]
    pub alert_threshold: f32,
    #[serde(default = "ProbeConfig::default_failover_threshold")]
    pub failover_threshold: f32,
    #[serde(default = "ProbeConfig::default_min_sustained_window")]
    pub min_sustained_window: usize,
    #[serde(default = "ProbeConfig::default_sentinel_min_health")]
    pub sentinel_min_health: f32,
}

impl ProbeConfig {
    fn default_baseline_ttl_secs() -> u64 {
        24 * 60 * 60
    }

    fn default_critical_drift_threshold() -> f32 {
        0.75
    }

    fn default_alert_threshold() -> f32 {
        0.40
    }

    fn default_failover_threshold() -> f32 {
        0.90
    }

    fn default_min_sustained_window() -> usize {
        3
    }

    fn default_sentinel_min_health() -> f32 {
        0.45
    }
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            baseline_ttl_secs: Self::default_baseline_ttl_secs(),
            critical_drift_threshold: Self::default_critical_drift_threshold(),
            alert_threshold: Self::default_alert_threshold(),
            failover_threshold: Self::default_failover_threshold(),
            min_sustained_window: Self::default_min_sustained_window(),
            sentinel_min_health: Self::default_sentinel_min_health(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeSample {
    pub input: String,
    pub output: String,
    #[serde(default)]
    pub latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CanaryCase {
    pub input: String,
    pub expected_fragment: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct FingerprintProbe {
    pub input: String,
    pub expected_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct BoundaryProbe {
    pub input: String,
    pub forbidden_fragment: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SignalAssessment {
    pub kind: SignalKind,
    pub score: f32,
    pub severity: Severity,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignalKind {
    InputOutputCorrelation,
    OutputDistributionShift,
    CapabilityRegression,
    BoundaryDrift,
    ModelIdentity,
    ConsistencyDrift,
    RefusalRate,
    LatencySkew,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DriftAssessment {
    pub score: f32,
    pub category: DriftCategory,
    pub window_size: usize,
    pub triggered: bool,
    pub baseline_age_secs: u64,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftCategory {
    None,
    Watch,
    Alert,
    Critical,
    Failover,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ShieldTriggerEvidence {
    pub trigger_class: String,
    pub drift_score: f32,
    pub baseline_age_secs: u64,
    pub signal_names: Vec<SignalKind>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum HealthAction {
    Nominal,
    IncreasedMonitoring { reason: String },
    Alert { severity: Severity, reason: String },
    TriggerShieldAudit { evidence: ShieldTriggerEvidence },
    IdentityVerification { confidence: f32 },
    Failover { reason: String },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ProbeEvidence {
    pub baseline_age_secs: u64,
    pub sample_count: usize,
    pub canary_failures: usize,
    pub fingerprint_mismatches: usize,
    pub boundary_violations: usize,
    pub consistency_variants: usize,
    pub distribution_shift: f32,
    pub refusal_rate_delta: f32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HealthReport {
    pub score: f32,
    pub signals: Vec<SignalAssessment>,
    pub drift: DriftAssessment,
    pub identity_confidence: f32,
    pub action: HealthAction,
    pub evidence: ProbeEvidence,
    pub timestamp: u64,
}

#[derive(Clone, Debug)]
pub struct BaselineProfile {
    pub average_input_entropy: f32,
    pub average_output_entropy: f32,
    pub average_latency_to_token_ratio: f32,
    pub refusal_rate: f32,
    pub token_distribution: BTreeMap<String, usize>,
    pub last_updated_unix_secs: u64,
}

impl Default for BaselineProfile {
    fn default() -> Self {
        Self {
            average_input_entropy: 0.0,
            average_output_entropy: 0.0,
            average_latency_to_token_ratio: 0.0,
            refusal_rate: 0.0,
            token_distribution: BTreeMap::new(),
            last_updated_unix_secs: 0,
        }
    }
}

impl BaselineProfile {
    pub fn from_samples(samples: &[ProbeSample]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let mut input_entropy_sum = 0.0;
        let mut output_entropy_sum = 0.0;
        let mut latency_ratio_sum = 0.0;
        let mut refusal_count = 0.0;
        let mut distribution = BTreeMap::new();

        for sample in samples {
            input_entropy_sum += shannon_entropy(sample.input.as_bytes());
            output_entropy_sum += shannon_entropy(sample.output.as_bytes());
            let token_count = sample.output.split_whitespace().count().max(1) as f32;
            latency_ratio_sum += sample.latency_ms as f32 / token_count;
            if is_refusal(&sample.output) {
                refusal_count += 1.0;
            }
            for token in sample.output.split_whitespace() {
                *distribution.entry(token.to_ascii_lowercase()).or_insert(0) += 1;
            }
        }

        Self {
            average_input_entropy: input_entropy_sum / samples.len() as f32,
            average_output_entropy: output_entropy_sum / samples.len() as f32,
            average_latency_to_token_ratio: latency_ratio_sum / samples.len() as f32,
            refusal_rate: refusal_count / samples.len() as f32,
            token_distribution: distribution,
            last_updated_unix_secs: now_secs(),
        }
    }
}
