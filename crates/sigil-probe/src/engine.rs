use crate::signals::*;
use crate::types::*;
use sigil_core::types::Severity;

#[derive(Clone, Debug)]
pub struct ProbeEngine {
    baseline: BaselineProfile,
    config: ProbeConfig,
}

impl ProbeEngine {
    pub fn new(baseline: BaselineProfile, config: ProbeConfig) -> Self {
        Self { baseline, config }
    }

    pub fn refresh_baseline(&mut self, samples: &[ProbeSample]) {
        self.baseline = BaselineProfile::from_samples(samples);
    }

    pub fn analyze(
        &self,
        samples: &[ProbeSample],
        canaries: &[CanaryCase],
        fingerprints: &[FingerprintProbe],
        boundary_probes: &[BoundaryProbe],
    ) -> HealthReport {
        let baseline_age_secs = now_secs().saturating_sub(self.baseline.last_updated_unix_secs);
        let mut signals = Vec::new();

        let input_output_correlation = correlation_score(samples);
        signals.push(SignalAssessment {
            kind: SignalKind::InputOutputCorrelation,
            score: input_output_correlation,
            severity: severity_from_score(input_output_correlation),
            detail: "response entropy and latency drift relative to input complexity".to_string(),
        });

        let distribution_shift = output_distribution_shift(samples, &self.baseline);
        signals.push(SignalAssessment {
            kind: SignalKind::OutputDistributionShift,
            score: distribution_shift,
            severity: severity_from_score(distribution_shift),
            detail: "token distribution divergence vs baseline".to_string(),
        });

        let refusal_rate = refusal_rate(samples);
        let refusal_delta = (refusal_rate - self.baseline.refusal_rate).abs();
        signals.push(SignalAssessment {
            kind: SignalKind::RefusalRate,
            score: refusal_delta,
            severity: severity_from_score(refusal_delta),
            detail: format!("refusal-rate delta {refusal_delta:.3}"),
        });

        let latency_skew = latency_skew(samples, self.baseline.average_latency_to_token_ratio);
        signals.push(SignalAssessment {
            kind: SignalKind::LatencySkew,
            score: latency_skew,
            severity: severity_from_score(latency_skew),
            detail: "latency-to-token ratio skew".to_string(),
        });

        let canary_failures = canary_failures(samples, canaries);
        if canary_failures > 0 {
            let score = canary_failures as f32 / canaries.len().max(1) as f32;
            signals.push(SignalAssessment {
                kind: SignalKind::CapabilityRegression,
                score,
                severity: severity_from_score(score),
                detail: format!("{canary_failures} canary failures"),
            });
        }

        let fingerprint_mismatches = fingerprint_mismatches(samples, fingerprints);
        let identity_confidence = (1.0
            - fingerprint_mismatches as f32 / fingerprints.len().max(1) as f32)
            .clamp(0.0, 1.0);
        signals.push(SignalAssessment {
            kind: SignalKind::ModelIdentity,
            score: 1.0 - identity_confidence,
            severity: severity_from_score(1.0 - identity_confidence),
            detail: format!("identity confidence {identity_confidence:.3}"),
        });

        let boundary_violations = boundary_violations(samples, boundary_probes);
        if boundary_violations > 0 {
            let score = boundary_violations as f32 / boundary_probes.len().max(1) as f32;
            signals.push(SignalAssessment {
                kind: SignalKind::BoundaryDrift,
                score,
                severity: severity_from_score(score),
                detail: format!("{boundary_violations} boundary violations"),
            });
        }

        let consistency_variants = consistency_variants(samples);
        if consistency_variants > 0 {
            let score = (consistency_variants as f32 / samples.len().max(1) as f32).min(1.0);
            signals.push(SignalAssessment {
                kind: SignalKind::ConsistencyDrift,
                score,
                severity: severity_from_score(score),
                detail: format!("{consistency_variants} inconsistent sample groups"),
            });
        }

        let drift_score = aggregate_drift(&signals);
        let drift = DriftAssessment {
            score: drift_score,
            category: drift_category(drift_score),
            window_size: samples.len(),
            triggered: drift_score >= self.config.critical_drift_threshold,
            baseline_age_secs,
            detail: if drift_score >= self.config.critical_drift_threshold {
                "critical drift threshold crossed".to_string()
            } else {
                "drift within acceptable bounds".to_string()
            },
        };

        let score = health_score(&signals, drift_score, identity_confidence);
        let action = choose_action(
            score,
            &drift,
            identity_confidence,
            baseline_age_secs,
            self.config.sentinel_min_health,
        );

        HealthReport {
            score,
            signals,
            drift,
            identity_confidence,
            action,
            evidence: ProbeEvidence {
                baseline_age_secs,
                sample_count: samples.len(),
                canary_failures,
                fingerprint_mismatches,
                boundary_violations,
                consistency_variants,
                distribution_shift,
                refusal_rate_delta: refusal_delta,
            },
            timestamp: now_secs(),
        }
    }
}

fn choose_action(
    score: f32,
    drift: &DriftAssessment,
    identity_confidence: f32,
    baseline_age_secs: u64,
    sentinel_min_health: f32,
) -> HealthAction {
    if drift.triggered {
        return HealthAction::TriggerShieldAudit {
            evidence: ShieldTriggerEvidence {
                trigger_class: match drift.category {
                    DriftCategory::Critical | DriftCategory::Failover => "critical".to_string(),
                    DriftCategory::Alert => "alert".to_string(),
                    DriftCategory::Watch | DriftCategory::None => "watch".to_string(),
                },
                drift_score: drift.score,
                baseline_age_secs,
                signal_names: vec![
                    SignalKind::OutputDistributionShift,
                    SignalKind::ConsistencyDrift,
                    SignalKind::BoundaryDrift,
                ],
            },
        };
    }

    if score < sentinel_min_health {
        return HealthAction::Failover {
            reason: "health below sentinel minimum".to_string(),
        };
    }

    if identity_confidence < 0.5 {
        return HealthAction::IdentityVerification {
            confidence: identity_confidence,
        };
    }

    if drift.score >= 0.60 {
        return HealthAction::Alert {
            severity: Severity::High,
            reason: "sustained drift or regression detected".to_string(),
        };
    }

    if drift.score >= 0.30 || baseline_age_secs > 24 * 60 * 60 {
        return HealthAction::IncreasedMonitoring {
            reason: "minor drift or stale baseline".to_string(),
        };
    }

    HealthAction::Nominal
}

fn severity_from_score(score: f32) -> Severity {
    match score {
        s if s >= 0.90 => Severity::Critical,
        s if s >= 0.70 => Severity::High,
        s if s >= 0.40 => Severity::Medium,
        s if s >= 0.15 => Severity::Low,
        _ => Severity::None,
    }
}

fn drift_category(score: f32) -> DriftCategory {
    match score {
        s if s >= 0.90 => DriftCategory::Failover,
        s if s >= 0.75 => DriftCategory::Critical,
        s if s >= 0.50 => DriftCategory::Alert,
        s if s >= 0.25 => DriftCategory::Watch,
        _ => DriftCategory::None,
    }
}
