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
        let core = self.core_signals(samples);
        let canary = canary_check(samples, canaries);
        let identity = identity_check(samples, fingerprints);
        let boundary = boundary_check(samples, boundary_probes);
        let consistency = consistency_check(samples);

        let mut signals = core.signals;
        signals.extend(canary.signal);
        signals.push(identity.signal);
        signals.extend(boundary.signal);
        signals.extend(consistency.signal);

        let drift = self.assess_drift(&signals, samples.len(), baseline_age_secs);
        let score = health_score(&signals, drift.score, identity.confidence);
        let action = choose_action(
            score,
            &drift,
            identity.confidence,
            baseline_age_secs,
            self.config.sentinel_min_health,
        );

        HealthReport {
            score,
            signals,
            drift,
            identity_confidence: identity.confidence,
            action,
            evidence: ProbeEvidence {
                baseline_age_secs,
                sample_count: samples.len(),
                canary_failures: canary.count,
                fingerprint_mismatches: identity.mismatches,
                boundary_violations: boundary.count,
                consistency_variants: consistency.count,
                distribution_shift: core.distribution_shift,
                refusal_rate_delta: core.refusal_delta,
            },
            timestamp: now_secs(),
        }
    }

    /// The four signals that are always reported, plus the two raw values
    /// the evidence block repeats.
    fn core_signals(&self, samples: &[ProbeSample]) -> CoreSignals {
        let input_output_correlation = correlation_score(samples);
        let distribution_shift = output_distribution_shift(samples, &self.baseline);
        let refusal_delta = (refusal_rate(samples) - self.baseline.refusal_rate).abs();
        let latency_skew = latency_skew(samples, self.baseline.average_latency_to_token_ratio);
        let signals = vec![
            assessment(
                SignalKind::InputOutputCorrelation,
                input_output_correlation,
                "response entropy and latency drift relative to input complexity".to_string(),
            ),
            assessment(
                SignalKind::OutputDistributionShift,
                distribution_shift,
                "token distribution divergence vs baseline".to_string(),
            ),
            assessment(
                SignalKind::RefusalRate,
                refusal_delta,
                format!("refusal-rate delta {refusal_delta:.3}"),
            ),
            assessment(
                SignalKind::LatencySkew,
                latency_skew,
                "latency-to-token ratio skew".to_string(),
            ),
        ];
        CoreSignals {
            signals,
            distribution_shift,
            refusal_delta,
        }
    }

    fn assess_drift(
        &self,
        signals: &[SignalAssessment],
        window_size: usize,
        baseline_age_secs: u64,
    ) -> DriftAssessment {
        let drift_score = aggregate_drift(signals);
        let triggered = drift_score >= self.config.critical_drift_threshold;
        DriftAssessment {
            score: drift_score,
            category: drift_category(drift_score),
            window_size,
            triggered,
            baseline_age_secs,
            detail: if triggered {
                "critical drift threshold crossed".to_string()
            } else {
                "drift within acceptable bounds".to_string()
            },
        }
    }
}

struct CoreSignals {
    signals: Vec<SignalAssessment>,
    distribution_shift: f32,
    refusal_delta: f32,
}

/// A counted check that only reports a signal when something was found.
struct CountedCheck {
    count: usize,
    signal: Option<SignalAssessment>,
}

struct IdentityCheck {
    mismatches: usize,
    confidence: f32,
    signal: SignalAssessment,
}

fn assessment(kind: SignalKind, score: f32, detail: String) -> SignalAssessment {
    SignalAssessment {
        kind,
        score,
        severity: severity_from_score(score),
        detail,
    }
}

fn canary_check(samples: &[ProbeSample], canaries: &[CanaryCase]) -> CountedCheck {
    let count = canary_failures(samples, canaries);
    let signal = (count > 0).then(|| {
        let score = count as f32 / canaries.len().max(1) as f32;
        assessment(
            SignalKind::CapabilityRegression,
            score,
            format!("{count} canary failures"),
        )
    });
    CountedCheck { count, signal }
}

fn identity_check(samples: &[ProbeSample], fingerprints: &[FingerprintProbe]) -> IdentityCheck {
    let mismatches = fingerprint_mismatches(samples, fingerprints);
    let confidence = (1.0 - mismatches as f32 / fingerprints.len().max(1) as f32).clamp(0.0, 1.0);
    let signal = assessment(
        SignalKind::ModelIdentity,
        1.0 - confidence,
        format!("identity confidence {confidence:.3}"),
    );
    IdentityCheck {
        mismatches,
        confidence,
        signal,
    }
}

fn boundary_check(samples: &[ProbeSample], probes: &[BoundaryProbe]) -> CountedCheck {
    let count = boundary_violations(samples, probes);
    let signal = (count > 0).then(|| {
        let score = count as f32 / probes.len().max(1) as f32;
        assessment(
            SignalKind::BoundaryDrift,
            score,
            format!("{count} boundary violations"),
        )
    });
    CountedCheck { count, signal }
}

fn consistency_check(samples: &[ProbeSample]) -> CountedCheck {
    let count = consistency_variants(samples);
    let signal = (count > 0).then(|| {
        let score = (count as f32 / samples.len().max(1) as f32).min(1.0);
        assessment(
            SignalKind::ConsistencyDrift,
            score,
            format!("{count} inconsistent sample groups"),
        )
    });
    CountedCheck { count, signal }
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
