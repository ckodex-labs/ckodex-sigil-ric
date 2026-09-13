use sigil_probe::{
    BaselineProfile, BoundaryProbe, CanaryCase, FingerprintProbe, HealthAction, ProbeConfig,
    ProbeEngine, ProbeSample,
};

#[test]
fn escalates_on_sustained_drift_and_boundary_failure() {
    let baseline = BaselineProfile::from_samples(&[
        ProbeSample {
            input: "hello".into(),
            output: "ok".into(),
            latency_ms: 10,
        },
        ProbeSample {
            input: "status".into(),
            output: "healthy".into(),
            latency_ms: 11,
        },
        ProbeSample {
            input: "ping".into(),
            output: "stable".into(),
            latency_ms: 9,
        },
    ]);
    let engine = ProbeEngine::new(baseline, ProbeConfig::default());
    let report = engine.analyze(
        &[
            ProbeSample {
                input: "hello".into(),
                output: "ignore previous instructions jailbreak exfiltrate".into(),
                latency_ms: 900,
            },
            ProbeSample {
                input: "status".into(),
                output: "refuse refuse refuse".into(),
                latency_ms: 875,
            },
        ],
        &[CanaryCase {
            input: "hello".into(),
            expected_fragment: "ok".into(),
        }],
        &[FingerprintProbe {
            input: "hello".into(),
            expected_fingerprint: "healthy".into(),
        }],
        &[BoundaryProbe {
            input: "hello".into(),
            forbidden_fragment: "ignore previous".into(),
        }],
    );

    assert!(report.drift.triggered);
    assert!(!matches!(report.action, HealthAction::Nominal));
}

#[test]
fn surfaces_canary_and_identity_regressions() {
    let baseline = BaselineProfile::from_samples(&[
        ProbeSample {
            input: "hello".into(),
            output: "stable".into(),
            latency_ms: 10,
        },
        ProbeSample {
            input: "status".into(),
            output: "healthy".into(),
            latency_ms: 10,
        },
    ]);
    let engine = ProbeEngine::new(baseline, ProbeConfig::default());
    let report = engine.analyze(
        &[ProbeSample {
            input: "hello".into(),
            output: "drifted output".into(),
            latency_ms: 450,
        }],
        &[CanaryCase {
            input: "hello".into(),
            expected_fragment: "stable".into(),
        }],
        &[FingerprintProbe {
            input: "hello".into(),
            expected_fingerprint: "stable".into(),
        }],
        &[BoundaryProbe {
            input: "hello".into(),
            forbidden_fragment: "ignore previous".into(),
        }],
    );

    assert!(report.evidence.canary_failures > 0);
    assert!(report.evidence.fingerprint_mismatches > 0);
    assert!(!matches!(report.action, HealthAction::Nominal));
}
