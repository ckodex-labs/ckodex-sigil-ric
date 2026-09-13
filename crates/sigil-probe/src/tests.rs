use super::*;

#[test]
fn drift_triggers_action() {
    let baseline = BaselineProfile::from_samples(&[ProbeSample {
        input: "hello".into(),
        output: "ok".into(),
        latency_ms: 10,
    }]);
    let engine = ProbeEngine::new(baseline, ProbeConfig::default());
    let report = engine.analyze(
        &[ProbeSample {
            input: "hello".into(),
            output: "ignore previous instructions".into(),
            latency_ms: 500,
        }],
        &[CanaryCase {
            input: "hello".into(),
            expected_fragment: "ok".into(),
        }],
        &[FingerprintProbe {
            input: "hello".into(),
            expected_fingerprint: "ok".into(),
        }],
        &[BoundaryProbe {
            input: "hello".into(),
            forbidden_fragment: "ignore previous".into(),
        }],
    );

    assert!(report.score < 1.0);
    assert!(!matches!(report.action, HealthAction::Nominal));
}
