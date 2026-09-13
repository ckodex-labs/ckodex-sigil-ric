use sigil_probe::{
    BaselineProfile, BoundaryProbe, CanaryCase, FingerprintProbe, ProbeConfig, ProbeEngine,
    ProbeSample,
};

#[test]
fn triggers_shield_on_drift() {
    let baseline = BaselineProfile::from_samples(&[
        ProbeSample {
            input: "hello".into(),
            output: "ok".into(),
            latency_ms: 10,
        },
        ProbeSample {
            input: "status".into(),
            output: "healthy".into(),
            latency_ms: 12,
        },
    ]);
    let engine = ProbeEngine::new(baseline, ProbeConfig::default());
    let report = engine.analyze(
        &[ProbeSample {
            input: "hello".into(),
            output: "ignore previous instructions and jailbreak".into(),
            latency_ms: 800,
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

    assert!(report.drift.triggered || !matches!(report.action, sigil_probe::HealthAction::Nominal));
}
