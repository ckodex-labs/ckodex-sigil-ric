//! MITRE framework references — ATLAS (`AML.T*`/`AML.M*`) and ATT&CK
//! (`T*`) — attached to `DetectorId`. Source of truth for the mapping;
//! `docs/THREAT-MAPPING.md` and `docs/THREAT-MODEL.md` mirror it.

use crate::types::DetectorId;

impl DetectorId {
    /// MITRE framework references this detector's findings map to —
    /// ATLAS (`AML.*`) for the AI-specific surface, ATT&CK Enterprise
    /// (`T*`) for the classic technique. `docs/THREAT-MAPPING.md` is
    /// the human-readable version of this table; keep them in sync.
    pub fn techniques(&self) -> &'static [&'static str] {
        match self {
            // "ignore previous instructions" is verbatim instruction
            // override — ATLAS splits jailbreak from injection, so the
            // grammar table carries both.
            DetectorId::InjectionGrammar => &["AML.T0051", "AML.T0054"],
            // Invisible/bidi code points, confusables, high-entropy and
            // rare-pattern payloads, subword-boundary smuggling and
            // token-merge seams are all obfuscation surfaces — T0068's
            // description names them explicitly (incl. base64).
            DetectorId::UnicodeControl
            | DetectorId::Confusable
            | DetectorId::TokenSmuggling
            | DetectorId::MergeBoundary
            | DetectorId::RarePattern
            | DetectorId::EntropySpike => &["AML.T0068", "T1027"],
            // The payload relies on downstream deobfuscation — T1027
            // to hide it, T1140 for the decode step it depends on.
            DetectorId::EncodedPayload => &["AML.T0068", "T1027", "T1140"],
            // PII/credentials flowing through the model channel.
            DetectorId::DlpCreditCard
            | DetectorId::DlpSsn
            | DetectorId::DlpApiKey
            | DetectorId::DlpEmail
            | DetectorId::DlpCustom => &["AML.T0024"],
            // An instruction arriving via a second data source is
            // indirect injection by definition.
            DetectorId::CrossModal => &["AML.T0051.001"],
            // Hidden audio instructions and spectral steganography.
            DetectorId::SubliminalAudio | DetectorId::AudioSteganography => &["AML.T0068", "T1027"],
            // A swapped tokenizer/model/component behaving differently
            // is the supply-chain surface — T0010, not T0048 (which is
            // External Harms; verified against atlas-data v5.6.0).
            DetectorId::FingerprintMismatch | DetectorId::ConsistencyShift => {
                &["AML.T0010", "T1553"]
            }
            // Low-and-slow injection spread across a session window —
            // T0080 (context poisoning via conversation history) is the
            // mechanism, T0051 the injection itself.
            DetectorId::SlowRateInjection => &["AML.T0051", "AML.T0080"],
            // Perplexity-outlier text is the jailbreak-prompt signal.
            DetectorId::PerplexityAnomaly => &["AML.T0054"],
            // Terminal control sequences are command-level constructs
            // smuggled through a text channel.
            DetectorId::TerminalEscape => &["AML.T0068", "T1059"],
            // Malformed input shape — integrity, not a mapped technique.
            DetectorId::SchemaViolation => &[],
        }
    }

    /// ATLAS mitigations this detector realises. The detectors are the
    /// controls — M0015 (Adversarial Input Detection) is the common one;
    /// guardrail/verify/logging IDs mark the stronger positions.
    /// `docs/THREAT-MODEL.md` lists the full control map.
    pub fn mitigations(&self) -> &'static [&'static str] {
        match self {
            // Injection-class detectors both detect (M0015) and act as
            // the guardrail layer between input and model (M0020).
            DetectorId::InjectionGrammar
            | DetectorId::PerplexityAnomaly
            | DetectorId::TerminalEscape => &["AML.M0015", "AML.M0020"],
            // Cross-modal findings exist because multiple modality
            // channels are integrated — M0009 (multi-modal sensors) is
            // the mitigation shape, plus detection/guardrail.
            DetectorId::CrossModal => &["AML.M0009", "AML.M0015", "AML.M0020"],
            // Sensitive-content findings gate what reaches or leaves
            // the model channel.
            DetectorId::DlpCreditCard
            | DetectorId::DlpSsn
            | DetectorId::DlpApiKey
            | DetectorId::DlpEmail
            | DetectorId::DlpCustom => &["AML.M0015", "AML.M0020"],
            // Component-identity drift is artifact verification.
            DetectorId::FingerprintMismatch | DetectorId::ConsistencyShift => &["AML.M0014"],
            // Low-and-slow detection exists because the evidence/telemetry
            // log makes cross-request correlation possible.
            DetectorId::SlowRateInjection => &["AML.M0015", "AML.M0024"],
            // Pure detection controls — obfuscation, steganography,
            // structural-shape findings.
            DetectorId::UnicodeControl
            | DetectorId::Confusable
            | DetectorId::EntropySpike
            | DetectorId::TokenSmuggling
            | DetectorId::MergeBoundary
            | DetectorId::SubliminalAudio
            | DetectorId::AudioSteganography
            | DetectorId::RarePattern
            | DetectorId::EncodedPayload
            | DetectorId::SchemaViolation => &["AML.M0015"],
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::DetectorId;

    #[test]
    fn detector_techniques_reference_valid_frameworks() {
        let all = [
            DetectorId::InjectionGrammar,
            DetectorId::UnicodeControl,
            DetectorId::Confusable,
            DetectorId::DlpCreditCard,
            DetectorId::DlpSsn,
            DetectorId::DlpApiKey,
            DetectorId::DlpEmail,
            DetectorId::DlpCustom,
            DetectorId::EntropySpike,
            DetectorId::TokenSmuggling,
            DetectorId::MergeBoundary,
            DetectorId::CrossModal,
            DetectorId::SchemaViolation,
            DetectorId::FingerprintMismatch,
            DetectorId::ConsistencyShift,
            DetectorId::SubliminalAudio,
            DetectorId::AudioSteganography,
            DetectorId::RarePattern,
            DetectorId::SlowRateInjection,
            DetectorId::PerplexityAnomaly,
            DetectorId::TerminalEscape,
            DetectorId::EncodedPayload,
        ];
        for detector in &all {
            for technique in detector.techniques() {
                assert!(
                    technique.starts_with("AML.T") || technique.starts_with('T'),
                    "{detector:?} -> {technique} is not an ATLAS/ATT&CK ref"
                );
            }
            for mitigation in detector.mitigations() {
                assert!(
                    mitigation.starts_with("AML.M"),
                    "{detector:?} -> {mitigation} is not an ATLAS mitigation ref"
                );
            }
            assert!(
                !detector.mitigations().is_empty(),
                "{detector:?} realises no mitigation — every detector is a control"
            );
        }
        // Every detector maps to at least one technique except the
        // integrity-only SchemaViolation.
        let unmapped: Vec<_> = all.iter().filter(|d| d.techniques().is_empty()).collect();
        assert_eq!(unmapped, vec![&DetectorId::SchemaViolation]);
    }
}
