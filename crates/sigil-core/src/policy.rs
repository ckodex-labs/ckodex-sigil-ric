use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::{fs, path::Path, str::FromStr};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Monitor,
    Enforce,
    Strict,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Normalization {
    #[default]
    Nfc,
    Nfkc,
    None,
}

impl std::fmt::Display for Normalization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Normalization::Nfc => "nfc",
            Normalization::Nfkc => "nfkc",
            Normalization::None => "none",
        })
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HomoglyphAction {
    Normalize,
    #[default]
    Flag,
    Deny,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum InvisibleCharPolicy {
    Strip,
    #[default]
    Flag,
    Deny,
    Allow,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaintPolicy {
    #[default]
    Accumulate,
    Reset,
    Inherit,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EmailAction {
    #[default]
    Flag,
    Deny,
    Redact,
    Off,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EvidenceFormat {
    #[default]
    Json,
    Cbor,
    Protobuf,
}

/// Evidence emission policy. `NonAllow` (the default) preserves the
/// lazy-evidence invariant INV-006: bundles exist for Flag/Deny only.
/// `Always` trades that performance property for always-on attestation —
/// every admission, including clean ones, produces an evidence bundle
/// bound to the receipt (docs/RIC-CONTRACT.md DEV-1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceMode {
    #[default]
    NonAllow,
    Always,
}

#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct Policy {
    #[serde(default)]
    pub sigil: SigilSection,
    #[serde(default)]
    pub intake: IntakePolicy,
    #[serde(default)]
    pub taint: TaintSection,
    #[serde(default)]
    pub scan: ScanPolicy,
    #[serde(default)]
    pub merge: MergePolicy,
    #[serde(default)]
    pub emit: EmitPolicy,
}

impl Policy {
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let contents = fs::read_to_string(path)?;
        Self::from_toml_str(&contents)
    }

    pub fn from_toml_str(contents: &str) -> Result<Self> {
        Ok(toml::from_str(contents)?)
    }
}

impl FromStr for Policy {
    type Err = crate::error::SigilError;

    fn from_str(contents: &str) -> Result<Self> {
        Self::from_toml_str(contents)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SigilSection {
    #[serde(default = "SigilSection::default_version")]
    pub version: String,
    #[serde(default)]
    pub mode: Mode,
}

impl SigilSection {
    fn default_version() -> String {
        "0.3.0".to_string()
    }
}

impl Default for SigilSection {
    fn default() -> Self {
        Self {
            version: Self::default_version(),
            mode: Mode::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct IntakePolicy {
    #[serde(default)]
    pub normalization: Normalization,
    #[serde(default)]
    pub homoglyph_action: HomoglyphAction,
    #[serde(default)]
    pub invisible_chars: InvisibleCharPolicy,
    #[serde(default = "IntakePolicy::default_max_input_bytes")]
    pub max_input_bytes: usize,
}

impl IntakePolicy {
    fn default_max_input_bytes() -> usize {
        1_048_576
    }
}

impl Default for IntakePolicy {
    fn default() -> Self {
        Self {
            normalization: Normalization::default(),
            homoglyph_action: HomoglyphAction::default(),
            invisible_chars: InvisibleCharPolicy::default(),
            max_input_bytes: Self::default_max_input_bytes(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaintSection {
    #[serde(default = "TaintSection::default_require_provenance")]
    pub require_provenance: bool,
    #[serde(default = "TaintSection::default_unknown_trust")]
    pub unknown_trust: String,
}

impl TaintSection {
    fn default_require_provenance() -> bool {
        true
    }

    fn default_unknown_trust() -> String {
        "untrusted".to_string()
    }
}

impl Default for TaintSection {
    fn default() -> Self {
        Self {
            require_provenance: Self::default_require_provenance(),
            unknown_trust: Self::default_unknown_trust(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DlpPolicy {
    #[serde(default = "DlpPolicy::default_true")]
    pub credit_cards: bool,
    #[serde(default = "DlpPolicy::default_true")]
    pub ssn: bool,
    #[serde(default = "DlpPolicy::default_true")]
    pub api_keys: bool,
    #[serde(default)]
    pub emails: EmailAction,
    #[serde(default)]
    pub custom_patterns: Vec<String>,
}

impl DlpPolicy {
    fn default_true() -> bool {
        true
    }
}

impl Default for DlpPolicy {
    fn default() -> Self {
        Self {
            credit_cards: true,
            ssn: true,
            api_keys: true,
            emails: EmailAction::default(),
            custom_patterns: Vec::new(),
        }
    }
}

/// Multiscale perplexity-anomaly detection (D2). Opt-in: disabled by
/// default because statistical surprisal on short inputs is noisy — the
/// operator chooses to pay the compute/noise cost. When `enabled` and no
/// external scorer is injected, the kernel uses `SelfSurprisalScorer`
/// (deterministic order-k char n-gram, offline).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PerplexityPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// Window sizes in scored units (characters for the built-in scorer).
    #[serde(default = "PerplexityPolicy::default_windows")]
    pub window_sizes: Vec<usize>,
    /// Robust z-score threshold (median/MAD) for flagging a window.
    #[serde(default = "PerplexityPolicy::default_z")]
    pub z_threshold: f32,
    /// Distinct scales a flag cluster must span to emit a finding.
    #[serde(default = "PerplexityPolicy::default_min_scales")]
    pub min_scales: usize,
    /// Below this many scored units the detector reports `Skipped` —
    /// statistics are meaningless.
    #[serde(default = "PerplexityPolicy::default_min_units")]
    pub min_units: usize,
    /// Total windows analyzed across all scales — the cost bound.
    #[serde(default = "PerplexityPolicy::default_max_windows")]
    pub max_windows: usize,
    /// N-gram context order for the built-in scorer.
    #[serde(default = "PerplexityPolicy::default_order")]
    pub model_order: usize,
}

impl PerplexityPolicy {
    fn default_windows() -> Vec<usize> {
        vec![16, 64, 256]
    }
    fn default_z() -> f32 {
        4.0
    }
    fn default_min_scales() -> usize {
        2
    }
    fn default_min_units() -> usize {
        128
    }
    fn default_max_windows() -> usize {
        512
    }
    fn default_order() -> usize {
        4
    }
}

impl Default for PerplexityPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            window_sizes: Self::default_windows(),
            z_threshold: Self::default_z(),
            min_scales: Self::default_min_scales(),
            min_units: Self::default_min_units(),
            max_windows: Self::default_max_windows(),
            model_order: Self::default_order(),
        }
    }
}

/// Terminal-escape (VT control-sequence) detection (F2). Opt-in:
/// disabled by default. Detection requires an injected
/// `TerminalSequenceScanner` (e.g. `sigil-vt`'s Ghostty-backed engine);
/// enabled-without-scanner reports `Skipped`, never a silent pass.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TerminalEscapesPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// Cap on sequences converted to findings — bounds output volume on
    /// hostile input dense with escapes.
    #[serde(default = "TerminalEscapesPolicy::default_max_sequences")]
    pub max_sequences: usize,
}

impl TerminalEscapesPolicy {
    fn default_max_sequences() -> usize {
        512
    }
}

impl Default for TerminalEscapesPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            max_sequences: Self::default_max_sequences(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanPolicy {
    #[serde(default = "ScanPolicy::default_true")]
    pub injection_detection: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub tokenizer_firewall: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub dlp_enabled: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub entropy_analysis: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub smuggling_detection: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub rare_pattern_detection: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub slow_rate_detection: bool,
    #[serde(default = "ScanPolicy::default_true")]
    pub encoded_payloads: bool,
    #[serde(default = "ScanPolicy::default_injection_threshold")]
    pub injection_threshold: f32,
    #[serde(default = "ScanPolicy::default_entropy_window")]
    pub entropy_window: usize,
    #[serde(default = "ScanPolicy::default_entropy_deviation")]
    pub entropy_deviation: f32,
    #[serde(default)]
    pub dlp: DlpPolicy,
    #[serde(default)]
    pub perplexity: PerplexityPolicy,
    #[serde(default)]
    pub terminal_escapes: TerminalEscapesPolicy,
}

impl ScanPolicy {
    fn default_true() -> bool {
        true
    }

    fn default_injection_threshold() -> f32 {
        0.70
    }

    fn default_entropy_window() -> usize {
        64
    }

    fn default_entropy_deviation() -> f32 {
        3.0
    }
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            injection_detection: true,
            tokenizer_firewall: true,
            dlp_enabled: true,
            entropy_analysis: true,
            smuggling_detection: true,
            rare_pattern_detection: true,
            slow_rate_detection: true,
            encoded_payloads: true,
            injection_threshold: Self::default_injection_threshold(),
            entropy_window: Self::default_entropy_window(),
            entropy_deviation: Self::default_entropy_deviation(),
            dlp: DlpPolicy::default(),
            perplexity: PerplexityPolicy::default(),
            terminal_escapes: TerminalEscapesPolicy::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MergePolicy {
    #[serde(default = "MergePolicy::default_true")]
    pub suppress_cross_boundary: bool,
    #[serde(default)]
    pub boundary_tokens: bool,
    #[serde(default = "MergePolicy::default_true")]
    pub preserve_threat_annotations: bool,
}

impl MergePolicy {
    fn default_true() -> bool {
        true
    }
}

impl Default for MergePolicy {
    fn default() -> Self {
        Self {
            suppress_cross_boundary: true,
            boundary_tokens: false,
            preserve_threat_annotations: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EmitPolicy {
    #[serde(default = "EmitPolicy::default_true")]
    pub include_annotations: bool,
    #[serde(default = "EmitPolicy::default_true")]
    pub include_evidence: bool,
    #[serde(default)]
    pub evidence_mode: EvidenceMode,
    #[serde(default)]
    pub evidence_format: EvidenceFormat,
    #[serde(default = "EmitPolicy::default_max_evidence_findings")]
    pub max_evidence_findings: usize,
    #[serde(default = "EmitPolicy::default_max_evidence_summary_chars")]
    pub max_evidence_summary_chars: usize,
}

impl EmitPolicy {
    fn default_true() -> bool {
        true
    }

    fn default_max_evidence_findings() -> usize {
        64
    }

    fn default_max_evidence_summary_chars() -> usize {
        256
    }
}

impl Default for EmitPolicy {
    fn default() -> Self {
        Self {
            include_annotations: true,
            include_evidence: true,
            evidence_mode: EvidenceMode::default(),
            evidence_format: EvidenceFormat::Json,
            max_evidence_findings: Self::default_max_evidence_findings(),
            max_evidence_summary_chars: Self::default_max_evidence_summary_chars(),
        }
    }
}
