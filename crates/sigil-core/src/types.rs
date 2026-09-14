use serde::{Deserialize, Serialize};
use std::{fmt, ops::Range};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteRange {
    pub start: usize,
    pub end: usize,
}

impl ByteRange {
    pub fn new(start: usize, end: usize) -> Self {
        Self { start, end }
    }

    pub fn len(self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(self) -> bool {
        self.start >= self.end
    }

    pub fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }

    pub fn union(self, other: Self) -> Self {
        Self {
            start: self.start.min(other.start),
            end: self.end.max(other.end),
        }
    }
}

impl From<Range<usize>> for ByteRange {
    fn from(value: Range<usize>) -> Self {
        Self {
            start: value.start,
            end: value.end,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Provenance {
    System,
    User,
    Tool,
    Retrieval,
    Generated,
    McpTool,
    McpContext,
    #[default]
    Unknown,
}

impl Provenance {
    pub fn default_trust(self) -> TrustLevel {
        match self {
            Provenance::System => TrustLevel::Privileged,
            Provenance::Tool => TrustLevel::Trusted,
            Provenance::Retrieval => TrustLevel::Bounded,
            Provenance::Generated => TrustLevel::Trusted,
            Provenance::McpContext => TrustLevel::Bounded,
            Provenance::User | Provenance::McpTool | Provenance::Unknown => TrustLevel::Untrusted,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    #[default]
    Untrusted,
    Bounded,
    Trusted,
    Privileged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn rank(self) -> u8 {
        match self {
            Severity::None => 0,
            Severity::Low => 1,
            Severity::Medium => 2,
            Severity::High => 3,
            Severity::Critical => 4,
        }
    }

    pub fn max(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    pub fn from_rank(rank: u8) -> Self {
        match rank {
            0 => Severity::None,
            1 => Severity::Low,
            2 => Severity::Medium,
            3 => Severity::High,
            _ => Severity::Critical,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryContext {
    Start,
    Interior,
    End,
    CrossBoundary,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceFormat {
    Json,
    Cbor,
    Protobuf,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Grapheme {
    pub text: String,
    pub byte_range: ByteRange,
    pub normalized: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TaintedGrapheme {
    pub grapheme: Grapheme,
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub boundary_context: BoundaryContext,
    pub threat: ScanFinding,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextSegment<'a> {
    pub text: &'a str,
    pub provenance: Provenance,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ByteSegment<'a> {
    pub bytes: &'a [u8],
    pub provenance: Provenance,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanFinding {
    pub byte_range: ByteRange,
    pub severity: Severity,
    pub detectors: Vec<DetectorId>,
    pub confidence: f32,
    pub evidence: String,
}

impl ScanFinding {
    pub fn none(byte_range: ByteRange) -> Self {
        Self {
            byte_range,
            severity: Severity::None,
            detectors: Vec::new(),
            confidence: 0.0,
            evidence: String::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectorId {
    InjectionGrammar,
    UnicodeControl,
    Confusable,
    DlpCreditCard,
    DlpSsn,
    DlpApiKey,
    DlpEmail,
    DlpCustom,
    EntropySpike,
    TokenSmuggling,
    MergeBoundary,
    CrossModal,
    SchemaViolation,
    FingerprintMismatch,
    ConsistencyShift,
    SubliminalAudio,
    AudioSteganography,
    RarePattern,
    SlowRateInjection,
    PerplexityAnomaly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DlpFinding {
    pub kind: DlpKind,
    pub byte_range: ByteRange,
    pub severity: Severity,
    pub action: DlpAction,
    pub confidence: f32,
    pub sample: String,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpKind {
    CreditCard,
    Ssn,
    ApiKey,
    Email,
    Phone,
    Custom(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DlpAction {
    Flag,
    Deny,
    Redact,
    Off,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EntropyProfile {
    pub window_size: usize,
    pub baseline_entropy: f32,
    pub average_entropy: f32,
    pub peak_entropy: f32,
    pub anomaly_count: usize,
}

impl Default for EntropyProfile {
    fn default() -> Self {
        Self {
            window_size: 0,
            baseline_entropy: 0.0,
            average_entropy: 0.0,
            peak_entropy: 0.0,
            anomaly_count: 0,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct InputAssessment {
    pub verdict: Verdict,
    pub max_severity: Severity,
    pub threat_count: usize,
    pub entropy_profile: EntropyProfile,
    pub dlp_findings: Vec<DlpFinding>,
    pub injection_score: f32,
    /// Multiscale perplexity-anomaly evidence (`Some` whenever the
    /// detector ran — carries `Skipped`/`Failed` outcomes too).
    #[serde(default)]
    pub perplexity: Option<crate::perplexity::PerplexityReport>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum FlagReason {
    InjectionPattern,
    DlpFinding,
    EntropyAnomaly,
    Smuggling,
    UnicodeAbuse,
    SchemaMismatch,
    BehavioralDrift,
    SentinelDisagreement,
    CrossModalSmuggling,
    PerplexityAnomaly,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum DenyReason {
    CriticalFinding,
    PolicyViolation,
    SchemaViolation,
    BudgetExceeded,
    ProvenanceViolation,
    SentinelCritical,
    BehavioralCompromise,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum Verdict {
    Allow,
    Flag { reasons: Vec<FlagReason> },
    Deny { reasons: Vec<DenyReason> },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenAnnotation {
    pub provenance: Provenance,
    pub trust_level: TrustLevel,
    pub threat: ScanFinding,
    pub byte_range: ByteRange,
    pub normalized: bool,
    pub boundary: bool,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub id: String,
    pub verdict: Verdict,
    pub findings: Vec<ScanFinding>,
    pub token_count: usize,
    pub format: EvidenceFormat,
    pub persisted: bool,
    pub summary: String,
    pub timestamp_unix_ms: u64,
}

/// Cryptographic binding between the raw input and the canonical
/// (normalized) representation actually tokenized. Implements the RIC
/// receipt primitive: raw bytes are hashed as received, the canonical
/// stream is hashed as consumed, and both travel with every output so
/// "what was inspected" and "what was interpreted" are provably the same
/// object (docs/RIC-CONTRACT.md, RIC-R-1..R-4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct RepresentationReceipt {
    /// SHA-384 (hex) over the raw input bytes as received, pre-normalization.
    pub raw_digest: String,
    /// SHA-384 (hex) over the canonical grapheme stream as tokenized.
    pub canonical_digest: String,
    /// Hash algorithm used for the digests above. Self-describing so
    /// verifiers can recompute without assumptions (signed as part of the
    /// receipt message, `sigil-receipt-v2`).
    pub digest_algorithm: String,
    /// Normalization profile applied between raw and canonical (e.g. "nfc").
    pub normalization: String,
    /// Tokenizer identity the canonical stream was encoded against.
    pub vocab: String,
    pub token_count: usize,
    /// Signature over the receipt content, present when a signer is
    /// attached to the engine (docs/RIC-CONTRACT.md DEV-3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<crate::signing::ReceiptSignature>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct SigilOutput {
    pub token_ids: Vec<u32>,
    pub annotations: Vec<TokenAnnotation>,
    pub assessment: InputAssessment,
    pub evidence: Option<EvidenceBundle>,
    pub receipt: RepresentationReceipt,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::None => "none",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        })
    }
}
