use clap::{Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use sigil_core::vocab::SpecialTokenMode;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "sigil",
    version,
    about = "SIGIL security-native tokenizer toolkit"
)]
pub struct Cli {
    /// Policy TOML file (allow-lists, detector toggles, thresholds).
    #[arg(long)]
    pub policy: Option<PathBuf>,
    /// Tokenizer vocab to run under.
    #[arg(long, default_value = "cl100k_base")]
    pub vocab: String,
    /// Unencrypted PKCS#8 PEM private key. When present, every emitted
    /// receipt is signed with the corresponding ECDSA P-384 key.
    #[arg(long)]
    pub signing_key: Option<PathBuf>,
    /// Sigstore keyless signing: exchange the ambient OIDC token
    /// (SIGSTORE_ID_TOKEN) at Fulcio for a short-lived certificate and sign
    /// every receipt with the ephemeral key. Mutually exclusive with
    /// --signing-key. Requires network access to the Fulcio endpoint.
    #[arg(long, conflicts_with = "signing_key")]
    pub sigstore_keyless: bool,
    /// Append-only JSONL evidence log. When present, every emitted
    /// `EvidenceBundle` (scan path) and `McpEvidenceRecord` (mcp command)
    /// is written to this file before results are returned.
    #[arg(long)]
    pub evidence_log: Option<PathBuf>,
    /// Output format: `auto` renders human output on a terminal and JSON
    /// when piped; `json`/`human` force the mode.
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub format: OutputFormat,
    /// Colored output: `auto` enables color on a terminal unless
    /// `NO_COLOR` is set; `always`/`never` force.
    #[arg(long, value_enum, default_value = "auto", global = true)]
    pub color: ColorMode,
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputFormat {
    Auto,
    Json,
    Human,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Tokenize(TextCommand),
    TokenizeBatch(BatchTextCommand),
    Decode(TokenIdsCommand),
    DecodeBatch(TokenIdsBatchCommand),
    #[command(alias = "benchmark")]
    Bench(BenchCommand),
    Telemetry(BurnInTelemetryCommand),
    Scan(TextCommand),
    Mcp(McpCommand),
    Probe(ProbeCommand),
    Multimodal(MultimodalCommand),
    Sentinel(SentinelCommand),
    VerifyReceipt(VerifyReceiptCommand),
    Attest(AttestCommand),
    Perceive(PerceiveCommand),
    VerifyAttestation(VerifyAttestationCommand),
    Keygen(KeygenCommand),
    /// Print a shell completion script to stdout.
    Completions(CompletionsCommand),
}

/// Verdict level at which the process exits non-zero. `deny` (default)
/// exits 2 on Deny; `flag` also exits 1 on Flag; `never` always exits 0
/// regardless of the verdict.
#[derive(clap::ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FailOn {
    Never,
    Flag,
    #[default]
    Deny,
}

#[derive(clap::Args, Debug)]
pub struct TextCommand {
    /// Input file to read ("-" reads stdin). When neither --input nor
    /// --text is given, piped stdin is read automatically.
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Literal text to process. Mutually exclusive with --input.
    #[arg(long)]
    pub text: Option<String>,
    /// Render the full intake→scan→merge→emit pipeline instead of just
    /// the result (human format only).
    #[arg(long)]
    pub explain: bool,
    /// Exit non-zero when the assessment verdict reaches this level.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,
}

#[derive(clap::Args, Debug)]
pub struct CompletionsCommand {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(clap::Args, Debug)]
pub struct BatchTextCommand {
    /// JSON array file to read ("-" reads stdin).
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Literal texts to process. Mutually exclusive with --input.
    #[arg(long)]
    pub text: Vec<String>,
    /// Allow special tokens (e.g. `<|endoftext|>`) in the input.
    #[arg(long)]
    pub allow_specials: bool,
}

#[derive(clap::Args, Debug)]
pub struct TokenIdsCommand {
    /// Token IDs to decode (repeat the flag or pass several values).
    #[arg(long)]
    pub ids: Vec<u32>,
}

#[derive(clap::Args, Debug)]
pub struct TokenIdsBatchCommand {
    /// JSON array-of-arrays file to read ("-" reads stdin).
    #[arg(long)]
    pub input: Option<PathBuf>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkPreset {
    Small,
    Medium,
    Stress,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkOutputFormat {
    Human,
    Json,
    Csv,
    Jsonl,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BenchmarkSpecialTokenMode {
    Disallow,
    AllowAll,
}

impl BenchmarkSpecialTokenMode {
    pub(crate) fn as_runtime_mode(self) -> SpecialTokenMode {
        match self {
            Self::Disallow => SpecialTokenMode::Disallow,
            Self::AllowAll => SpecialTokenMode::AllowAll,
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct BenchCommand {
    /// JSON array file of inputs ("-" reads stdin).
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Literal texts to benchmark. Mutually exclusive with --input.
    #[arg(long)]
    pub text: Vec<String>,
    /// Benchmark manifest TOML (name, corpus, rounds, batch size).
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    /// Corpus name recorded in the report.
    #[arg(long)]
    pub corpus: Option<String>,
    /// Named benchmark preset.
    #[arg(long, value_enum, default_value_t = BenchmarkPreset::Small)]
    pub preset: BenchmarkPreset,
    /// Benchmark report serialization (distinct from the global
    /// `--format` presentation mode).
    #[arg(long = "report-format", value_enum, default_value_t = BenchmarkOutputFormat::Human)]
    pub report_format: BenchmarkOutputFormat,
    /// Write the rendered report to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Baseline directory for regression comparison.
    #[arg(long)]
    pub baseline_dir: Option<PathBuf>,
    /// Overwrite the stored baselines with this run's numbers.
    #[arg(long)]
    pub refresh_baselines: bool,
    /// Override the manifest's repetition count.
    #[arg(long)]
    pub rounds: Option<usize>,
    /// Override the manifest's batch size.
    #[arg(long)]
    pub batch_size: Option<usize>,
    /// Override the manifest's special-token handling.
    #[arg(long)]
    pub special_token_mode: Option<BenchmarkSpecialTokenMode>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BurnInDeploymentMode {
    Monitor,
    Shadow,
    Staged,
    Production,
}

impl BurnInDeploymentMode {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Monitor => "monitor",
            Self::Shadow => "shadow",
            Self::Staged => "staged",
            Self::Production => "production",
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct BurnInTelemetryCommand {
    /// Benchmark report JSON files to summarise (repeatable).
    #[arg(long)]
    pub benchmark: Vec<PathBuf>,
    /// Deployment posture this telemetry run reports against.
    #[arg(long, value_enum, default_value_t = BurnInDeploymentMode::Monitor)]
    pub deployment_mode: BurnInDeploymentMode,
    /// Assert that monitor/shadow mode was enabled for the window.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub monitor_shadow_enabled: bool,
    /// Observed false-positive rate for the window.
    #[arg(long)]
    pub false_positive_rate: Option<f64>,
    /// Approved false-positive threshold the observation is checked against.
    #[arg(long)]
    pub false_positive_rate_threshold: Option<f64>,
    /// Count of unresolved high-severity findings at capture time.
    #[arg(long, default_value_t = 0)]
    pub unresolved_high_severity_findings: u32,
    /// Assert that rollback can be executed without data loss.
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub rollback_ready: bool,
    /// Free-text source tag for the telemetry record.
    #[arg(long)]
    pub source: Option<String>,
    /// Capture timestamp override (milliseconds since Unix epoch).
    #[arg(long)]
    pub captured_at_unix_ms: Option<u64>,
    /// Free-text note attached to the record.
    #[arg(long)]
    pub note: Option<String>,
    /// Evidence references attached to the record (repeatable).
    #[arg(long)]
    pub evidence_ref: Vec<String>,
    /// Write the telemetry JSON to this file instead of stdout.
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct BenchmarkManifest {
    pub name: String,
    pub corpus: String,
    pub vocab: String,
    pub rounds: usize,
    pub batch_size: usize,
    pub special_token_mode: BenchmarkSpecialTokenMode,
    pub expected_parity: bool,
}

#[derive(clap::Args, Debug)]
pub struct McpCommand {
    /// Identifier of the MCP server whose response is being gated.
    #[arg(long)]
    pub server_id: String,
    /// Hash of the request the response claims to answer.
    #[arg(long)]
    pub request_hash: String,
    /// Response file to gate ("-" reads stdin; piped stdin is used when
    /// neither --input nor --text is given).
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Literal response text. Mutually exclusive with --input.
    #[arg(long)]
    pub text: Option<String>,
    /// JSON schema the response is expected to satisfy.
    #[arg(long)]
    pub schema: Option<PathBuf>,
    /// Exit non-zero when the gate verdict reaches this level.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,
}

#[derive(clap::Args, Debug)]
pub struct ProbeCommand {
    /// JSON file of probe samples to classify.
    #[arg(long)]
    pub samples: Option<PathBuf>,
    /// JSON file of canary strings for known-answer checks.
    #[arg(long)]
    pub canaries: Option<PathBuf>,
    /// JSON file of expected fingerprints to compare against.
    #[arg(long)]
    pub fingerprints: Option<PathBuf>,
    /// JSON file of boundary cases for drift checks.
    #[arg(long)]
    pub boundaries: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct VerifyReceiptCommand {
    /// JSON file containing either a bare receipt object or a full
    /// SigilOutput (the `receipt` field is extracted automatically).
    #[arg(long)]
    pub receipt: PathBuf,
    /// Hex-encoded ECDSA P-384 verification key (uncompressed SEC1 point).
    #[arg(long)]
    pub key: String,
}

#[derive(clap::Args, Debug)]
pub struct PerceiveCommand {
    /// Artifact file to decompose (image or audio).
    #[arg(long)]
    pub input: PathBuf,
    /// Modality hint: `image` (default), `audio`, `video`, `document`, or
    /// `code`. Container magic overrides a contradicting hint — the
    /// override is recorded as `sigil.modality_routed` evidence, never
    /// silent.
    #[arg(long, default_value = "image")]
    pub modality: String,
    /// External OCR binary to pin for the text channel (image, optional).
    #[arg(long)]
    pub ocr_binary: Option<PathBuf>,
    /// Arguments for the OCR binary (artifact bytes travel on stdin).
    #[arg(long, default_value = "")]
    pub ocr_args: String,
    /// External ASR binary to pin for the transcript channel (audio, optional).
    #[arg(long)]
    pub transcript_binary: Option<PathBuf>,
    /// Arguments for the ASR binary (artifact bytes travel on stdin).
    #[arg(long, default_value = "")]
    pub transcript_args: String,
    /// External renderer binary to pin for render-vs-extract comparison
    /// (document/PDF, optional — e.g. `pdftoppm`).
    #[arg(long)]
    pub render_binary: Option<PathBuf>,
    /// Arguments for the renderer binary (artifact bytes travel on stdin;
    /// e.g. `-png -singlefile -r 150 -`).
    #[arg(long, default_value = "")]
    pub render_args: String,
    /// External ffmpeg binary to pin for video stream extraction (video,
    /// optional). Demuxes the container twice: audio track → WAV →
    /// spectral/transcript, video track → PNG frames → `--ocr-binary`.
    #[arg(long)]
    pub ffmpeg_binary: Option<PathBuf>,
    /// Also run the fusion audit over the extracted channels.
    #[arg(long)]
    pub analyze: bool,
    /// Exit non-zero when the --analyze verdict reaches this level.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,
}

#[derive(clap::Args, Debug)]
pub struct AttestCommand {
    /// JSON file containing a receipt (bare, SigilOutput, or CLI envelope).
    #[arg(long)]
    pub receipt: PathBuf,
    /// Unencrypted PKCS#8 PEM private key to sign the DSSE envelope.
    #[arg(long)]
    pub signing_key: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct VerifyAttestationCommand {
    /// JSON file containing the DSSE envelope.
    #[arg(long)]
    pub attestation: PathBuf,
    /// Hex-encoded ECDSA P-384 verification key (uncompressed SEC1 point).
    #[arg(long)]
    pub key: String,
}

#[derive(clap::Args, Debug)]
pub struct KeygenCommand {
    /// Output path for the unencrypted PKCS#8 PEM private key.
    #[arg(long)]
    pub out_private: PathBuf,
    /// Output path for the SPKI PEM public key.
    #[arg(long)]
    pub out_public: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct MultimodalCommand {
    /// Authority-bearing system prompt included in the fusion audit.
    #[arg(long)]
    pub system: Option<String>,
    /// User-provided text channel.
    #[arg(long)]
    pub text: Option<String>,
    /// Text derived from a vision channel (untrusted provenance).
    #[arg(long)]
    pub vision: Option<String>,
    /// Text derived from an audio channel (untrusted provenance).
    #[arg(long)]
    pub audio: Option<String>,
    /// Text derived from a video channel (untrusted provenance).
    #[arg(long)]
    pub video: Option<String>,
    /// Source-code text channel.
    #[arg(long)]
    pub code: Option<String>,
    /// Text derived from a document channel (retrieval provenance).
    #[arg(long)]
    pub document: Option<String>,
    /// Exit non-zero when the fusion verdict reaches this level.
    #[arg(long, value_enum, default_value = "deny")]
    pub fail_on: FailOn,
}

#[derive(clap::Args, Debug)]
pub struct SentinelCommand {
    /// Input file to read ("-" reads stdin; piped stdin is used when
    /// neither --input nor --text is given).
    #[arg(long)]
    pub input: Option<PathBuf>,
    /// Literal text to classify. Mutually exclusive with --input.
    #[arg(long)]
    pub text: Option<String>,
    /// Emit the composite Sigil⊕Sentinel assessment instead of the
    /// sentinel score alone.
    #[arg(long)]
    pub compose: bool,
}
