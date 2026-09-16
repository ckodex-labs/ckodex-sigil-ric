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
    #[arg(long)]
    pub policy: Option<PathBuf>,
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

#[derive(clap::Args, Debug)]
pub struct TextCommand {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub text: Option<String>,
    /// Render the full intake→scan→merge→emit pipeline instead of just
    /// the result (human format only).
    #[arg(long)]
    pub explain: bool,
}

#[derive(clap::Args, Debug)]
pub struct CompletionsCommand {
    /// Shell to generate completions for.
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(clap::Args, Debug)]
pub struct BatchTextCommand {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub text: Vec<String>,
    #[arg(long)]
    pub allow_specials: bool,
}

#[derive(clap::Args, Debug)]
pub struct TokenIdsCommand {
    #[arg(long)]
    pub ids: Vec<u32>,
}

#[derive(clap::Args, Debug)]
pub struct TokenIdsBatchCommand {
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
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub text: Vec<String>,
    #[arg(long)]
    pub manifest: Option<PathBuf>,
    #[arg(long)]
    pub corpus: Option<String>,
    #[arg(long, value_enum, default_value_t = BenchmarkPreset::Small)]
    pub preset: BenchmarkPreset,
    /// Benchmark report serialization (distinct from the global
    /// `--format` presentation mode).
    #[arg(long = "report-format", value_enum, default_value_t = BenchmarkOutputFormat::Human)]
    pub report_format: BenchmarkOutputFormat,
    #[arg(long)]
    pub output: Option<PathBuf>,
    #[arg(long)]
    pub baseline_dir: Option<PathBuf>,
    #[arg(long)]
    pub refresh_baselines: bool,
    #[arg(long)]
    pub rounds: Option<usize>,
    #[arg(long)]
    pub batch_size: Option<usize>,
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
    #[arg(long)]
    pub benchmark: Vec<PathBuf>,
    #[arg(long, value_enum, default_value_t = BurnInDeploymentMode::Monitor)]
    pub deployment_mode: BurnInDeploymentMode,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub monitor_shadow_enabled: bool,
    #[arg(long)]
    pub false_positive_rate: Option<f64>,
    #[arg(long)]
    pub false_positive_rate_threshold: Option<f64>,
    #[arg(long, default_value_t = 0)]
    pub unresolved_high_severity_findings: u32,
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub rollback_ready: bool,
    #[arg(long)]
    pub source: Option<String>,
    #[arg(long)]
    pub captured_at_unix_ms: Option<u64>,
    #[arg(long)]
    pub note: Option<String>,
    #[arg(long)]
    pub evidence_ref: Vec<String>,
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
    #[arg(long)]
    pub server_id: String,
    #[arg(long)]
    pub request_hash: String,
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub text: Option<String>,
    #[arg(long)]
    pub schema: Option<PathBuf>,
}

#[derive(clap::Args, Debug)]
pub struct ProbeCommand {
    #[arg(long)]
    pub samples: Option<PathBuf>,
    #[arg(long)]
    pub canaries: Option<PathBuf>,
    #[arg(long)]
    pub fingerprints: Option<PathBuf>,
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
    /// Modality hint: `image` (default), `audio`, `video`, or `document`.
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
    /// Also run the fusion audit over the extracted channels.
    #[arg(long)]
    pub analyze: bool,
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
    #[arg(long)]
    pub text: Option<String>,
    #[arg(long)]
    pub vision: Option<String>,
    #[arg(long)]
    pub audio: Option<String>,
    #[arg(long)]
    pub video: Option<String>,
    #[arg(long)]
    pub code: Option<String>,
    #[arg(long)]
    pub document: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SentinelCommand {
    #[arg(long)]
    pub input: Option<PathBuf>,
    #[arg(long)]
    pub text: Option<String>,
    #[arg(long)]
    pub compose: bool,
}
