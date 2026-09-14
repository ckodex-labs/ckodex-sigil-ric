# SIGIL-SPEC v0.3.0

## Security-Integrated Governance-Informed Lexer

> *"The tokenizer is the first firewall."*

**Status:** DRAFT  
**Author:** MNChorfa — Thales Digital Solutions (R&T, Canada)  
**Ecosystem:** Ckodex · ckodex-labs  
**License:** TBD (dual: Apache-2.0 + commercial)  
**Date:** 2026-04-03  

> **Representation Integrity:** this specification implements the RIC contract
> ([docs/RIC-CONTRACT.md](./docs/RIC-CONTRACT.md)): *admit what is interpreted,
> execute what was admitted, prove the two are the same.* Conformance vectors:
> `crates/sigil-core/tests/conformance_vectors.rs` (CV-RIC-001..008).  

---

## 1. Problem Statement

Every modern LLM system — from ChatGPT to Claude to open-weight deployments — relies on a tokenizer designed for a single objective: **compression efficiency**. BPE, SentencePiece, Unigram, tiktoken — all optimize for minimal token count given a training corpus. None treat the tokenizer as what it structurally *is*: **the first interpreter of all untrusted input**.

This creates a systemic blind spot. Every prompt injection, every data exfiltration attempt, every adversarial encoding exploit passes through the tokenizer *before* any safety mechanism engages. Current defenses — output classifiers, embedding-space detectors, guardrail wrappers — operate **post-tokenization**, after the adversarial structure is already encoded in the representation space.

SIGIL inverts this. It treats tokenization as a **security boundary** — the lexical gate where governance begins.

### 1.1 The Structural Gap

```
Current pipeline:
  raw_input → [tokenizer] → token_ids → [embeddings] → [model] → [output_filter] → response
                   ↑                                                      ↑
              blind pass-through                                   too late to detect
                                                                   structural attacks

SIGIL pipeline:
  raw_input → [SIGIL] → annotated_tokens → [embeddings] → [model] → [output_filter] → response
                 ↑
          security boundary:
          - provenance tagging
          - injection detection
          - DLP scanning
          - adversarial encoding detection
          - entropy anomaly detection
          - taint propagation
```

### 1.2 Attack Classes Addressable at the Token Level

| Attack Class | Current Detection Point | SIGIL Detection Point | Advantage |
|---|---|---|---|
| Prompt injection | Post-embedding classifier | Token-sequence grammar analysis | Structural, not statistical |
| Unicode homoglyphs | Output filter (if at all) | Pre-merge grapheme normalization | Catches before encoding |
| Zero-width char injection | Rarely caught | Byte-level scan stage | Deterministic detection |
| Token smuggling | Unknown | Merge-boundary analysis | Novel detection surface |
| DLP/PII exfiltration | Output scanner | Pre-merge pattern matching | Prevents model exposure |
| RTL override attacks | Rarely caught | Bidirectional control analysis | Unicode-native |
| Instruction-data confusion | Prompt engineering heuristics | Provenance taint bits | Formal boundary enforcement |

---

## 2. Design Principles

**P-1: Security is not a layer; it is the lexer.**  
SIGIL does not wrap a tokenizer with security checks. Security semantics are embedded in the tokenization algorithm itself.

**P-2: Provenance is first-class.**  
Every token carries taint metadata — its origin (system, user, tool, retrieval, generated), trust level, and boundary context. This metadata propagates through the pipeline.

**P-3: Zero-copy, zero-allocation hot path.**  
Security cannot come at the cost of inference latency. The core scan loop must operate on borrowed byte slices with no heap allocation in the common (clean) case.

**P-4: Drop-in compatible.**  
SIGIL must produce standard token IDs consumable by any model. The security annotations are sideband metadata — models that ignore them still function; models that consume them gain governance awareness.

**P-5: Vocabulary-agnostic.**  
SIGIL is not a new vocabulary. It wraps *any* BPE/Unigram/SentencePiece vocabulary and adds the security stage. You bring your tokenizer; SIGIL makes it a firewall.

**P-6: Composable with Valance.**  
SIGIL token-level taint feeds directly into Valance binding evaluation. A tainted token sequence that enters a shell context triggers Valance's radical-deny. The two systems are complementary: SIGIL guards the input boundary; Valance guards the execution boundary.

---

## 3. Architecture

### 3.1 Five-Stage Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│                        SIGIL Pipeline                           │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────┐  ┌─────┐│
│  │  INTAKE   │→│  TAINT   │→│   SCAN    │→│  MERGE  │→│ EMIT ││
│  │          │  │          │  │          │  │        │  │     ││
│  │ bytes →  │  │ provenance│ │ patterns │  │ BPE w/ │  │ ann.││
│  │ graphemes│  │ tagging  │  │ + entropy│  │ sec.   │  │ tok ││
│  │          │  │          │  │ + struct │  │ policy │  │ ids ││
│  └──────────┘  └──────────┘  └──────────┘  └────────┘  └─────┘│
│                                                                 │
│  Latency budget: <200μs typical · <1ms worst-case (per chunk)  │
└─────────────────────────────────────────────────────────────────┘
```

#### Stage 1: INTAKE — Byte Stream → Grapheme Clusters

Raw bytes are segmented into Unicode grapheme clusters (UAX #29). This stage performs:

- **Encoding validation** — reject/flag malformed UTF-8
- **Per-cluster normalization** — clusters are segmented from the RAW text first, then each cluster is normalized individually (NFC/NFKC per policy). Because extended grapheme clusters are closed under normalization, this is equivalent to whole-text normalization while keeping every byte range accurate against the raw input (INV-007).
- **Homoglyph detection** — confusable character identification (Unicode UTS #39 skeleton mapping)
- **Control character inventory** — flag zero-width joiners/non-joiners, bidirectional overrides and isolates, interlinear annotation, invisible operators, and tag characters (U+E0000–U+E007F)
- **Invisible character stripping** — configurable policy (`strip`, `flag`, `deny`, `allow`). `strip` removes graphemes that consist solely of invisible characters; clusters with attached invisible characters are never silently rewritten — they are flagged by SCAN (or denied), preserving the raw-evidence binding.

Output: `Vec<Grapheme>` where each grapheme carries its raw byte offset and normalization metadata.

#### Stage 2: TAINT — Provenance Tagging

Each grapheme is annotated with provenance bits:

```rust
#[repr(u8)]
enum Provenance {
    System    = 0b0000_0001,  // System prompt / instructions
    User      = 0b0000_0010,  // Direct user input
    Tool      = 0b0000_0100,  // Tool/function output (local)
    Retrieval = 0b0000_1000,  // RAG / retrieved context
    Generated = 0b0001_0000,  // Model-generated (for re-tokenization)
    McpTool   = 0b0010_0000,  // MCP server response (external, untrusted)
    McpContext= 0b0100_0000,  // MCP-injected context (resources, prompts)
    Unknown   = 0b1000_0000,  // Provenance cannot be determined → high suspicion
}

struct TaintedGrapheme {
    grapheme: Grapheme,
    provenance: Provenance,
    trust_level: TrustLevel,       // Untrusted | Bounded | Trusted | Privileged
    boundary_context: BoundaryCtx, // Start | Interior | End | CrossBoundary
}
```

Provenance is supplied by the caller (the inference server knows which segment is system vs. user). SIGIL validates that boundary markers are consistent and flags anomalies — e.g., user-provenance graphemes that contain instruction-like patterns.

#### Stage 3: SCAN — Pattern Detection

The scan stage runs multiple detectors on the tainted grapheme stream:

**3a. Injection Grammar Detection**  
A finite automaton recognizes structural patterns characteristic of prompt injection:
- Role-switching markers (`system:`, `[INST]`, `<|im_start|>`, `### Instruction`)
- Instruction-override patterns (`ignore previous`, `disregard`, `new instructions`)
- Delimiter manipulation (closing/opening XML-like tags, markdown fences)
- Multi-language injection patterns (CJKV, Arabic, Cyrillic variants)

Detection is **structural, not keyword-based** — the automaton recognizes *grammatical patterns* of injection, not specific strings. This makes it resistant to synonym substitution.

**3b. DLP Pattern Matching**  
Pre-configured + extensible pattern sets:
- Credit card numbers (Luhn-validated)
- SSNs, national ID patterns (configurable by jurisdiction)
- API keys / secrets (high-entropy string detection + known prefix patterns like `sk-`, `ghp_`, `AKIA`)
- Email addresses, phone numbers
- Custom PII patterns (regex-based, user-supplied)

DLP scanning occurs **before** BPE merge — patterns are detected on the raw grapheme stream where they are structurally intact. Post-tokenization, a credit card number may be split across 3-4 tokens, making detection unreliable.

**3c. Entropy Analysis**  
Per-window entropy calculation on the grapheme stream. Anomalous entropy regions (sudden spikes or drops relative to the baseline for the declared content type) are flagged. This catches:
- Base64-encoded payloads embedded in natural language
- Encrypted/compressed blobs
- Random padding used to manipulate attention patterns

**3d. Token Smuggling Detection**  
Analysis of how the grapheme stream will map to BPE merges, detecting inputs crafted to exploit merge boundaries:
- Payloads split across merge seams to avoid pattern detection
- Characters inserted specifically to force/prevent certain merges
- Adversarial inputs designed to produce specific token sequences through BPE edge cases

**3e. Multiscale Perplexity-Anomaly Detection** *(optional, policy-gated)*  
Sliding windows are scored at several scales; a window whose mean surprisal is a robust outlier (median/MAD z-score) — corroborated across `min_scales` scales — produces a `PerplexityAnomaly` finding. This catches camouflaged segments that break the document's own predictive statistics: encoded blobs, obfuscated payloads, script switches.

The surprisal signal comes from a `SurprisalScorer` trait — model code never lives in the kernel. The built-in `SelfSurprisalScorer` is a deterministic order-k character n-gram model fit to the input itself (offline, zero dependencies); LM-grade scorers plug in through `Sigil::with_surprisal_scorer`. Scores become *findings* — the kernel's severity→verdict mapping owns every verdict (`Medium` → `Flag`, `Deny` under `Mode::Strict`). Scorer failure is evidence-visible (`PerplexityStatus::Failed`), never silent, never self-decided. Honest scope: the built-in scorer flags statistical outliers, not same-style English instructions — that requires an injected LM scorer. Disabled by default; enable via `[scan.perplexity] enabled = true`.

Output: `Vec<ScanResult>` — each grapheme now carries a `ThreatAssessment`:

```rust
struct ThreatAssessment {
    severity: Severity,       // None | Low | Medium | High | Critical
    detectors: Vec<DetectorId>,
    confidence: f32,          // 0.0–1.0
    evidence: ScanEvidence,   // What triggered detection
}

enum Severity {
    None,
    Low,       // Informational — unusual but not threatening
    Medium,    // Suspicious — warrants logging
    High,      // Likely malicious — flag for review
    Critical,  // Known attack pattern — deny by policy
}
```

#### Stage 4: MERGE — Security-Aware Tokenization

Standard BPE/Unigram merge, but with governance-informed modifications:

- **Merge suppression** — when a merge would combine graphemes across a provenance boundary (e.g., system→user), the merge is suppressed. This preserves boundary integrity in the token representation. Suppression is governed by `merge.suppress_cross_boundary` (default: enabled).
- **Boundary findings** — every boundary event is recorded as a `MergeBoundary` finding. When suppression is enabled, the finding records the preserved boundary (severity `Low` when trust levels differ, informational otherwise). When suppression is disabled by policy, each crossing is flagged **High**: the resulting token carries the first source's provenance over bytes that originate elsewhere — the unsafe-merge condition itself.
- **Threat-annotated merges** — when a merge would obscure a flagged pattern (e.g., merging the digits of a detected credit card number into opaque tokens), the merge proceeds but the resulting token inherits the threat annotation.
- **Boundary tokens** — optional insertion of explicit boundary tokens between provenance zones (`<|sigil:boundary:system→user|>`), configurable per deployment.

The merge stage uses the *same vocabulary* as the target model. SIGIL does not define its own vocabulary — it applies security policy to the merge algorithm of whatever tokenizer is in use.

#### Stage 5: EMIT — Annotated Token Stream

Output is a standard token ID sequence *plus* a sideband annotation vector:

```rust
struct SigilOutput {
    /// Standard token IDs — compatible with any model
    token_ids: Vec<u32>,
    
    /// Per-token security annotations (same length as token_ids)
    annotations: Vec<TokenAnnotation>,
    
    /// Aggregate threat assessment for the entire input
    assessment: InputAssessment,
    
    /// Evidence bundle for audit trail (lazy — non-Allow verdicts only)
    evidence: Option<EvidenceBundle>,
    
    /// Representation receipt — binds raw input, canonical stream,
    /// normalization profile, and tokenizer identity (RIC-R-1..R-4).
    /// Always present; digests are deterministic in (input, policy).
    receipt: RepresentationReceipt,
}

struct RepresentationReceipt {
    raw_digest: String,        // SHA-384 over raw input bytes as received
    canonical_digest: String,  // SHA-384 over the normalized grapheme stream
    digest_algorithm: String,  // "sha384" — self-describing, signed
    normalization: String,     // profile id: "nfc" | "nfkc" | "none"
    vocab: String,             // tokenizer identity used for encoding
    token_count: usize,
    signature: Option<ReceiptSignature>,  // present when a signer is attached
}

struct ReceiptSignature {
    algorithm: String,         // "ecdsa-p384-sha384" (from the signer port)
    key_id: String,            // derived from the verification key
    signature: String,         // hex-encoded r||s (96 bytes for P-384)
}

// Receipt signing (DEV-3): the engine defines a ReceiptSigner port; the
// reference adapter is ECDSA P-384 (NIST P-384 / secp384r1, SHA-384,
// RFC 6979 deterministic nonces). Receipt digests are SHA-384 (strength-
// aligned with the signature mandate). The signed message is the versioned
// canonical receipt content
// ("sigil-receipt-v2|raw=...|canonical=...|digest=...|norm=...|vocab=...|tokens=..."),
// so any tampering with the admitted-representation binding is detectable.
// Key material lives in the signer, never in Policy. Sigstore keyless and
// HSM signers are future adapters of the same port.

struct TokenAnnotation {
    provenance: Provenance,
    trust_level: TrustLevel,
    threat: ThreatAssessment,
    byte_range: Range<usize>,   // Back-reference to original input
    normalized: bool,            // Was this grapheme normalized?
    boundary: bool,              // Is this at a provenance boundary?
}

struct InputAssessment {
    verdict: Verdict,            // Allow | Flag | Deny
    max_severity: Severity,
    threat_count: usize,
    entropy_profile: EntropyProfile,
    dlp_findings: Vec<DlpFinding>,
    injection_score: f32,        // 0.0–1.0 composite injection probability
}

enum Verdict {
    Allow,                       // Clean input — proceed
    Flag { reasons: Vec<FlagReason> },  // Suspicious — log + proceed (or escalate per policy)
    Deny { reasons: Vec<DenyReason> },  // Blocked — do not pass to model
}
```

### 3.2 Policy Configuration

SIGIL behavior is governed by a policy file (TOML):

```toml
[sigil]
version = "0.1.0"
mode = "enforce"  # "monitor" | "enforce" | "strict"

[intake]
normalization = "nfc"           # "nfc" | "nfkc" | "none"
homoglyph_action = "normalize"  # "normalize" | "flag" | "deny"
invisible_chars = "strip"       # "strip" | "flag" | "deny" | "allow"
max_input_bytes = 1_048_576     # 1 MiB default

[taint]
require_provenance = true       # Reject inputs without provenance markers
unknown_trust = "untrusted"     # Default trust for unmarked segments

[scan]
injection_detection = true
dlp_enabled = true
entropy_analysis = true
smuggling_detection = true
injection_threshold = 0.7       # Composite score threshold for Deny
entropy_window = 64             # Graphemes per entropy window
entropy_deviation = 3.0         # Std deviations for anomaly

[scan.dlp]
credit_cards = true
ssn = true
api_keys = true
emails = "flag"                 # "flag" | "deny" | "redact" | "off"
custom_patterns = ["patterns/custom.toml"]

[scan.perplexity]
enabled = false                 # opt-in: noisy on short inputs
window_sizes = [16, 64, 256]    # units per sliding window (chars, built-in scorer)
z_threshold = 4.0               # median/MAD robust z-score for flagging
min_scales = 2                  # scales a flag cluster must span to report
min_units = 128                 # shorter inputs → Skipped
max_windows = 512               # total windows across scales — cost bound
model_order = 4                 # char n-gram context order (built-in scorer)

[merge]
suppress_cross_boundary = true
boundary_tokens = false         # Insert explicit boundary markers
preserve_threat_annotations = true

[emit]
include_annotations = true
include_evidence = true         # Generate evidence bundles
evidence_mode = "non-allow"     # "non-allow" (lazy, INV-006) | "always" (attest every admission)
evidence_format = "json"        # "json" | "cbor" | "protobuf"
```

---

## 4. Delivery Artifacts

SIGIL ships as a standalone, embeddable package — same philosophy as Valance.

| Artifact | Description | Target |
|---|---|---|
| `ckx-sigil` | Rust crate — core library | `crates.io` |
| `ckx-sigil-mcp` | Rust crate — MCP security gate | `crates.io` |
| `ckx-sigil-probe` | Rust crate — model health query engine | `crates.io` |
| `libsigil` | C ABI shared library — `crates/sigil-ffi` cdylib (`cargo build -p sigil-ffi --release`); ABI at `bindings/c/sigil_tiktoken.h` | FFI consumers |
| `sigil.wasm` | WebAssembly module — `scripts/build_wasm.sh` (wasm32-freestanding reactor; `memory` + `zig_tiktoken_*` exports) | Browser / edge / serverless |
| `sigil` | CLI tool (tokenize, scan, mcp, probe) | Operators / CI pipelines |
| `sigil_tiktoken` | Python bindings (ctypes over the Zig shared library) | ML ecosystem integration |
| `sigil-server` | Sidecar composition façade; gRPC/HTTP transport planned | Inference pipeline sidecar |

### 4.1 CLI Interface

The binary is `sigil-cli` (workspace crate `sigil-cli`). Global flags: `--policy <toml>`,
`--vocab <name>` (default `cl100k_base`). All results are emitted as JSON.

```bash
# Tokenize with security analysis
$ sigil-cli tokenize --input prompt.txt
{"result":{"token_ids":[...],"annotations":[...],"assessment":{"verdict":"Allow",...},
 "evidence":null,"receipt":{"raw_digest":"…","canonical_digest":"…",
 "normalization":"nfc","vocab":"cl100k_base","token_count":9}}}

# Scan only (no tokenization — just security analysis)
$ sigil-cli scan --input prompt.txt
{"result":{"token_ids":[...],"annotations":[...],"assessment":{"verdict":{"Flag":{"reasons":[...]}} ,...},...}}

# Multimodal fusion audit (per-modality provenance defaults; --system feeds
# the authority-bearing channel)
$ sigil-cli multimodal --system "You are a helpful assistant." \
    --document "Quarterly report figures look stable."
{"result":{...,"fusion":{"events":[{"kind":"cross_trust_fusion",...},...]},
 "authority_ceiling":"draft","verdict":"Allow"}}

# Key generation (PKCS#8 private + SPKI public; private chmod 600)
$ sigil-cli keygen --out-private sigil-key.pem --out-public sigil-pub.pem
{"result":{"key_id":"…","verification_key_hex":"…",...}}

# Signed admission (any engine command; receipts carry ECDSA P-384 signatures)
$ sigil-cli --signing-key sigil-key.pem tokenize --input prompt.txt
{"result":{...,"receipt":{...,"signature":{"algorithm":"ecdsa-p384-sha384",...}}}}

# Receipt verification (no producer code required — RIC §5)
$ sigil-cli verify-receipt --receipt signed-output.json --key <hex-pinned-key>
{"result":{"valid":true,"algorithm":"ecdsa-p384-sha384","key_id":"…"}}

# Benchmark
$ sigil-cli bench --preset small --input corpus.txt

# MCP gate
$ sigil-cli mcp --input tool-response.json
```

Subcommands: `tokenize`, `tokenize-batch`, `decode`, `decode-batch`, `bench`
(alias `benchmark`), `telemetry`, `scan`, `mcp`, `probe`, `multimodal`, `sentinel`,
`verify-receipt`, `keygen`, `perceive`. Global flag `--signing-key <pem>` signs every emitted
receipt (PKCS#8 PEM, OpenSSL-interoperable; private file written mode 600). Global flag
`--sigstore-keyless` signs every receipt with a Fulcio-issued ephemeral P-384 certificate
exchanged for the ambient OIDC token (`SIGSTORE_ID_TOKEN`); requires network at signing
time, mutually exclusive with `--signing-key`.

### 4.2 Rust API

```rust
use sigil_core::{Sigil, Policy, Provenance, TextSegment, Vocab, Verdict};

// Initialize with vocabulary and policy
let policy = Policy::from_file("policy.toml")?;
let vocab = Vocab::tiktoken("cl100k_base");
let sigil = Sigil::new(vocab, policy)?;

// Optionally attach a receipt signer (ECDSA P-384 reference adapter);
// key material lives in the signer, never in Policy.
// let sigil = sigil.with_receipt_signer(std::sync::Arc::new(signer));

// Tokenize with provenance
let output = sigil.process_text_segments(&[
    TextSegment { text: system_prompt, provenance: Provenance::System },
    TextSegment { text: user_input, provenance: Provenance::User },
    TextSegment { text: tool_output, provenance: Provenance::Tool },
])?;

match output.assessment.verdict {
    Verdict::Allow => {
        // Pass output.token_ids to model
        model.forward(&output.token_ids)?;
    }
    Verdict::Flag { reasons } => {
        log::warn!("Input flagged: {:?}", reasons);
        // Proceed with logging, or escalate per policy
    }
    Verdict::Deny { reasons } => {
        return Err(SigilDeny { reasons });
    }
}

// Receipt: binds raw input, canonical stream, profile, tokenizer identity —
// and carries a signature when a signer is attached.
let receipt = &output.receipt;

// Access per-token annotations
for (token_id, annotation) in output.token_ids.iter().zip(&output.annotations) {
    if annotation.threat.severity >= Severity::Medium {
        println!("Token {} flagged: {:?}", token_id, annotation.threat);
    }
}
```

---

## 5. Integration Points

### 5.1 Ckodex Containment Plane

SIGIL operates as a **pre-inference hook** in the Containment Plane:

```
Containment Plane
├── SIGIL (pre-inference) ← tokenization + security boundary
│   ├── YARA rules feed SIGIL pattern library
│   ├── Canary traps inform taint configuration
│   └── Behavioral baselines inform entropy thresholds
├── SIGIL-MCP (tool boundary) ← MCP content security gate
│   ├── Per-server trust profiles
│   ├── Response schema validation
│   └── Cross-tool taint accumulation
├── SIGIL-PROBE (model boundary) ← behavioral health monitoring
│   ├── Canary + fingerprint probes
│   ├── Output distribution tracking
│   └── SHIELD bridge (trigger deep audit on drift)
├── Valance (execution boundary) ← governance binding
├── Runtime monitors (inter-agent)
└── Output filters (post-inference)
```

### 5.2 Valance Composition

SIGIL and Valance are complementary:

- **SIGIL** → guards the **input boundary** (untrusted text → tokenized representation)
- **Valance** → guards the **execution boundary** (intent → action)

When SIGIL detects tainted tokens that flow into a Valance-evaluated context:

```
SIGIL taint(User, severity=Medium) 
  + Valance context(shell_exec) 
  → radical(deny)
```

The anti-dilution theorem applies: if SIGIL marks *any* token as tainted with severity ≥ Medium, and that token appears in a Valance shell context, the entire binding is radical (deny). Taint does not dilute through composition.

### 5.3 SHIELD Relationship

SIGIL and SHIELD address **different threat models**:

| | SIGIL | SHIELD |
|---|---|---|
| **Threat** | Malicious input | Malicious model modification |
| **When** | Inference time | Post-training / pre-deployment |
| **What** | Token stream analysis | Weight-space forensics |
| **Where** | Before the model | Inside the model |
| **Scope** | Every request | Periodic audits |

They are **orthogonal defenses**: SIGIL protects against adversarial inputs assuming a trusted model; SHIELD ensures the model itself has not been tampered with. Together they form a complete trust boundary — the model is verified (SHIELD), and the input is verified (SIGIL).

### 5.4 MCP Security Gate

MCP (Model Context Protocol) is the emerging standard for tool integration — and it is a **wide-open attack surface**. Every MCP server response is injected directly into the model's context window. The protocol itself provides no content inspection, no taint tracking, no injection detection. The model treats MCP tool results with the same trust as system instructions.

This is the **indirect prompt injection** problem at industrial scale.

SIGIL positions itself as a **mandatory security proxy** for all MCP content flows:

```
┌──────────────────────────────────────────────────────────────────┐
│                    MCP Security Architecture                     │
│                                                                  │
│  MCP Server A ──┐                                                │
│  MCP Server B ──┼──→ [SIGIL MCP Gate] ──→ Context Assembly ──→ Model
│  MCP Server C ──┘         │                                      │
│                           ├── taint(McpTool, server_id)          │
│                           ├── scan(injection, dlp, schema)       │
│                           ├── validate(response_schema)          │
│                           └── evidence(per_server_attestation)   │
│                                                                  │
│  Without SIGIL:  MCP response → raw injection into context       │
│  With SIGIL:     MCP response → scanned → tainted → bounded     │
└──────────────────────────────────────────────────────────────────┘
```

#### 5.4.1 MCP Threat Surface

| Threat | Vector | SIGIL Mitigation |
|---|---|---|
| **Indirect prompt injection** | MCP tool response contains instruction-override patterns | Injection grammar detection on McpTool-provenance content |
| **Data exfiltration via tool** | Tool crafts response to encode secrets in seemingly benign output | DLP scan on tool response before context injection |
| **Schema violation** | Tool returns unexpected structure to confuse model parsing | Schema validation against declared MCP tool schema |
| **Context poisoning** | MCP resource injection pollutes long-term context | Taint propagation — McpContext tokens never promote to System trust |
| **Server impersonation** | Rogue MCP server responds on behalf of legitimate server | Server identity verification + per-server taint profiles |
| **Response inflation** | Tool returns excessive content to dilute system instructions | Token budget enforcement per MCP source |
| **Recursive injection** | Tool output triggers another tool call with embedded payload | Cross-tool taint accumulation — taint compounds, never dilutes |

#### 5.4.2 MCP-Specific Scan Rules

SIGIL extends its scan stage with MCP-aware detectors:

```rust
/// MCP-specific scan configuration
struct McpScanConfig {
    /// Validate tool response against declared JSON schema
    schema_validation: bool,
    
    /// Maximum tokens allowed from a single MCP response
    max_response_tokens: usize,       // default: 4096
    
    /// Per-server trust profiles
    server_profiles: HashMap<ServerId, ServerTrustProfile>,
    
    /// Cross-tool taint accumulation policy
    cross_tool_taint: TaintPolicy,    // Accumulate | Reset | Inherit
    
    /// MCP resource injection policy
    resource_policy: ResourcePolicy,  // Scan | ScanAndQuarantine | Deny
}

struct ServerTrustProfile {
    server_id: ServerId,
    trust_level: TrustLevel,          // Untrusted | Bounded | Trusted
    allowed_content_types: Vec<ContentType>,
    injection_threshold: f32,         // Stricter for untrusted servers
    dlp_policy: DlpPolicy,           // What DLP rules apply to this server
    token_budget: usize,             // Max tokens per response
    history: ServerHistory,           // Behavioral baseline for this server
}
```

#### 5.4.3 MCP Integration Modes

SIGIL can integrate into MCP flows in three modes:

**Mode 1: MCP Proxy (recommended)**  
SIGIL operates as a transparent proxy between the MCP client and MCP servers. All traffic passes through SIGIL. No changes required to client or server code.

```
Client → SIGIL Proxy → MCP Server
                ↓
         scan + taint + evidence
```

**Mode 2: MCP Middleware**  
SIGIL registers as MCP middleware in the client SDK. Tool responses are scanned before being added to the context.

```rust
let mcp_client = McpClient::new()
    .with_middleware(SigilMcpMiddleware::new(policy))
    .connect("https://mcp.example.com")?;
```

**Mode 3: Post-Assembly Scan**  
SIGIL scans the fully assembled context (system + user + tool responses) before tokenization. Less granular than Modes 1-2 but works with any MCP implementation.

#### 5.4.4 MCP Evidence Trail

Every MCP content flow through SIGIL generates an evidence record:

```rust
struct McpEvidence {
    server_id: ServerId,
    tool_name: String,
    request_hash: Hash,           // Hash of the tool invocation
    response_hash: Hash,          // Hash of the raw response
    scan_result: ScanResult,      // Full scan output
    taint_applied: Provenance,    // McpTool | McpContext
    tokens_consumed: usize,       // Token budget impact
    schema_valid: bool,           // Did response match declared schema
    timestamp: Timestamp,
    sigil_version: Version,
}
```

This evidence feeds into the Ckodex UCA pipeline — every MCP interaction is attestable and auditable.

### 5.5 Model Health Query — SIGIL-PROBE

SIGIL's position at the input boundary gives it a unique vantage point: it sees **every token that enters the model**. Over time, this creates a statistical picture of input patterns. SIGIL-PROBE extends this into **active model health monitoring** — detecting when the model's behavior drifts from expected baselines.

This is the bridge between SIGIL (input security) and SHIELD (model integrity).

#### 5.5.1 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                      SIGIL-PROBE Architecture                    │
│                                                                  │
│  SIGIL Pipeline ────→ Input Telemetry ─┐                         │
│                                        ├──→ Correlation Engine   │
│  Model Output ──────→ Output Telemetry ┘         │               │
│                                                  ↓               │
│                                        Behavioral Baseline       │
│                                              │                   │
│                                    ┌─────────┼─────────┐        │
│                                    ↓         ↓         ↓        │
│                               Drift     Anomaly    Health       │
│                              Detection  Alerting   Score        │
│                                    │         │         │        │
│                                    └─────────┼─────────┘        │
│                                              ↓                   │
│                                    ┌─────────────────────┐       │
│                                    │ SHIELD Integration  │       │
│                                    │ (trigger deep audit │       │
│                                    │  on health decline) │       │
│                                    └─────────────────────┘       │
└──────────────────────────────────────────────────────────────────┘
```

#### 5.5.2 Health Signals

SIGIL-PROBE monitors three classes of signals:

**Class A: Input-Output Correlation**  
- **Response entropy vs. input entropy** — a healthy model's output entropy should correlate with input complexity. Sudden decorrelation suggests drift.
- **Refusal rate tracking** — if refusal rates spike for inputs that previously succeeded, the model may have been over-constrained or fine-tuned.
- **Latency-to-token ratio** — abnormal latency patterns for normal inputs can indicate model degradation or substitution.

**Class B: Behavioral Drift Detection**  
- **Output distribution shift** — statistical comparison of token distribution in outputs over sliding windows. KL-divergence or Wasserstein distance against baseline.
- **Capability regression** — periodic canary probes (known-good input→expected-output pairs) to verify model capability hasn't degraded.
- **Safety boundary drift** — monitoring whether the model's safety behavior is consistent. If previously-blocked patterns start succeeding, SHIELD audit is triggered.

**Class C: Model Identity Verification**  
- **Fingerprint probes** — inputs designed to produce model-specific responses, verifying the model behind the API hasn't been silently swapped.
- **Weight-hash correlation** — when SHIELD weight audits are available, correlate behavioral observations with weight-space state.
- **Consistency probes** — same input across multiple requests should produce statistically consistent outputs. High variance suggests instability or model mixture.

```rust
struct HealthReport {
    /// Composite health score (0.0 = critical, 1.0 = nominal)
    score: f32,
    
    /// Individual signal assessments
    signals: Vec<SignalAssessment>,
    
    /// Drift detection results
    drift: DriftAssessment,
    
    /// Model identity confidence
    identity_confidence: f32,
    
    /// Recommendation
    action: HealthAction,
    
    /// Evidence for audit trail
    evidence: ProbeEvidence,
    
    /// Timestamp
    timestamp: Timestamp,
}

enum HealthAction {
    /// Model is healthy — no action needed
    Nominal,
    
    /// Minor drift detected — increase monitoring frequency
    IncreasedMonitoring { reason: String },
    
    /// Significant anomaly — alert operators
    Alert { severity: Severity, reason: String },
    
    /// Behavioral drift exceeds threshold — trigger SHIELD audit
    TriggerShieldAudit { evidence: ShieldTriggerEvidence },
    
    /// Model identity uncertain — halt and verify
    IdentityVerification { confidence: f32 },
    
    /// Critical health failure — recommend failover
    Failover { reason: String },
}
```

#### 5.5.3 Probe Types

| Probe | Frequency | Purpose | Invasiveness |
|---|---|---|---|
| **Canary** | Every N requests | Verify known-good input→output pairs | None (normal requests) |
| **Fingerprint** | Hourly | Confirm model identity | Minimal (single request) |
| **Distribution** | Continuous | Track output token distribution | None (passive observation) |
| **Consistency** | Every 6h | Same input → statistical consistency | Low (repeated request) |
| **Boundary** | Daily | Verify safety boundaries hold | Low (adversarial canary) |
| **Deep** | On anomaly | Comprehensive behavioral analysis | Medium (multi-probe sequence) |

#### 5.5.4 SHIELD Bridge

When SIGIL-PROBE detects behavioral anomalies that suggest model-level issues (not input-level attacks), it triggers a SHIELD audit:

```
SIGIL-PROBE detects:
  - Output distribution shift (KL-divergence > threshold)
  - Safety boundary regression (previously-blocked pattern succeeds)
  - Model identity uncertainty (fingerprint mismatch)
  
  ↓ generates ShieldTriggerEvidence
  
SHIELD receives:
  - Behavioral evidence from SIGIL-PROBE
  - Trigger classification (drift | safety | identity)
  - Temporal context (when did the anomaly begin)
  
  ↓ performs
  
SHIELD audit:
  - Weight-space forensics
  - Safety-alignment verification
  - Fine-tuning detection
  - Verdict: {clean | tampered | uncertain}
```

This creates a **closed-loop security posture**: SIGIL guards the input, SIGIL-PROBE monitors the model's behavior, and SHIELD verifies the model's integrity. An attacker would need to simultaneously evade all three to compromise the system.

#### 5.5.5 CLI — sigil probe

```bash
# Run canary probes against a model endpoint
$ sigil probe canary --endpoint https://api.example.com/v1 --baseline canary.json
Health Score: 0.97
Canary Pass Rate: 24/25
Drift: none detected

# Fingerprint a model
$ sigil probe fingerprint --endpoint https://api.example.com/v1
Model Identity: claude-3-opus (confidence: 0.94)
Consistency: high (σ = 0.02)

# Continuous monitoring mode
$ sigil probe monitor --endpoint https://api.example.com/v1 \
    --baseline baseline.json \
    --interval 60s \
    --shield-webhook https://shield.internal/trigger

# Generate health report
$ sigil probe report --from 2026-04-01 --to 2026-04-03
Health Score (avg): 0.95
Anomalies: 2
  [2026-04-02T14:23:00Z] Output entropy spike (resolved)
  [2026-04-02T18:45:00Z] Latency anomaly (ongoing)
SHIELD Triggers: 0
```

---

## 6. Performance Targets

| Metric | Target | Rationale |
|---|---|---|
| Throughput | ≥1M tokens/sec | Must not bottleneck inference |
| Latency overhead | <50μs per 1K tokens | Imperceptible at inference scale |
| Memory overhead | <2 MiB per instance | Embeddable in edge devices |
| Heap allocations (clean path) | 0 | Zero-alloc hot path for clean inputs |
| Cold start | <10ms | Viable as sidecar / serverless |
| WASM binary size | <500 KiB | Browser-embeddable |

### 6.1 Optimization Strategy

- **SIMD scanning** — vectorized pattern matching using `std::simd` (nightly) or manual NEON/AVX2 intrinsics
- **Aho-Corasick automaton** — multi-pattern matching in single pass for DLP + injection patterns
- **Arena allocation** — per-request arena for scan metadata, freed in bulk
- **Lazy evidence** — evidence bundles generated only when `Verdict != Allow`
- **Vocabulary precomputation** — merge tables loaded once, reused across requests

---

## 7. Threat Model

### 7.1 Attackers

| Profile | Capability | Goal |
|---|---|---|
| **Script kiddie** | Copy-paste injection templates | Jailbreak, extract system prompt |
| **Sophisticated user** | Unicode manipulation, encoding tricks | Bypass content policy |
| **Adversarial researcher** | Model internals knowledge, tokenizer exploitation | Demonstrate novel attacks |
| **Nation-state** | Custom tooling, supply chain access | Data exfiltration, model manipulation |

### 7.2 What SIGIL Defends Against

- Prompt injection (structural + semantic patterns)
- Data exfiltration via crafted outputs (DLP at input boundary)
- Unicode-based attacks (homoglyphs, invisible chars, BiDi overrides)
- Token-boundary exploitation (merge-seam smuggling)
- Encoded payload delivery (base64, hex, encoded blobs in natural language)

### 7.3 What SIGIL Does NOT Defend Against

- **Semantic-only attacks** — adversarial inputs that are linguistically valid and carry no structural anomaly. These require embedding-level or model-level detection.
- **Model-level vulnerabilities** — SHIELD's domain, not SIGIL's.
- **Side-channel attacks** — timing, power analysis, etc. Out of scope.
- **Authorized misuse** — a legitimately authenticated user misusing the system within their permissions.

SIGIL is one layer in a defense-in-depth stack, not a complete solution.

---

## 8. Research Contributions

SIGIL advances the state of the art in five ways:

1. **Tokenization as a security primitive** — the first formal treatment of the tokenizer as a governance boundary, not merely a compression algorithm.

2. **Token-level provenance tracking** — formal taint propagation from input segmentation through BPE merge, enabling provenance-aware model inference.

3. **Pre-merge DLP and injection detection** — pattern detection on the grapheme stream where structural patterns are intact, rather than on the post-tokenization embedding space where they are fragmented.

4. **MCP content security gate** — the first formal treatment of MCP tool responses as an untrusted input channel requiring token-level security analysis, with per-server trust profiles and cross-tool taint accumulation.

5. **Input-behavioral model health correlation** — using tokenizer-level input telemetry correlated with output distribution analysis to detect model drift, substitution, and safety boundary regression without requiring model internals access.

### 8.1 Positioning Against Literature

| Work | Relationship |
|---|---|
| BPE (Sennrich et al., 2016) | SIGIL wraps BPE; does not replace it |
| tiktoken (OpenAI) | SIGIL is vocabulary-compatible; adds security stage |
| Prompt injection taxonomies (Greshake et al., 2023) | SIGIL operationalizes detection at the token level |
| Indirect prompt injection (Greshake et al., 2023) | SIGIL's MCP gate directly addresses tool-response injection |
| MCP Specification (Anthropic, 2024) | SIGIL adds the security layer MCP lacks natively |
| Constitutional AI (Anthropic) | Complementary — Constitutional AI governs model behavior; SIGIL governs input |
| Proof-carrying code (Necula, 1997) | SIGIL's evidence bundles extend PCC to the tokenization boundary |
| NIST AI RMF | SIGIL addresses GOVERN and MAP functions at the input boundary |
| Model fingerprinting literature | SIGIL-PROBE extends fingerprinting into continuous health monitoring |

### 8.2 Publication Target

**Title:** "The Tokenizer is the First Firewall: Security-Native Lexical Analysis for LLM Systems"  
**Venue:** ArXiv preprint → USENIX Security / IEEE S&P submission  
**Timeline:** Q3 2026  
**Position:** Paper #6 in the Ckodex decomposition sequence

---

## 9. Project Structure

```
ckodex-labs/sigil/
├── Cargo.toml
├── crates/
│   ├── sigil-core/             # Core library (five-stage pipeline, receipts, signing)
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── intake.rs       # Stage 1: byte → grapheme (per-cluster normalization, strip)
│   │   │   ├── taint.rs        # Stage 2: provenance tagging
│   │   │   ├── scan/
│   │   │   │   └── mod.rs      # Stage 3: injection, DLP, entropy, smuggling, firewall
│   │   │   ├── merge.rs        # Stage 4: security-aware BPE + boundary findings
│   │   │   ├── emit.rs         # Stage 5: annotated output + evidence gating
│   │   │   ├── engine.rs       # Sigil engine (digests, receipt construction)
│   │   │   ├── signing.rs      # ReceiptSigner port + ECDSA P-384 adapter
│   │   │   ├── policy.rs       # Policy configuration
│   │   │   ├── evidence.rs     # Evidence bundle generation
│   │   │   ├── vocab.rs        # Vocabulary abstraction + token-range remapping
│   │   │   ├── parallel.rs     # TokenizerActor (rayon batch)
│   │   │   ├── tokenizer_ffi.rs# Zig tokenizer bridge
│   │   │   ├── error.rs        # Error types
│   │   │   └── types.rs        # Core types
│   │   ├── tests/
│   │   │   └── conformance_vectors.rs  # CV-RIC-001..008
│   │   └── Cargo.toml
│   ├── sigil-mcp/              # MCP security gate
│   ├── sigil-multimodal/       # SIGIL-M: modality channels + fusion-boundary auditor
│   ├── sigil-probe/            # Model health query engine
│   ├── sigil-s/                # Semantic sentinel companion
│   ├── sigil-server/           # Sidecar composition façade
│   └── sigil-cli/              # Operator and CI entrypoint
├── bindings/
│   ├── go/                     # cgo bindings + sigil-bench command
│   └── python/                 # PyO3 bindings (pysigil)
├── patterns/
│   ├── injection.toml          # Injection grammar patterns
│   ├── injection-mcp.toml      # MCP-specific injection patterns
│   ├── dlp-pci.toml            # PCI-DSS patterns
│   ├── dlp-pii.toml            # PII patterns
│   └── dlp-secrets.toml        # API key / secret patterns
├── probes/
│   ├── canary-default.json     # Default canary probe set
│   ├── fingerprint-claude.json # Claude model fingerprint probes
│   ├── fingerprint-gpt.json    # GPT model fingerprint probes
│   └── boundary-safety.json    # Safety boundary test probes
├── tests/
│   ├── adversarial/            # Adversarial input corpus
│   ├── dlp/                    # DLP test cases
│   ├── injection/              # Injection detection tests
│   ├── mcp/                    # MCP security gate tests
│   ├── probe/                  # Model health probe tests
│   └── integration/            # End-to-end pipeline tests
├── docs/
│   ├── TRAJECTORY.md           # Maintained engineering trajectory and work queue
│   ├── RIC-CONTRACT.md         # Representation Integrity Contract (RIC-R-1..8)
│   ├── RIC-DELTA-ANALYSIS.md   # Design critique + defect ledger (D-1..D-9)
│   ├── ARCHITECTURE.md         # Detailed architecture
│   ├── MCP-SECURITY.md         # MCP security gate deep dive
│   ├── PROBE-GUIDE.md          # Model health monitoring guide
│   └── THREAT-MODEL.md         # Extended threat model
├── formal/
│   ├── SigilPipeline.tla       # Pipeline FSM specification
│   ├── SigilSafety.tla         # Safety invariants (INV-001..007)
│   ├── SigilMcpSafety.tla      # MCP invariants (INV-MCP-001..006)
│   ├── TaintAlgebra.tla        # Taint semilattice + proofs
│   ├── SigilLiveness.tla       # Liveness properties (LIVE-001..006)
│   ├── SigilValanceComp.tla    # Composition proofs (COMP-001..005)
│   ├── ProbeSafety.tla         # PROBE health invariants
│   └── MC/                     # TLC model checker configs
│       ├── pipeline.cfg
│       ├── mcp.cfg
│       └── composition.cfg
└── bench/
    ├── corpus/                 # Benchmark corpora
    └── results/                # Benchmark baselines
```

> `sigil-ffi` (C ABI `libsigil`) and `sigil.wasm` ship as build targets
> rather than feature crates — see §4 Delivery Artifacts. A dedicated
> `sigil-bench` crate remains planned. Executable conformance vectors live at
> `crates/sigil-core/tests/conformance_vectors.rs` (CV-RIC-001..008), not
> under `formal/`.

---

## 10. Formal Verification

SIGIL's security guarantees must be machine-checkable, not aspirational. This section specifies the formal properties that SIGIL implementations must satisfy, expressed as TLA+ invariants and temporal logic assertions. These properties are the contract between the specification and any conforming implementation.

### 10.1 Pipeline State Machine

The SIGIL pipeline is a deterministic finite state machine. Each input transitions through exactly five stages in strict order. No stage may be skipped, reordered, or revisited.

```tla+
--------------------------- MODULE SigilPipeline ---------------------------

CONSTANTS
    MaxInputBytes,          \* Maximum input size (configurable)
    MaxTokens,              \* Maximum output token count
    Severities,             \* {None, Low, Medium, High, Critical}
    Verdicts,               \* {Allow, Flag, Deny}
    Provenances,            \* {System, User, Tool, Retrieval, Generated, McpTool, McpContext, Unknown}
    TrustLevels             \* {Untrusted, Bounded, Trusted, Privileged}

VARIABLES
    stage,                  \* Current pipeline stage
    input,                  \* Raw input bytes
    graphemes,              \* Grapheme cluster sequence (after Intake)
    tainted,                \* Tainted grapheme sequence (after Taint)
    scanned,                \* Scan results (after Scan)
    merged,                 \* Merged token sequence (after Merge)
    output,                 \* Final annotated output (after Emit)
    evidence                \* Evidence bundle

Stages == {"Init", "Intake", "Taint", "Scan", "Merge", "Emit", "Complete"}

TypeInvariant ==
    /\ stage \in Stages
    /\ \A g \in graphemes : g.byte_offset \in Nat
    /\ \A t \in tainted : t.provenance \in Provenances
    /\ \A t \in tainted : t.trust_level \in TrustLevels
    /\ \A s \in scanned : s.severity \in Severities
    /\ output.verdict \in Verdicts

Init ==
    /\ stage = "Init"
    /\ input \in SUBSET Byte
    /\ Len(input) <= MaxInputBytes
    /\ graphemes = <<>>
    /\ tainted = <<>>
    /\ scanned = <<>>
    /\ merged = <<>>
    /\ output = NoOutput
    /\ evidence = NoEvidence

\* Stage transitions are strictly sequential
IntakeStep ==
    /\ stage = "Init"
    /\ stage' = "Intake"
    /\ graphemes' = NormalizeToGraphemes(input)
    /\ UNCHANGED <<input, tainted, scanned, merged, output, evidence>>

TaintStep ==
    /\ stage = "Intake"
    /\ stage' = "Taint"
    /\ tainted' = ApplyProvenance(graphemes)
    /\ UNCHANGED <<input, graphemes, scanned, merged, output, evidence>>

ScanStep ==
    /\ stage = "Taint"
    /\ stage' = "Scan"
    /\ scanned' = RunDetectors(tainted)
    /\ UNCHANGED <<input, graphemes, tainted, merged, output, evidence>>

MergeStep ==
    /\ stage = "Scan"
    /\ stage' = "Merge"
    /\ merged' = SecurityAwareMerge(scanned)
    /\ UNCHANGED <<input, graphemes, tainted, scanned, output, evidence>>

EmitStep ==
    /\ stage = "Merge"
    /\ stage' = "Emit"
    /\ output' = GenerateOutput(merged)
    /\ evidence' = IF output'.verdict /= "Allow"
                   THEN GenerateEvidence(merged, output')
                   ELSE NoEvidence
    /\ UNCHANGED <<input, graphemes, tainted, scanned, merged>>

CompleteStep ==
    /\ stage = "Emit"
    /\ stage' = "Complete"
    /\ UNCHANGED <<input, graphemes, tainted, scanned, merged, output, evidence>>

Next ==
    \/ IntakeStep
    \/ TaintStep
    \/ ScanStep
    \/ MergeStep
    \/ EmitStep
    \/ CompleteStep

Spec == Init /\ [][Next]_vars

==========================================================================
```

### 10.2 Safety Invariants

Seven machine-checkable safety invariants that any conforming SIGIL implementation must maintain. These are the hard guarantees.

```tla+
--------------------------- MODULE SigilSafety ----------------------------

\* INV-001: Stage ordering — pipeline stages execute in strict sequence
\* No stage may be skipped, reordered, or revisited
StageOrdering ==
    /\ (stage = "Intake")  => (stage' \in {"Taint"})
    /\ (stage = "Taint")   => (stage' \in {"Scan"})
    /\ (stage = "Scan")    => (stage' \in {"Merge"})
    /\ (stage = "Merge")   => (stage' \in {"Emit"})
    /\ (stage = "Emit")    => (stage' \in {"Complete"})
    \* No backward transitions exist
    /\ ~(stage = "Scan"   /\ stage' = "Intake")
    /\ ~(stage = "Merge"  /\ stage' = "Taint")
    /\ ~(stage = "Emit"   /\ stage' = "Scan")
    /\ ~(stage = "Complete" /\ stage' \in Stages \ {"Complete"})

\* INV-002: Taint monotonicity (anti-dilution theorem)
\* Once a grapheme is tainted at severity S, no subsequent operation
\* may reduce its severity. Taint only increases or holds.
TaintMonotonicity ==
    \A i \in 1..Len(scanned) :
        scanned[i].severity >= tainted[i].initial_severity

\* Extended: across composition with other tainted sequences
TaintCompositionMonotonicity ==
    \A a, b \in TaintedSequence :
        MaxSeverity(Compose(a, b)) >= Max(MaxSeverity(a), MaxSeverity(b))

\* INV-003: Verdict determinism
\* The same input with the same policy MUST produce the same verdict.
\* SIGIL is a pure function from (input, policy) → (output, evidence).
VerdictDeterminism ==
    \A i1, i2 \in Input, p \in Policy :
        (i1 = i2) => (Verdict(i1, p) = Verdict(i2, p))

\* INV-004: Provenance completeness
\* Every grapheme in the tainted sequence MUST have a provenance tag.
\* No grapheme may reach the Scan stage without provenance.
ProvenanceCompleteness ==
    \A g \in tainted : g.provenance /= Unset

\* INV-005: Critical verdict enforcement
\* If any detector returns Critical severity, the final verdict MUST be Deny.
\* No policy configuration may override a Critical finding.
CriticalEnforcement ==
    (\E s \in scanned : s.severity = "Critical") => (output.verdict = "Deny")

\* INV-006: Evidence completeness on non-Allow
\* If the verdict is Flag or Deny, an evidence bundle MUST be generated.
\* Evidence bundles are never generated for Allow verdicts (lazy evidence).
\* (Policy-gated exception: emit.evidence_mode = "always" attests every
\* admission, including Allow — a deliberate deployment trade of the
\* laziness performance property for always-on evidence. Default stays lazy.
\* Pinned by conformance vector CV-RIC-007.)
EvidenceCompleteness ==
    /\ (output.verdict \in {"Flag", "Deny"}) => (evidence /= NoEvidence)
    /\ (output.verdict = "Allow") => (evidence = NoEvidence)

\* INV-007: Byte-range traceability
\* Every token in the output MUST map back to a contiguous byte range
\* in the original input. No token may exist without provenance to source bytes.
\* (Held against RAW input: per-cluster normalization keeps ranges raw-accurate
\* even when normalization changes byte length; enforced by conformance
\* vectors CV-RIC-005 in crates/sigil-core/tests/conformance_vectors.rs.)
ByteRangeTraceability ==
    \A t \in output.token_ids :
        /\ t.byte_range.start >= 0
        /\ t.byte_range.end <= Len(input)
        /\ t.byte_range.start < t.byte_range.end

==========================================================================
```

### 10.3 MCP Security Invariants

Formal properties specific to the MCP security gate. These ensure that tool-response content is never injected into the model context without security analysis.

```tla+
--------------------------- MODULE SigilMcpSafety -------------------------

CONSTANTS
    McpServers,             \* Set of known MCP server identifiers
    TokenBudgets            \* Per-server token budget map

VARIABLES
    server_trust,           \* Per-server trust profile
    accumulated_taint,      \* Cross-tool taint accumulation state
    mcp_evidence            \* Per-server evidence trail

\* INV-MCP-001: No unscanned MCP content
\* Every byte of MCP server response MUST pass through the SIGIL scan
\* pipeline before injection into the model context. No bypass path exists.
NoUnscannedMcpContent ==
    \A response \in McpResponses :
        response.injected_into_context => response.sigil_scanned

\* INV-MCP-002: Trust level monotonicity within session
\* A server's effective trust level within a single session can only
\* decrease (or hold), never increase. Trust degradation is irreversible
\* within session scope.
McpTrustMonotonicity ==
    \A s \in McpServers :
        server_trust'[s] <= server_trust[s]

\* INV-MCP-003: Cross-tool taint accumulation
\* When content from multiple MCP servers is composed, the resulting
\* taint level is at least as severe as the maximum component taint.
\* Taint accumulates; it never dilutes through composition.
CrossToolTaintAccumulation ==
    \A s1, s2 \in McpServers :
        LET combined == ComposeTaint(accumulated_taint[s1], accumulated_taint[s2])
        IN combined.severity >= Max(accumulated_taint[s1].severity,
                                     accumulated_taint[s2].severity)

\* INV-MCP-004: Token budget enforcement
\* No single MCP server response may consume more tokens than its
\* allocated budget. Responses exceeding budget are truncated + flagged.
McpTokenBudgetEnforcement ==
    \A s \in McpServers :
        TokenCount(s.current_response) <= TokenBudgets[s]

\* INV-MCP-005: Schema conformance
\* If a server declares a response schema, every response from that
\* server MUST validate against the schema. Schema violations produce
\* a Flag or Deny verdict (configurable).
McpSchemaConformance ==
    \A s \in McpServers, r \in s.responses :
        (s.declared_schema /= Null) =>
            (ValidatesAgainst(r, s.declared_schema) \/ r.verdict \in {"Flag", "Deny"})

\* INV-MCP-006: Evidence trail completeness
\* Every MCP content flow through SIGIL generates an evidence record.
\* No MCP interaction may occur without an attestable audit entry.
McpEvidenceCompleteness ==
    \A s \in McpServers, r \in s.responses :
        r.sigil_scanned => (\E e \in mcp_evidence : e.server_id = s /\ e.response_hash = Hash(r))

==========================================================================
```

### 10.4 Taint Algebra

The taint system forms a bounded join-semilattice. This algebraic structure guarantees that taint composition is well-defined, associative, commutative, and monotone — properties essential for correctness in multi-source and multi-modal contexts.

```
Severity lattice:
    None < Low < Medium < High < Critical

    join(a, b) = max(a, b)

Properties:
    Associativity:  join(join(a, b), c) = join(a, join(b, c))
    Commutativity:  join(a, b) = join(b, a)
    Idempotency:    join(a, a) = a
    Identity:       join(a, None) = a
    Absorption:     join(a, Critical) = Critical

    Bottom element: None
    Top element:    Critical
```

```tla+
--------------------------- MODULE TaintAlgebra ---------------------------

\* The taint join operation
TaintJoin(a, b) ==
    CASE a = "Critical" \/ b = "Critical" -> "Critical"
      [] a = "High"     \/ b = "High"     -> "High"
      [] a = "Medium"   \/ b = "Medium"   -> "Medium"
      [] a = "Low"      \/ b = "Low"      -> "Low"
      [] OTHER                             -> "None"

\* PROOF-001: Anti-dilution theorem
\* For any taint values a1, a2: join(a1, a2) >= max(a1, a2)
\* This is the core guarantee: combining tainted content never
\* produces a result less severe than the worst input.
AntiDilutionTheorem ==
    \A a1, a2 \in Severities :
        SeverityOrd(TaintJoin(a1, a2)) >= Max(SeverityOrd(a1), SeverityOrd(a2))

\* PROOF-002: Taint propagation through BPE merge
\* When two tainted graphemes are merged into a single token,
\* the resulting token's taint is the join of both graphemes' taints.
MergeTaintPropagation ==
    \A g1, g2 \in TaintedGraphemes :
        LET merged_token == BpeMerge(g1, g2)
        IN merged_token.severity = TaintJoin(g1.severity, g2.severity)

\* PROOF-003: Cross-boundary merge suppression
\* When two graphemes have different provenances (e.g., System and User),
\* and merge suppression is enabled, the BPE merge MUST NOT combine them.
CrossBoundaryMergeSuppression ==
    \A g1, g2 \in TaintedGraphemes :
        (policy.suppress_cross_boundary /\ g1.provenance /= g2.provenance)
        => ~CanMerge(g1, g2)

\* PROOF-004: Cross-modal taint propagation
\* When a non-text modality produces content that is detected as
\* text-equivalent (OCR in images, speech in audio), the taint
\* from that detection propagates to the text taint channel.
CrossModalTaintPropagation ==
    \A detection \in {OcrDetection, SpeechDetection, PolyglotDetection} :
        detection.found => (text_taint' = TaintJoin(text_taint, detection.severity))

\* PROOF-005: Provenance downgrade prohibition
\* A grapheme's provenance cannot be promoted to a more trusted level.
\* McpTool cannot become System. User cannot become System.
\* Unknown can only remain Unknown or be downgraded to Untrusted.
ProvenanceDowngradeProhibition ==
    \A g \in TaintedGraphemes :
        TrustOrd(g.trust_level') <= TrustOrd(g.trust_level)

==========================================================================
```

### 10.5 Liveness Properties

Safety invariants guarantee that bad things never happen. Liveness properties guarantee that good things eventually happen. Both are necessary for a complete specification.

```tla+
--------------------------- MODULE SigilLiveness --------------------------

\* LIVE-001: Pipeline completion
\* Every input that enters the pipeline MUST eventually reach the
\* Complete stage. The pipeline cannot stall indefinitely.
PipelineCompletion ==
    \A i \in Input :
        (stage = "Init" /\ input = i) ~> (stage = "Complete")

\* LIVE-002: Verdict emission
\* Every completed pipeline run MUST emit exactly one verdict.
\* The system cannot silently drop an input without producing a decision.
VerdictEmission ==
    (stage = "Complete") => (output.verdict \in {"Allow", "Flag", "Deny"})

\* LIVE-003: Evidence generation on threat
\* If any detector fires at severity >= Medium, evidence MUST
\* eventually be generated and persisted before pipeline completion.
EvidenceOnThreat ==
    (\E s \in scanned : SeverityOrd(s.severity) >= SeverityOrd("Medium"))
    ~> (evidence /= NoEvidence /\ evidence.persisted = TRUE)

\* LIVE-004: PROBE health convergence
\* The health score MUST converge to a stable value within a bounded
\* observation window. Unbounded oscillation indicates a bug.
ProbeHealthConvergence ==
    \E window \in Nat :
        \A t1, t2 \in TimeSteps :
            (t2 - t1 > window) =>
                Abs(health_score[t2] - health_score[t1]) < epsilon

\* LIVE-005: SHIELD trigger on critical drift
\* If SIGIL-PROBE detects behavioral drift exceeding the critical
\* threshold, a SHIELD audit MUST eventually be triggered.
ShieldTriggerOnDrift ==
    (probe.drift_score > CRITICAL_THRESHOLD) ~> (shield.audit_triggered = TRUE)

\* LIVE-006: MCP evidence persistence
\* Every MCP evidence record MUST eventually be persisted to the
\* evidence store. Transient failures trigger retry with backoff.
McpEvidencePersistence ==
    \A e \in mcp_evidence :
        (e.generated = TRUE) ~> (e.persisted = TRUE)

==========================================================================
```

### 10.6 Composition Proofs — SIGIL × Valance

When SIGIL composes with Valance, the combined system must satisfy properties that neither satisfies alone. These composition proofs establish the contract at the SIGIL-Valance boundary.

```tla+
------------------------- MODULE SigilValanceComposition -------------------

CONSTANTS
    ValanceSlots,           \* VS-001..VS-020
    ShellConstructs         \* Set of shell-context constructs

\* COMP-001: Taint-to-radical bridge
\* If SIGIL marks any token with severity >= Medium AND that token
\* appears in a Valance shell execution context, the Valance binding
\* MUST evaluate to radical (deny). This is the anti-dilution theorem
\* projected across the SIGIL-Valance boundary.
TaintToRadicalBridge ==
    \A token \in output.token_ids :
        /\ token.annotation.threat.severity >= "Medium"
        /\ token \in ValanceShellContext
        => ValanceDecision(token) = "radical"

\* COMP-002: Provenance-aware binding
\* Valance bindings that reference tokens with McpTool or McpContext
\* provenance MUST apply the MCP trust profile as an additional
\* constraint on the Valance evaluation.
ProvenanceAwareBinding ==
    \A binding \in ValanceBindings :
        (\E token \in binding.tokens : token.provenance \in {"McpTool", "McpContext"})
        => binding.mcp_trust_applied = TRUE

\* COMP-003: Evidence chain continuity
\* The evidence chain from SIGIL → Valance MUST be unbroken.
\* Every Valance decision that references SIGIL-tainted tokens
\* MUST include the SIGIL evidence hash in its own evidence bundle.
EvidenceChainContinuity ==
    \A vd \in ValanceDecisions :
        (\E token \in vd.referenced_tokens : token.annotation.threat.severity >= "Low")
        => (vd.evidence.sigil_hash /= Null)

\* COMP-004: Verdict consistency
\* If SIGIL issues a Deny verdict, no downstream component (including
\* Valance) may override it to Allow. SIGIL Deny is terminal.
SigilDenyIsTerminal ==
    (output.verdict = "Deny") => ~(\E downstream : downstream.verdict = "Allow")

\* COMP-005: Sentinel-Valance composition (Paper #8)
\* When the security sentinel is active, Valance bindings receive
\* both SIGIL structural assessment AND sentinel semantic assessment.
\* The composition follows the verdict composition rules:
\*   SIGIL Critical              → Deny (always, regardless of sentinel)
\*   Sentinel High + SIGIL Medium → Deny
\*   Sentinel Medium + SIGIL None → Flag
\*   Both None                   → Allow
\*   Disagreement                → Flag + training signal
SentinelValanceComposition ==
    \A decision \in GateDecisions :
        /\ (decision.sigil = "Critical") => (decision.final = "Deny")
        /\ (decision.sentinel = "High" /\ decision.sigil = "Medium")
                                         => (decision.final = "Deny")
        /\ (decision.sentinel = "Medium" /\ decision.sigil = "None")
                                         => (decision.final = "Flag")
        /\ (decision.sentinel = "None" /\ decision.sigil = "None")
                                         => (decision.final = "Allow")

==========================================================================
```

### 10.7 PROBE Health Invariants

Formal properties of the model health monitoring subsystem. These ensure that PROBE's observations are statistically sound and its triggers are well-calibrated.

```tla+
--------------------------- MODULE ProbeSafety ----------------------------

CONSTANTS
    CanarySet,              \* Set of canary probe input-output pairs
    DriftThresholds,        \* {nominal, watch, alert, critical, failover}
    FingerPrintSet           \* Model fingerprint probes

VARIABLES
    health_score,           \* Current composite health score [0.0, 1.0]
    drift_score,            \* Current drift magnitude
    identity_confidence,    \* Model identity confidence [0.0, 1.0]
    baseline                \* Statistical baseline for comparisons

\* INV-PROBE-001: Health score boundedness
\* The health score is always in [0.0, 1.0]. No computation may
\* produce a value outside this range.
HealthScoreBounded ==
    /\ health_score >= 0.0
    /\ health_score <= 1.0

\* INV-PROBE-002: Monotone response to anomalies
\* As detected anomalies increase, the health score MUST decrease
\* (or hold). More anomalies cannot improve health.
MonotoneAnomalyResponse ==
    (anomaly_count' > anomaly_count) => (health_score' <= health_score)

\* INV-PROBE-003: Canary probe integrity
\* Canary probes MUST use inputs that are indistinguishable from
\* normal traffic. The model under test cannot detect that it is
\* being probed based on input characteristics alone.
CanaryProbeIndistinguishability ==
    \A canary \in CanarySet :
        StatisticallyIndistinguishable(canary.input, NormalTrafficDistribution)

\* INV-PROBE-004: Baseline freshness
\* The statistical baseline MUST be refreshed at least every
\* baseline_ttl period. Stale baselines produce false positives.
BaselineFreshness ==
    (CurrentTime - baseline.last_updated) <= baseline_ttl

\* INV-PROBE-005: Trigger threshold ordering
\* Thresholds must be strictly ordered:
\*   nominal < watch < alert < critical < failover
\* No threshold inversion is permitted.
ThresholdOrdering ==
    DriftThresholds.nominal < DriftThresholds.watch
    /\ DriftThresholds.watch < DriftThresholds.alert
    /\ DriftThresholds.alert < DriftThresholds.critical
    /\ DriftThresholds.critical < DriftThresholds.failover

\* INV-PROBE-006: No false SHIELD triggers on transient anomalies
\* A SHIELD audit trigger requires sustained anomaly detection
\* across at least min_sustained_window consecutive observations.
\* Single-observation spikes MUST NOT trigger SHIELD.
NoTransientShieldTrigger ==
    shield.audit_triggered =>
        (\A t \in (CurrentTime - min_sustained_window)..CurrentTime :
            drift_score_at[t] > DriftThresholds.critical)

\* INV-PROBE-007: Sentinel self-monitoring (Paper #8)
\* The security sentinel itself is monitored by PROBE.
\* If sentinel health degrades below sentinel_min_health,
\* the system falls back to SIGIL structural analysis only.
SentinelSelfMonitoring ==
    (sentinel_health < sentinel_min_health)
    => (active_defense_mode = "structural_only")

==========================================================================
```

### 10.8 Conformance Vectors

Eleven conformance vectors that map formal properties to testable implementation requirements. Each vector has a unique identifier, references the invariants it validates, and specifies the verification method.

| Vector | Property | Invariants | Verification Method |
|---|---|---|---|
| CV-S-001 | Pipeline stage ordering | INV-001 | Unit test: assert stage transitions match FSM |
| CV-S-002 | Taint anti-dilution | INV-002, PROOF-001, PROOF-002 | Property-based test: random taint compositions never decrease |
| CV-S-003 | Verdict determinism | INV-003 | Fuzz test: same input + policy → same verdict across 10K runs |
| CV-S-004 | Provenance completeness | INV-004 | Static analysis: no code path reaches Scan without provenance |
| CV-S-005 | Critical enforcement | INV-005 | Integration test: Critical finding → Deny, regardless of policy |
| CV-S-006 | Evidence completeness | INV-006 | Property-based test: Flag/Deny always produces evidence |
| CV-S-007 | Byte-range traceability | INV-007 | Round-trip test: every output token maps to valid input range |
| CV-S-008 | MCP no-bypass | INV-MCP-001 | Architecture test: no code path injects MCP content unscanned |
| CV-S-009 | Cross-tool taint accumulation | INV-MCP-003, PROOF-004 | Property-based test: multi-server composition never dilutes |
| CV-S-010 | Taint-to-radical bridge | COMP-001 | Integration test with Valance: tainted shell context → deny |
| CV-S-011 | PROBE no-transient trigger | INV-PROBE-006 | Simulation: inject single-spike anomalies, assert no SHIELD trigger |

### 10.9 Verification Toolchain

```
Verification stack:

  ┌─────────────────────────────────────────────────────────┐
  │  TLA+ / TLC model checker                               │
  │  — Exhaustive state-space exploration for finite models │
  │  — Validates INV-001..007, INV-MCP-001..006             │
  │  — Validates LIVE-001..006                              │
  └─────────────────┬───────────────────────────────────────┘
                    │
  ┌─────────────────┴───────────────────────────────────────┐
  │  proptest / quickcheck (Rust)                            │
  │  — Property-based testing for algebraic properties       │
  │  — Validates PROOF-001..005, taint algebra axioms       │
  │  — 100K+ random inputs per property                     │
  └─────────────────┬───────────────────────────────────────┘
                    │
  ┌─────────────────┴───────────────────────────────────────┐
  │  cargo-fuzz + AFL                                        │
  │  — Fuzz testing for crash safety and verdict determinism │
  │  — Validates CV-S-003 (determinism under adversarial     │
  │    input), panic-freedom, OOM-freedom                    │
  └─────────────────┬───────────────────────────────────────┘
                    │
  ┌─────────────────┴───────────────────────────────────────┐
  │  Integration test harness                                │
  │  — End-to-end pipeline tests with known adversarial     │
  │    corpora                                               │
  │  — SIGIL × Valance composition tests (CV-S-010)         │
  │  — MCP proxy interception tests (CV-S-008)              │
  └─────────────────┬───────────────────────────────────────┘
                    │
  ┌─────────────────┴───────────────────────────────────────┐
  │  CI gate                                                 │
  │  — All conformance vectors MUST pass before merge        │
  │  — TLA+ model check runs nightly (state space too large │
  │    for per-commit)                                       │
  │  — Property tests and fuzz tests run per-commit          │
  └─────────────────────────────────────────────────────────┘
```

### 10.10 Formal Verification CLI

```bash
# Run TLA+ model check on pipeline FSM
$ sigil verify --module SigilPipeline --invariants all
Checking INV-001 (StageOrdering)............ PASS
Checking INV-002 (TaintMonotonicity)........ PASS
Checking INV-003 (VerdictDeterminism)....... PASS
Checking INV-004 (ProvenanceCompleteness)... PASS
Checking INV-005 (CriticalEnforcement)...... PASS
Checking INV-006 (EvidenceCompleteness)..... PASS
Checking INV-007 (ByteRangeTraceability).... PASS
States explored: 847,293
Time: 4.2s

# Run property-based tests on taint algebra
$ sigil verify --module TaintAlgebra --proofs all --iterations 100000
Checking PROOF-001 (AntiDilution)........... PASS (100000/100000)
Checking PROOF-002 (MergePropagation)....... PASS (100000/100000)
Checking PROOF-003 (BoundarySuppression).... PASS (100000/100000)
Checking PROOF-004 (CrossModalPropagation).. PASS (100000/100000)
Checking PROOF-005 (ProvenanceDowngrade).... PASS (100000/100000)

# Run MCP invariant checks
$ sigil verify --module SigilMcpSafety --invariants all
Checking INV-MCP-001 (NoUnscannedContent)... PASS
Checking INV-MCP-002 (TrustMonotonicity).... PASS
Checking INV-MCP-003 (TaintAccumulation).... PASS
Checking INV-MCP-004 (TokenBudget).......... PASS
Checking INV-MCP-005 (SchemaConformance).... PASS
Checking INV-MCP-006 (EvidenceComplete)..... PASS

# Run composition proofs (requires Valance)
$ sigil verify --module SigilValanceComposition --proofs all
Checking COMP-001 (TaintToRadical).......... PASS
Checking COMP-002 (ProvenanceBinding)....... PASS
Checking COMP-003 (EvidenceChain)........... PASS
Checking COMP-004 (DenyIsTerminal).......... PASS
Checking COMP-005 (SentinelComposition)..... PASS

# Full conformance report
$ sigil verify --all --report json > conformance-report.json
```

---

## 11. Version History

| Version | Date | Changes |
|---|---|---|
| 0.1.0 | 2026-04-03 | Initial specification |
| 0.2.0 | 2026-04-03 | Added MCP Security Gate (§5.4), Model Health Query / SIGIL-PROBE (§5.5), expanded Provenance enum, updated project structure |
| 0.3.0 | 2026-04-04 | Added Formal Verification (§10): TLA+ pipeline FSM, 7 safety invariants, 6 MCP invariants, taint algebra with 5 proofs, 6 liveness properties, 5 SIGIL×Valance composition proofs, 7 PROBE health invariants, 11 conformance vectors, verification toolchain |

---

*SIGIL is a component of the Ckodex ecosystem. It is designed to be independently deployable and useful outside of Ckodex, while composing naturally with Valance, SHIELD, and the Ckodex Containment Plane.*

```
                    The Ckodex Security Triad
                    
         SIGIL ←——————————→ SHIELD
     (input boundary)    (model integrity)
          ↑    ╲              ╱    ↑
          │     ╲            ╱     │
          │      SIGIL-PROBE      │
          │    (behavioral bridge) │
          │                        │
          └──── Valance ───────────┘
            (execution boundary)

  "Guard the input. Verify the model. Govern the action."
```

*"Every model has a front door. SIGIL is the lock."*
