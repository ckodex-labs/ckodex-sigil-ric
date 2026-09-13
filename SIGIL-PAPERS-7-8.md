# SIGIL Extended Papers — Outlines

---

## Paper #7: SIGIL-M — Multimodal Security Tokenization

### Working Title
**"Beyond Text: Security-Native Tokenization for Multimodal AI Systems"**

Alternative: *"Every Encoder is an Attack Surface: Multimodal Tokenization as a Security Boundary"*

### Thesis (one sentence)
Multimodal encoders (vision, audio, video, code) are untreated security boundaries where modality-specific adversarial payloads bypass text-focused defenses entirely, and a security-native multimodal tokenization framework can detect cross-modal injection, steganographic exfiltration, and adversarial perturbations before encoding.

### The Gap

| Modality | Encoder | Security Treatment | Known Attacks |
|---|---|---|---|
| Text | BPE / SentencePiece | SIGIL addresses this | Prompt injection, Unicode tricks |
| Vision | ViT patch tokenizer | **None** | Text-in-image injection, adversarial patches, steganography |
| Audio | Whisper / wav2vec | **None** | Adversarial audio commands, ultrasonic injection, hidden speech |
| Video | Frame sampling + ViT | **None** | Temporal injection (single-frame attacks), motion-encoded payloads |
| Code | AST tokenizers | **None** | Polyglot payloads, comment injection, encoding tricks |
| Documents | OCR + layout | **None** | Layout manipulation, invisible text layers, font substitution |

Every modality has its own encoding pipeline, and none of them are designed as security boundaries. The text tokenizer is just the one we noticed first.

### Core Contributions

**C1: Cross-Modal Injection Taxonomy**
A formal taxonomy of attacks that exploit modality boundaries:
- **Text-in-image injection** — instructions rendered as text in images bypass all text-level filters
- **Audio command injection** — adversarial audio that encodes instructions inaudible to humans
- **Cross-modal smuggling** — payload split across modalities (half in text, half in image) that only becomes coherent post-encoding
- **Steganographic exfiltration** — data encoded in image/audio channels invisible to human inspection
- **Temporal injection** — single frames in video containing adversarial content

**C2: Modality-Specific Security Stages**
Extension of SIGIL's 5-stage pipeline to non-text modalities:

```
SIGIL-M Pipeline (per modality)

Vision:
  Pixel Intake → Patch Taint → Visual Scan → Encode → Annotated Patches
                                    │
                    ┌───────────────┼───────────────┐
                    ↓               ↓               ↓
              OCR Detection   Stego Analysis   Adversarial
             (text in image) (hidden payloads)  Perturbation
                                                 Detection

Audio:
  Waveform Intake → Segment Taint → Audio Scan → Encode → Annotated Frames
                                        │
                         ┌──────────────┼──────────────┐
                         ↓              ↓              ↓
                   Speech Detect   Ultrasonic     Adversarial
                  (hidden commands) Analysis      Audio Detection

Code:
  Source Intake → AST Taint → Code Scan → Tokenize → Annotated Tokens
                                  │
                    ┌─────────────┼─────────────┐
                    ↓             ↓             ↓
              Polyglot       Comment        Encoding
              Detection    Injection       Exploit
                          Detection       Detection
```

**C3: Cross-Modal Taint Propagation**
When multiple modalities are present in a single request, taint must propagate *across* modalities:
- If SIGIL-M detects text-in-image that matches injection patterns → taint propagates to the text stream
- If audio contains speech that matches instruction patterns → taint propagates to the prompt context
- Cross-modal taint is always **additive** — consistent with SIGIL's anti-dilution principle

**C4: Unified Threat Assessment**
A single `InputAssessment` that aggregates findings across all modalities:
```rust
struct MultimodalAssessment {
    text: Option<SigilOutput>,           // SIGIL core
    vision: Option<VisionAssessment>,    // SIGIL-M vision
    audio: Option<AudioAssessment>,      // SIGIL-M audio
    code: Option<CodeAssessment>,        // SIGIL-M code
    cross_modal: CrossModalAssessment,   // Cross-modal correlation
    verdict: Verdict,                    // Unified Allow/Flag/Deny
}
```

### Positioning
- Extends SIGIL's "tokenizer as firewall" thesis to all modalities
- Directly addresses the image-based prompt injection attacks demonstrated against GPT-4V and Claude
- Novel contribution: cross-modal taint propagation is not addressed in any existing work
- Positions against: adversarial robustness literature (Goodfellow et al.), multimodal safety (Schlarmann & Hein 2023)

### Venue
ArXiv preprint → NeurIPS or ICML workshop on AI safety / adversarial ML

### Timeline
Q4 2026 — after SIGIL core paper establishes the foundational argument

### Relationship to SIGIL
SIGIL-M is an **extension crate** (`sigil-multimodal` or `sigil-vision`, `sigil-audio`) that adds modality-specific stages. It depends on `sigil-core` for the taint type system, evidence generation, and policy framework.

---

## Paper #8: SIGIL-S — Small Model Security Companion

### Working Title
**"The Security Sentinel: A Dedicated Small Model Architecture for Real-Time LLM Defense"**

Alternative: *"Asymmetric Defense: Pairing Small Security Models with Large Language Models"*

### Thesis (one sentence)
A purpose-built small language model (1B–7B parameters), trained exclusively on security classification and adversarial detection, running as a parallel companion to the primary model, provides semantic-level threat detection at a cost and latency profile that enables deployment on every request — filling the gap between SIGIL's structural analysis and the primary model's own safety training.

### The Gap

Current LLM security exists on two extremes:

```
                    Cost / Latency
                         ↑
                         │
  Full model             │                    ● Primary model's own
  re-evaluation          │                      safety training
  (expensive, slow)      │                      (free but unreliable,
                         │                       can be ablated)
                         │
                         │         ← GAP →
                         │
  Structural             │  ● SIGIL
  pattern matching       │    (fast, cheap, but
  (cheap, fast)          │     misses semantic attacks)
                         │
                         └──────────────────→ Detection Capability
```

**The gap**: attacks that are semantically meaningful but structurally normal. A well-crafted jailbreak that uses no Unicode tricks, no injection grammar, no anomalous entropy — just clever language. SIGIL can't catch it (it's structurally clean). The model's own safety training might catch it (but might not, especially if fine-tuned/ablated per SHIELD's threat model).

**The solution**: a small, cheap, fast model whose *entire purpose* is security classification. It runs in parallel, adds minimal latency, and provides semantic understanding that structural analysis cannot.

### Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                  Asymmetric Defense Architecture                  │
│                                                                  │
│                    ┌──────────────────┐                           │
│                    │   SIGIL (core)   │ Stage 1: Structural      │
│                    │  <200μs / req    │                           │
│  Input ──→         └────────┬─────────┘                          │
│                             │                                     │
│                    ┌────────┴─────────┐                           │
│                    ↓                  ↓                           │
│           ┌──────────────┐  ┌──────────────────┐                 │
│           │ Primary Model│  │ Security Sentinel │ Stage 2:       │
│           │ (70B+)       │  │ (1B–7B)          │ Parallel       │
│           │              │  │                  │ inference      │
│           │ task_output  │  │ security_verdict │                 │
│           └──────┬───────┘  └────────┬─────────┘                 │
│                  │                   │                            │
│                  └───────┬───────────┘                            │
│                          ↓                                        │
│                 ┌─────────────────┐                               │
│                 │  Gate Decision  │ Stage 3: Verdict              │
│                 │                 │                               │
│                 │ IF sentinel.ok  │                               │
│                 │   → emit output │                               │
│                 │ ELSE            │                               │
│                 │   → block/flag  │                               │
│                 └─────────────────┘                               │
│                                                                  │
│  Total latency: max(primary, sentinel) ≈ primary                 │
│  (sentinel finishes first — it's smaller and faster)             │
└──────────────────────────────────────────────────────────────────┘
```

Key insight: because the sentinel runs **in parallel** with the primary model, it adds **zero additional latency** to the pipeline. The sentinel (1B–7B) finishes inference before the primary model (70B+) does. The gate decision happens on the output, but by the time the primary model produces output, the sentinel has already rendered its verdict.

### Core Contributions

**C1: Security Sentinel Architecture**
Formal specification of the companion model architecture:
- **Training objective**: multi-task classification — injection detection, jailbreak detection, DLP risk scoring, safety boundary classification, adversarial intent detection
- **Training data**: curated corpus of adversarial examples, jailbreak attempts, prompt injections, DLP violations, safety boundary probes — plus large volumes of benign data for calibration
- **Architecture**: small decoder-only transformer (1B–7B), or encoder-only for pure classification
- **Inference**: parallel with primary model, independent context window
- **Output**: structured verdict, not natural language

```rust
struct SentinelVerdict {
    /// Composite threat score (0.0 = benign, 1.0 = certain attack)
    threat_score: f32,
    
    /// Per-category scores
    injection_score: f32,      // Prompt injection likelihood
    jailbreak_score: f32,      // Jailbreak attempt likelihood
    dlp_risk: f32,             // Data exfiltration risk
    safety_score: f32,         // Safety boundary violation risk
    adversarial_score: f32,    // General adversarial intent
    
    /// Explanation tokens (short — sentinel is small)
    rationale: String,         // max 50 tokens
    
    /// Confidence in the verdict
    confidence: f32,
    
    /// Recommended action
    action: SentinelAction,    // Allow | Flag | Deny | Escalate
}
```

**C2: Asymmetric Cost Analysis**
Quantitative analysis of the cost/benefit of the sentinel architecture:
- Running a 3B sentinel alongside a 70B primary model adds ~4% compute cost
- But it catches ~60-80% of semantic attacks that structural analysis misses
- Cost per blocked attack: orders of magnitude cheaper than incident response
- Comparison with: running the primary model twice (too expensive), fine-tuning the primary model's safety (fragile, per SHIELD), output-only classifiers (too late)

**C3: Training Protocol — Adversarial Curriculum**
Novel training approach for the sentinel:
- **Phase 1**: Train on known attack corpora (injection, jailbreak databases)
- **Phase 2**: Adversarial self-play — primary model generates attacks, sentinel learns to detect them
- **Phase 3**: Red-team augmentation — human red-teamers generate novel attacks, sentinel is fine-tuned
- **Phase 4**: Production feedback — false positives and false negatives from production feed back into training
- **Continuous**: SIGIL-PROBE behavioral anomalies generate new training signal

**C4: Sentinel-SIGIL Composition**
The sentinel does not replace SIGIL — they compose:
```
SIGIL (structural) ──┐
                     ├──→ Composite Verdict
Sentinel (semantic) ──┘

Rules:
- SIGIL Critical → Deny (regardless of sentinel)
- Sentinel High + SIGIL Medium → Deny
- Sentinel Medium + SIGIL None → Flag (semantic-only suspicion)
- Both None → Allow
- Disagreement → log + escalate (training signal)
```

Disagreements between SIGIL and the sentinel are particularly valuable — they represent the boundary between structural and semantic detection and are ideal training data for both systems.

**C5: Sentinel Integrity — Who Guards the Guard?**
The sentinel itself is a model and could be attacked:
- **Weight integrity**: SHIELD monitors the sentinel's weights just like any other model
- **Adversarial robustness**: sentinel is adversarially trained (Phase 2 above)
- **Canary probes**: SIGIL-PROBE runs canary probes against the sentinel itself
- **Fallback**: if sentinel health degrades, SIGIL structural analysis remains as baseline defense
- **Diversity**: multiple sentinel instances with different training seeds for ensemble voting

### Positioning
- Novel architecture: no existing work proposes a dedicated small companion model for real-time security
- Extends the SIGIL argument: structural analysis has limits; semantic analysis is needed but shouldn't require a second full-size model
- Positions against: existing safety fine-tuning approaches (fragile), output classifiers (too late), Constitutional AI (internal to model, not independent), Llama Guard (closest work — but Llama Guard is a general-purpose classifier, not an architecture for real-time companion deployment)
- Directly addresses SHIELD's threat model: if the primary model's safety training is ablated, the independent sentinel still catches attacks

### Venue
ArXiv preprint → AAAI / ICLR (ML security track)

### Timeline
Q1 2027 — requires some experimental validation (training a proof-of-concept sentinel)

### Relationship to SIGIL
SIGIL-S is a **companion system**, not an extension crate. It has its own model weights, its own training pipeline, and its own inference server. It integrates with SIGIL through the `SentinelVerdict` API and composes verdicts with SIGIL's structural assessment.

```
The Complete SIGIL Defense Stack:

  Layer 1: SIGIL-core      — structural analysis (pattern, entropy, taint)     — <200μs
  Layer 2: SIGIL-MCP       — MCP content security gate                         — <500μs  
  Layer 3: SIGIL-S         — semantic analysis (small companion model)         — parallel
  Layer 4: SIGIL-M         — multimodal security (vision, audio, code)         — per-modality
  Layer 5: SIGIL-PROBE     — model health monitoring                           — continuous
  Bridge:  SHIELD          — model integrity verification                      — periodic
  Gate:    Valance          — execution boundary governance                     — per-action
```

---

## Publication Sequence (Updated)

| # | Paper | Target | Timeline | Status |
|---|---|---|---|---|
| 1 | Manifesto — Proof-Native AI Governance | ckodex.org | Concurrent | v1.1 drafted |
| 2 | SHIELD — Weight-Space Forensics | ArXiv | April 2026 | In progress |
| 3 | CE-SEC — Context Engineering Threat Taxonomy | ArXiv | May 2026 | Planned |
| 4 | OSS — Open Sandbox Specification | ArXiv | Q3 2026 | Planned |
| 5 | Compositional Proof-Carrying Governance | ArXiv | Q3 2026 | Planned |
| 6 | SIGIL — The Tokenizer is the First Firewall | ArXiv → USENIX | Q3 2026 | **SPEC v0.2.0** |
| 7 | SIGIL-M — Multimodal Security Tokenization | ArXiv → NeurIPS | Q4 2026 | **Outlined** |
| 8 | SIGIL-S — Small Model Security Companion | ArXiv → ICLR | Q1 2027 | **Outlined** |

### Strategic Notes

Papers #6, #7, and #8 form a **trilogy** within the broader Ckodex publication strategy:

- **#6 (SIGIL)** establishes the foundational thesis: the tokenizer is a security boundary
- **#7 (SIGIL-M)** extends it across modalities: every encoder is a security boundary  
- **#8 (SIGIL-S)** addresses the structural analysis limitation: semantic threats need a dedicated model

Each paper builds on the previous one, but each is independently falsifiable and independently publishable. An adversary can read #6 without #7 or #8 and still derive value.

The trilogy also demonstrates **architectural range** — from zero-allocation byte-level scanning to trained neural network deployment — which strengthens the overall Ckodex credibility narrative for the fellowship application.
