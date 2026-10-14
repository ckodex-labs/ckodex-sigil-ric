# SIGIL architecture

SIGIL enforces representation integrity between what security controls inspect and what an AI model executes. The engine prevents prompt injection, terminal escape tampering, and boundary loss during tokenization and multimodal fusion.

## Layered security architecture

```mermaid
flowchart TD
    subgraph Clients["Intake Channels"]
        RAW["Raw User Prompts"]
        MCP_IN["MCP Tool Responses"]
        MEDIA["Media and Perception Streams"]
    end

    subgraph Adapters["Perception and Gateway Adapters"]
        PERC["sigil-perception: OCR, ASR, Stream Demux"]
        MCP_GATE["sigil-mcp: Schema Gate and Taint Tracking"]
    end

    subgraph Kernel["Representation Integrity Boundary"]
        CORE["sigil-core: Normalization, Scan, Tokenizer Firewall"]
        VT["sigil-vt: Terminal Window Repaint Detector"]
        MULTI["sigil-multimodal: Fusion Boundary Auditor"]
    end

    subgraph Assurance["Assurance and Signing"]
        SIG["sigil-sigstore: Keyless Fulcio Attestations"]
        ECDSA["ECDSA P-384 Admission Receipts"]
    end

    subgraph Runtime["Execution Interfaces"]
        CLI["sigil-cli: CLI Runner and Benchmarks"]
        FFI["sigil-ffi: C ABI, Zig tiktoken, WebAssembly"]
        SRV["sigil-server: Local Sidecar Daemon"]
        PROBE["sigil-probe: Drift and Canary Monitoring"]
        S["sigil-s: Semantic Sentinel Companion"]
    end

    RAW --> CORE
    MEDIA --> PERC --> MULTI --> CORE
    MCP_IN --> MCP_GATE --> MULTI
    CORE <--> VT
    CORE --> ECDSA
    CORE --> SIG
    CORE --> FFI
    CORE --> CLI
    CORE --> SRV
    CORE --> PROBE
    CORE --> S
```

The architecture consists of eleven modular crates:

### Core execution and boundaries

- `crates/sigil-core`: owns intake normalization, token boundary mapping, prompt injection detectors, data loss prevention scans, and cryptographic receipt generation using ECDSA P-384.
- `crates/sigil-vt`: provides virtual terminal window emulation to detect cursor repaints, line erases, and escape sequences that attempt to forge visual terminal output.
- `crates/sigil-s`: acts as the semantic sentinel companion layer, evaluating composite model risk scores without permitting lower-confidence assessments to weaken core security denials.

### Protocols and integration

- `crates/sigil-mcp`: gates tool responses from Model Context Protocol servers against declared schemas and injection signatures before output enters a prompt context.
- `crates/sigil-perception`: adapts binary assets into text channels, covering images with OCR, audio with speech recognition, video with stream demuxing, documents with render comparisons, and code with comment splits.
- `crates/sigil-multimodal`: audits fusion boundaries across heterogeneous channels to ensure that benign inputs do not synthesize malicious commands when combined.
- `crates/sigil-sigstore`: provides keyless signing through Fulcio OIDC tokens and verification of transparency log bundles.

### Services and operational interfaces

- `crates/sigil-probe`: monitors tokenizer health, canary token stability, and distribution drift metrics.
- `crates/sigil-server`: hosts local daemon endpoints and sidecar interfaces for containerized applications.
- `crates/sigil-ffi`: exports standard C ABI entry points and packages the WebAssembly reactor target.
- `crates/sigil-cli`: supplies operator commands, CI test runners, and performance benchmark suites.

## Containerized pipeline and toolchain architecture

All CI lanes and release builds execute inside reproducible Dagger containers, ensuring identical results across development machines and GitHub Actions runners.

For Zig compilation targets, the pipeline integrates with [dagger-zig](https://github.com/MChorfa/dagger-zig). This native Zig SDK for Dagger drives:

- Containerized compilation of `libzig_tiktoken.a` and `libzig_tiktoken.so`.
- Standalone compilation and validation of the `sigil.wasm` WebAssembly module.
- Verification of cross-runtime tokenization parity against Python and Go bindings.
- Differential conformance tests comparing the virtual terminal scanner with ghostty terminal tables.

```mermaid
flowchart LR
    SRC["Repository Source"] --> DAGGER["Dagger Engine Container"]
    DAGGER --> RUST["Rust CI Driver: ci/"]
    DAGGER --> ZIG["dagger-zig SDK"]

    RUST --> TESTS["cargo test: 384 tests"]
    RUST --> CLIPPY["clippy: 0 warnings"]
    RUST --> REPORTS["ci-out: Scorecard and Launch Reports"]

    ZIG --> STATIC["libzig_tiktoken.a"]
    ZIG --> SHARED["libzig_tiktoken.so"]
    ZIG --> WASM["sigil.wasm"]
    ZIG --> PARITY["Polyglot Parity: Python and Go"]
```

See [SIGIL-SPEC.md](../SIGIL-SPEC.md) for the complete mathematical and behavioral specification.
