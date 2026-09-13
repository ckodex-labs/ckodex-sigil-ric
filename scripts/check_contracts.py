#!/usr/bin/env python3
"""Validate that contract docs and the QA scorecard match the live workspace.

This check is intentionally conservative: it fails if the repo adds or removes
core contracts, layer names, or proof tests without updating the human-readable
boundary docs that describe them.
"""

from __future__ import annotations

from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "CONTRACTS.md"
SCORECARD = ROOT / "docs" / "QA-SCORECARD.md"


def read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"failed to read {path}: {exc}") from exc


def require_all(text: str, needles: list[str], *, scope: str) -> None:
    missing = [needle for needle in needles if needle not in text]
    if missing:
        raise SystemExit(
            f"{scope} is missing required entries: {', '.join(missing)}"
        )


def collect_test_files() -> list[str]:
    files = []
    for path in sorted((ROOT / "crates").glob("*/tests/*.rs")):
        files.append(path.relative_to(ROOT).as_posix())
    return files


def module_tree_files(rel: str) -> list[Path]:
    """Resolve a contract pin to every file in its module tree.

    Rust modules refactor between `foo.rs` and `foo/{mod,...}.rs` shapes;
    a pin must survive that. Resolution:
      - `foo.rs`      -> `foo.rs` + `foo/**/*.rs`
      - `foo/mod.rs`  -> `foo/**/*.rs` (the whole module dir)
      - `src/lib.rs`  -> the crate's entire `src/**/*.rs`
      - missing `foo.rs` with a live `foo/` dir -> `foo/**/*.rs`
      - non-`.rs` pins -> the file itself
    """
    path = ROOT / rel
    if path.suffix != ".rs":
        return [path]

    files: list[Path] = []
    if path.is_file():
        files.append(path)
    tree_dir = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.with_suffix("")
    if tree_dir.is_dir():
        files.extend(tree_dir.rglob("*.rs"))
    files = sorted(set(files))
    if not files:
        raise SystemExit(f"no source found for contract pin: {rel}")
    return files


def main() -> int:
    contracts = read(CONTRACTS)
    scorecard = read(SCORECARD)

    require_all(
        contracts,
        [
            "sigil-core",
            "sigil-mcp",
            "sigil-probe",
            "sigil-multimodal",
            "sigil-s",
            "Bindings",
        ],
        scope="docs/CONTRACTS.md",
    )

    # Make sure the documented public contract surface still exists in code.
    source_checks = {
        "crates/sigil-core/src/lib.rs": [
            "Policy",
            "SigilOutput",
            "InputAssessment",
            "Verdict",
            "EvidenceBundle",
            "TokenAnnotation",
            "TokenizerActor",
            "Vocab",
            "RepresentationReceipt",
            "ReceiptSignature",
            "ReceiptSigner",
            "EcdsaP384Signer",
            "DsseEnvelope",
            "EvidenceSink",
            "JsonlEvidenceSink",
        ],
        "crates/sigil-cli/src/cli/commands.rs": [
            "ReceiptVerificationOutcome",
            "KeygenOutcome",
            "AttestationVerificationOutcome",
        ],
        "crates/sigil-mcp/src/lib.rs": [
            "McpScanConfig",
            "ServerTrustProfile",
            "McpInspection",
            "McpEvidenceRecord",
            "EvidenceSink",
            "JsonlEvidenceSink",
        ],
        "crates/sigil-probe/src/lib.rs": [
            "ProbeConfig",
            "HealthReport",
            "HealthAction",
            "DriftAssessment",
        ],
        "crates/sigil-multimodal/src/types.rs": [
            "SubliminalAudio",
            "AudioSteganography",
            "MultimodalAssessment",
            "ModalityAssessment",
            "CrossModalAssessment",
            "FusionAssessment",
            "FusionRiskKind",
            "AuthorityCeiling",
        ],
        "crates/sigil-multimodal/src/perception.rs": [
            "PerceptionAdapter",
            "PerceptionReport",
            "ExtractedChannel",
        ],
        "crates/sigil-perception/src/lib.rs": [
            "ImageAdapter",
            "ExternalOcr",
            "PerceptionOutcome",
        ],
        "crates/sigil-perception/src/audio/mod.rs": [
            "AudioAdapter",
            "ExternalTranscript",
            "AudioPerceptionOutcome",
        ],
        "crates/sigil-perception/src/spectral/mod.rs": [
            "SpectralReport",
            "SpectralConfig",
            "analyze_spectrum",
            "downmix_to_mono",
            "downmix_to_mono_weighted",
            "downmix_to_mono_f32",
            "downmix_to_mono_weighted_f32",
            "normalization_factor",
            "pcm_to_f32",
            "artifact_digest",
        ],
        "crates/sigil-perception/src/video.rs": [
            "VideoAdapter",
            "VideoPerceptionOutcome",
        ],
        "crates/sigil-perception/src/document.rs": [
            "extract_pdf_text_via_lopdf",
            "extract_pdf_text_page_by_page",
            "extract_pdf_text_fallback",
            "DocumentAdapter",
            "DocumentPerceptionOutcome",
        ],
        "crates/sigil-sigstore/src/lib.rs": [
            "SigstoreKeylessSigner",
            "RekorEntry",
            "OidcSource",
            "SigstoreBundle",
            "build_bundle",
            "verify_bundle",
        ],
        "crates/sigil-sigstore/src/trust/mod.rs": [
            "TrustRoot",
            "verify_bundle_with_trust",
            "fetch_trust_bundle",
            "InclusionProof",
        ],
        "crates/sigil-sigstore/src/trust/rekor.rs": [
            "verify_rekor_set",
            "verify_inclusion_proof",
            "verify_rekor_entry_binding",
        ],
        "crates/sigil-sigstore/src/tuf.rs": [
            "trust_root_from_embedded",
            "trust_root_from_embedded_staging",
        ],
        "crates/sigil-s/src/lib.rs": [
            "SentinelVerdict",
            "CompositeVerdict",
        ],
        "bindings/c/sigil_tiktoken.h": [
            "zig_tiktoken_open",
            "zig_tiktoken_encode",
            "zig_tiktoken_decode",
            "zig_tiktoken_special_token_id",
        ],
    }

    for rel, needles in source_checks.items():
        tree = "\n".join(read(path) for path in module_tree_files(rel))
        require_all(
            tree,
            needles,
            scope=f"{rel} (+ module tree)",
        )

    test_files = collect_test_files()
    for test_file in test_files:
        if test_file not in scorecard:
            raise SystemExit(
                f"docs/QA-SCORECARD.md is missing proof-test reference: {test_file}"
            )

    # Ensure the scorecard still describes the key boundary classes.
    require_all(
        scorecard,
        [
            "Contract boundary invariants",
            "Batch actor consistency and thread safety",
            "Throughput regression and batch consistency",
            "Zig tokenizer parity and ABI stability",
            "Python binding encode/decode parity",
            "Go binding encode/decode parity",
        ],
        scope="docs/QA-SCORECARD.md",
    )

    print("contract docs and QA scorecard are in sync")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
