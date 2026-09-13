#!/usr/bin/env python3
"""Render the SIGIL burn-in report from benchmark output and rollout telemetry."""

from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "docs" / "BURN-IN.toml"
TELEMETRY_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class ItemResult:
    id: str
    label: str
    status: str
    detail: str


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def read_config() -> dict:
    return tomllib.loads(CONFIG.read_text(encoding="utf-8"))


def validate_telemetry(payload: dict) -> dict:
    if not isinstance(payload, dict):
        raise SystemExit("telemetry payload must be a JSON object")

    schema_version = payload.get("schema_version", TELEMETRY_SCHEMA_VERSION)
    if schema_version != TELEMETRY_SCHEMA_VERSION:
        raise SystemExit(
            f"unsupported telemetry schema_version {schema_version}; expected {TELEMETRY_SCHEMA_VERSION}"
        )

    required_keys = [
        "deployment_mode",
        "monitor_shadow_enabled",
        "representative_corpora",
        "false_positive_rate",
        "unresolved_high_severity_findings",
        "rollback_ready",
    ]
    missing = [key for key in required_keys if key not in payload]
    if missing:
        raise SystemExit(f"telemetry payload is missing required keys: {', '.join(missing)}")

    if not isinstance(payload["representative_corpora"], list):
        raise SystemExit("telemetry.representative_corpora must be an array")
    if not all(isinstance(item, str) for item in payload["representative_corpora"]):
        raise SystemExit("telemetry.representative_corpora must contain strings")
    if not isinstance(payload["monitor_shadow_enabled"], bool):
        raise SystemExit("telemetry.monitor_shadow_enabled must be a boolean")
    if not isinstance(payload["rollback_ready"], bool):
        raise SystemExit("telemetry.rollback_ready must be a boolean")
    if not isinstance(payload["deployment_mode"], str):
        raise SystemExit("telemetry.deployment_mode must be a string")

    false_positive_rate = payload["false_positive_rate"]
    if not isinstance(false_positive_rate, (int, float)) or not math.isfinite(
        float(false_positive_rate)
    ):
        raise SystemExit("telemetry.false_positive_rate must be a finite number")
    if not 0.0 <= float(false_positive_rate) <= 1.0:
        raise SystemExit("telemetry.false_positive_rate must be between 0.0 and 1.0")

    high_severity = payload["unresolved_high_severity_findings"]
    if not isinstance(high_severity, int) or high_severity < 0:
        raise SystemExit(
            "telemetry.unresolved_high_severity_findings must be a non-negative integer"
        )

    evidence_refs = payload.get("evidence_refs", [])
    if not isinstance(evidence_refs, list):
        raise SystemExit("telemetry.evidence_refs must be an array when present")
    if not all(isinstance(item, str) for item in evidence_refs):
        raise SystemExit("telemetry.evidence_refs must contain strings when present")

    captured_at = payload.get("captured_at_unix_ms")
    if captured_at is not None and not isinstance(captured_at, int):
        raise SystemExit("telemetry.captured_at_unix_ms must be an integer when present")

    return payload


def compute_item(
    item_id: str,
    label: str,
    *,
    benchmark: dict,
    telemetry: dict | None,
    config: dict,
) -> ItemResult:
    burn_in = config["burn_in"]

    if item_id == "stress-benchmark":
        ok = bool(benchmark.get("outputs_match")) and bool(benchmark.get("expected_parity"))
        detail = (
            f"preset={benchmark.get('preset')} corpus={benchmark.get('corpus')} "
            f"outputs_match={benchmark.get('outputs_match')} expected_parity={benchmark.get('expected_parity')}"
        )
        return ItemResult(item_id, label, "pass" if ok else "fail", detail)

    if telemetry is None:
        return ItemResult(item_id, label, "manual", "missing rollout telemetry")

    if item_id == "monitor-shadow":
        deployment_mode = telemetry.get("deployment_mode")
        monitor_shadow_enabled = telemetry.get("monitor_shadow_enabled")
        ok = deployment_mode in {"monitor", "shadow"} and monitor_shadow_enabled is True
        detail = (
            f"deployment_mode={deployment_mode} "
            f"monitor_shadow_enabled={monitor_shadow_enabled}"
        )
        return ItemResult(item_id, label, "pass" if ok else "fail", detail)

    if item_id == "representative-corpus":
        corpora = telemetry.get("representative_corpora") or []
        required = burn_in["representative_corpora"]
        ok = all(corpus in corpora for corpus in required)
        detail = f"telemetry={corpora!r} required={required!r}"
        return ItemResult(item_id, label, "pass" if ok else "fail", detail)

    if item_id == "false-positive-rate":
        rate = telemetry.get("false_positive_rate")
        threshold = telemetry.get(
            "false_positive_rate_threshold", burn_in["false_positive_rate_max"]
        )
        if rate is None:
            return ItemResult(item_id, label, "manual", "missing false_positive_rate")
        ok = float(rate) <= float(threshold)
        detail = f"rate={rate} threshold={threshold}"
        return ItemResult(item_id, label, "pass" if ok else "fail", detail)

    if item_id == "no-high-sev":
        count = telemetry.get("unresolved_high_severity_findings")
        if count is None:
            return ItemResult(item_id, label, "manual", "missing unresolved_high_severity_findings")
        ok = int(count) <= int(burn_in["max_unresolved_high_severity_findings"])
        detail = f"count={count}"
        return ItemResult(item_id, label, "pass" if ok else "fail", detail)

    if item_id == "rollback-plan":
        ready = telemetry.get("rollback_ready")
        if ready is None:
            return ItemResult(item_id, label, "manual", "missing rollback_ready")
        detail = f"rollback_ready={ready}"
        return ItemResult(item_id, label, "pass" if ready else "fail", detail)

    return ItemResult(item_id, label, "manual", "unhandled item")


def render_markdown(stage: str, overall: str, results: list[ItemResult], benchmark: dict) -> str:
    lines = [
        "# SIGIL Burn-In Report",
        "",
        f"Stage: `{stage}`",
        f"Overall: **{overall.replace('_', ' ').title()}**",
        "",
        f"Benchmark preset: `{benchmark.get('preset', 'unknown')}`",
        f"Benchmark corpus: `{benchmark.get('corpus', 'unknown')}`",
        f"Benchmark outputs match: `{benchmark.get('outputs_match', False)}`",
        "",
        "| Item | Status | Detail |",
        "| --- | --- | --- |",
    ]
    for item in results:
        detail = item.detail.replace("|", "\\|")
        lines.append(f"| {item.label} | {item.status} | {detail} |")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", default="staged_rollout")
    parser.add_argument("--benchmark", type=Path, required=True)
    parser.add_argument("--telemetry", type=Path)
    parser.add_argument(
        "--fail-on-not-ready",
        action="store_true",
        help="exit non-zero when the burn-in report is not ready",
    )
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    config = read_config()
    benchmark = read_json(args.benchmark)
    telemetry = validate_telemetry(read_json(args.telemetry)) if args.telemetry else None

    items = [
        ("stress-benchmark", "Stress benchmark compared to baselines"),
        ("monitor-shadow", "Monitor/shadow mode is enabled"),
        ("representative-corpus", "Representative corpus exercised"),
        ("false-positive-rate", "False-positive rate is stable"),
        ("no-high-sev", "No unresolved high-severity findings remain"),
        ("rollback-plan", "Rollback plan is ready"),
    ]
    results = [
        compute_item(item_id, label, benchmark=benchmark, telemetry=telemetry, config=config)
        for item_id, label in items
    ]
    overall = "ready" if all(item.status == "pass" for item in results) else "not_ready"
    markdown = render_markdown(args.stage, overall, results, benchmark)
    payload = {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "stage": args.stage,
        "overall": overall,
        "benchmark": benchmark,
        "telemetry": telemetry,
        "items": [asdict(item) for item in results],
    }

    if args.markdown_out:
        args.markdown_out.write_text(markdown, encoding="utf-8")
    if args.json_out:
        args.json_out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    if not args.markdown_out and not args.json_out:
        print(markdown, end="")

    if overall == "ready":
        return 0
    return 1 if args.fail_on_not_ready else 0


if __name__ == "__main__":
    raise SystemExit(main())
