#!/usr/bin/env python3
"""Render the SIGIL launch readiness status from a machine-readable checklist."""

from __future__ import annotations

import argparse
import json
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


ROOT = Path(__file__).resolve().parents[1]
CHECKLIST = ROOT / "docs" / "LAUNCH-CHECKLIST.toml"


@dataclass(frozen=True)
class ItemResult:
    id: str
    label: str
    kind: str
    status: str
    detail: str


def read_checklist() -> dict:
    return tomllib.loads(CHECKLIST.read_text(encoding="utf-8"))


def run_command(command: str) -> tuple[bool, str]:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        shell=True,
        capture_output=True,
        text=True,
    )
    ok = completed.returncode == 0
    detail = completed.stdout.strip() or completed.stderr.strip()
    if not ok and not detail:
        detail = f"exit code {completed.returncode}"
    return ok, detail


def check_file(path: str) -> tuple[bool, str]:
    full_path = ROOT / path
    if full_path.exists():
        return True, f"exists: {path}"
    return False, f"missing: {path}"


def resolve_stage(config: dict, stage: str) -> list[dict]:
    entry = config[stage]
    items = list(entry.get("items", []))
    parent = entry.get("extends")
    if parent:
        items = resolve_stage(config, parent) + items
    return items


def evaluate(
    stage: str,
    *,
    assume_commands_pass: bool,
    burn_in_report: dict | None,
) -> tuple[str, list[ItemResult]]:
    config = read_checklist()
    items = resolve_stage(config["stage"], stage)
    results: list[ItemResult] = []
    ready = True
    burn_in_status = {}
    if burn_in_report:
        burn_in_status = {
            item["id"]: item
            for item in burn_in_report.get("items", [])
            if "id" in item
        }

    for item in items:
        kind = item["kind"]
        label = item["label"]
        item_id = item["id"]
        if kind == "manual":
            status = "manual"
            detail = "requires operator confirmation"
            if burn_in_status:
                burn_in_item = burn_in_status.get(item_id)
                if burn_in_item is None:
                    status = "manual"
                    detail = "waiting on burn-in report"
                    ready = False
                else:
                    status = burn_in_item.get("status", "manual")
                    detail = burn_in_item.get("detail", "burn-in report")
                    ready = ready and status == "pass"
            else:
                ready = False
        elif kind == "file":
            ok, detail = check_file(item["path"])
            status = "pass" if ok else "fail"
            ready = ready and ok
        elif kind == "command":
            if assume_commands_pass:
                ok, detail = True, "inherited from prior verification"
            else:
                ok, detail = run_command(item["command"])
            status = "pass" if ok else "fail"
            ready = ready and ok
        else:
            status = "fail"
            detail = f"unknown kind: {kind}"
            ready = False
        results.append(ItemResult(item_id, label, kind, status, detail))

    return ("ready" if ready else "not_ready"), results


def render_markdown(stage: str, overall: str, results: list[ItemResult]) -> str:
    lines = [
        "# SIGIL Launch Readiness Report",
        "",
        f"Stage: `{stage}`",
        f"Overall: **{overall.replace('_', ' ').title()}**",
        "",
        "| Item | Kind | Status | Detail |",
        "| --- | --- | --- | --- |",
    ]
    for item in results:
        detail = item.detail.replace("|", "\\|")
        lines.append(
            f"| {item.label} | {item.kind} | {item.status} | {detail} |"
        )
    return "\n".join(lines).rstrip() + "\n"


def load_burn_in_report(path: Path | None) -> dict | None:
    if path is None:
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stage",
        choices=["internal_qa", "staged_rollout", "production_launch"],
        default="internal_qa",
    )
    parser.add_argument(
        "--assume-commands-pass",
        action="store_true",
        help="mark command items as passing without executing them",
    )
    parser.add_argument(
        "--burn-in-report",
        type=Path,
        help="optional burn-in report JSON used to discharge rollout items",
    )
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--json-out", type=Path)
    args = parser.parse_args()

    burn_in_report = load_burn_in_report(args.burn_in_report)
    overall, results = evaluate(
        args.stage,
        assume_commands_pass=args.assume_commands_pass,
        burn_in_report=burn_in_report,
    )
    markdown = render_markdown(args.stage, overall, results)
    payload = {
        "stage": args.stage,
        "overall": overall,
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

    return 0 if overall == "ready" else 1


if __name__ == "__main__":
    raise SystemExit(main())
