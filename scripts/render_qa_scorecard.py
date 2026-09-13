#!/usr/bin/env python3
"""Render a live QA scorecard artifact from the repo.

The committed docs remain the human-readable source of truth. This renderer
turns them into a deterministic artifact that CI can upload on every run so
coverage changes are visible without digging through logs.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass, asdict
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCORECARD = ROOT / "docs" / "QA-SCORECARD.md"


@dataclass(frozen=True)
class ScorecardRow:
    attack_class: str
    blocking_layer: str
    proof_tests: list[str]
    status: str


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_scorecard_table(text: str) -> list[tuple[str, str, str]]:
    rows: list[tuple[str, str, str]] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        if stripped.startswith("| ---"):
            continue
        parts = [part.strip() for part in stripped.strip("|").split("|")]
        if len(parts) != 3 or parts[0] == "Attack class":
            continue
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def collect_test_inventory() -> dict[str, list[str]]:
    inventory: dict[str, list[str]] = {}
    for path in sorted((ROOT / "crates").glob("*/tests/*.rs")):
        crate = path.parts[-3]
        inventory.setdefault(crate, []).append(path.relative_to(ROOT).as_posix())
    return inventory


def row_status(row: tuple[str, str, str]) -> ScorecardRow:
    attack_class, blocking_layer, proof_tests = row
    files = [item.strip(" `") for item in proof_tests.split(",")]
    checked = [file for file in files if looks_like_path(file)]
    missing = [file for file in checked if not path_exists_or_matches(file)]
    status = "ok" if not missing else f"missing: {', '.join(missing)}"
    return ScorecardRow(
        attack_class=attack_class,
        blocking_layer=blocking_layer,
        proof_tests=files,
        status=status,
    )


def looks_like_path(item: str) -> bool:
    return any(
        token in item
        for token in (
            "/",
            "*",
            ".rs",
            ".md",
            ".json",
            ".toml",
            ".yml",
            ".yaml",
        )
    )


def path_exists_or_matches(item: str) -> bool:
    if "*" in item:
        return any(ROOT.glob(item))
    return (ROOT / item).exists()


def render_markdown(rows: list[ScorecardRow], inventory: dict[str, list[str]]) -> str:
    lines = [
        "# SIGIL QA Scorecard Artifact",
        "",
        "This artifact is generated from `docs/QA-SCORECARD.md` and the live test inventory.",
        "",
        "## Row Status",
        "",
        "| Attack class | Blocking layer | Proof tests | Status |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        tests = ", ".join(f"`{test}`" for test in row.proof_tests)
        lines.append(
            f"| {row.attack_class} | {row.blocking_layer} | {tests} | {row.status} |"
        )
    lines.extend(["", "## Live Test Inventory", ""])
    for crate, files in sorted(inventory.items()):
        lines.append(f"### {crate}")
        for file in files:
            lines.append(f"- `{file}`")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_comment(rows: list[ScorecardRow]) -> str:
    lines = [
        "<!-- sigil-qa-scorecard -->",
        "## SIGIL QA Scorecard",
        "",
        "This is the current contract and regression coverage summary for the workspace.",
        "",
        "| Attack class | Blocking layer | Proof tests | Status |",
        "| --- | --- | --- | --- |",
    ]
    for row in rows:
        tests = ", ".join(f"`{test}`" for test in row.proof_tests)
        lines.append(
            f"| {row.attack_class} | {row.blocking_layer} | {tests} | {row.status} |"
        )
    lines.extend(
        [
            "",
            "For the full live inventory, see the workflow artifact generated in CI.",
        ]
    )
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--markdown-out", type=Path)
    parser.add_argument("--json-out", type=Path)
    parser.add_argument("--comment-out", type=Path)
    args = parser.parse_args()

    table_rows = [row_status(row) for row in parse_scorecard_table(read(SCORECARD))]
    inventory = collect_test_inventory()
    payload = {
        "rows": [asdict(row) for row in table_rows],
        "inventory": inventory,
    }
    markdown = render_markdown(table_rows, inventory)
    comment = render_comment(table_rows)

    if args.markdown_out:
        args.markdown_out.write_text(markdown, encoding="utf-8")
    if args.json_out:
        args.json_out.write_text(
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    if args.comment_out:
        args.comment_out.write_text(comment, encoding="utf-8")

    if not args.markdown_out and not args.json_out and not args.comment_out:
        print(markdown, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
