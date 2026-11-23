"""Print one version's section of CHANGELOG.md, for the GitHub release body.

    python3 scripts/release_notes.py v0.4.0 > notes.md

Fails if the section is missing or empty, so a release cannot ship without
its notes.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path


def section(changelog: str, version: str) -> str:
    """Return the body under "## [version]" up to the next "## [" heading."""
    pattern = rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)"
    match = re.search(pattern, changelog, re.MULTILINE | re.DOTALL)
    if match is None:
        raise SystemExit(f"release_notes: no '## [{version}]' section in CHANGELOG.md")
    body = re.sub(r"^\[[^\]]+\]: .*$", "", match.group(1), flags=re.MULTILINE).strip()
    if not body:
        raise SystemExit(f"release_notes: the [{version}] section is empty")
    return body


def main() -> None:
    tag = sys.argv[1]
    version = tag.removeprefix("v")
    root = Path(__file__).resolve().parent.parent
    print(section((root / "CHANGELOG.md").read_text(encoding="utf-8"), version))


if __name__ == "__main__":
    main()
