#!/usr/bin/env python3
"""Validate local Markdown links and machine-readable documentation examples."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
ROOT_DOCUMENTS = (
    "README.md",
    "AGENTS.md",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
)
LINK_PATTERN = re.compile(r"!?\[[^]]*\]\((?P<target>[^)]+)\)")
REFERENCE_PATTERN = re.compile(r"(?m)^\[[^]]+\]:\s*(?P<target>\S+)")
FENCE_PATTERN = re.compile(r"```(?P<language>json|toml)\s*\n(?P<body>.*?)```", re.DOTALL)


def markdown_files() -> list[Path]:
    documents = [ROOT / name for name in ROOT_DOCUMENTS if (ROOT / name).exists()]
    for directory in (ROOT / "docs", ROOT / "examples"):
        documents.extend(sorted(directory.rglob("*.md")))
    return documents


def _display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return path.name


def _local_target(raw_target: str) -> str | None:
    target = raw_target.strip().strip("<>")
    if not target or target.startswith(("#", "https://", "http://", "mailto:")):
        return None
    return unquote(target.split("#", maxsplit=1)[0])


def validate_document(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    display_path = _display_path(path)

    for match in (*LINK_PATTERN.finditer(text), *REFERENCE_PATTERN.finditer(text)):
        target = _local_target(match.group("target"))
        if target is not None and not (path.parent / target).resolve().exists():
            errors.append(f"{display_path}: missing local link target {target!r}")

    parsers = {"json": json.loads, "toml": tomllib.loads}
    for index, match in enumerate(FENCE_PATTERN.finditer(text), start=1):
        language = match.group("language")
        try:
            parsers[language](match.group("body"))
        except (json.JSONDecodeError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"{display_path}: invalid {language} fence {index}: {exc}")
    return errors


def main() -> int:
    documents = markdown_files()
    errors = [error for path in documents for error in validate_document(path)]
    if errors:
        for error in errors:
            print(error)
        return 1
    print(f"validate_docs: OK ({len(documents)} Markdown files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
