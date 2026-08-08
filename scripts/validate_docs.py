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
    "SUPPORT.md",
)
LINK_PATTERN = re.compile(r"!?\[[^]]*\]\((?P<target>[^)]+)\)")
REFERENCE_PATTERN = re.compile(r"(?m)^\[[^]]+\]:\s*(?P<target>\S+)")
FENCE_PATTERN = re.compile(r"```(?P<language>json|toml)\s*\n(?P<body>.*?)```", re.DOTALL)
ANY_FENCE_LINE = re.compile(r"^\s*(```|~~~)")
HEADING_LINE = re.compile(r"^(?P<hashes>#{1,6})\s+(?P<text>.+?)\s*#*\s*$")
INLINE_CODE = re.compile(r"`([^`]*)`")
INLINE_LINK = re.compile(r"!?\[([^]]*)\]\([^)]*\)")
# Asterisk emphasis only -- underscore emphasis is deliberately not
# stripped here, since CommonMark itself doesn't trigger `_..._`
# intraword (so it never appears in this repo's identifier-bearing
# headings like `` `pfsense_get_system_status` ``), and naively
# stripping it would mangle a bare (post-code-span-stripped) identifier
# like `pfsense_get_system_status` into `pfsenseget_system_status`.
INLINE_EMPHASIS = re.compile(r"(\*\*\*|\*\*|\*)(.+?)\1")
# Mirrors github-slugger's removal set: control characters plus
# !"#$%&'()*+,./:;<=>?@[\]^`{|}~ and DEL -- notably NOT hyphen or
# underscore, which GitHub's own heading anchors preserve.
SLUG_STRIP = re.compile(r"[\x00-\x1f\x21-\x2c\x2e\x2f\x3a-\x40\x5b-\x5e\x60\x7b-\x7f]")


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
    if not target or target.startswith(("https://", "http://", "mailto:")):
        return None
    return unquote(target.split("#", maxsplit=1)[0])


def _anchor(raw_target: str) -> str | None:
    target = raw_target.strip().strip("<>")
    if target.startswith(("https://", "http://", "mailto:")):
        return None
    _, sep, fragment = target.partition("#")
    return unquote(fragment) if sep else None


def _heading_to_slug(text: str, *, seen: dict[str, int]) -> str:
    """Reproduces GitHub's own heading-anchor algorithm closely enough to
    validate real anchors: strip inline code spans, links, and asterisk
    emphasis down to their visible text (matching what GitHub actually
    renders and slugifies, not the raw Markdown source), strip the same
    punctuation set GitHub's slugger strips (preserving hyphens and
    underscores), lowercase, spaces to hyphens, then disambiguate
    duplicate headings with a `-N` suffix exactly as GitHub does."""

    rendered = INLINE_CODE.sub(r"\1", text)
    rendered = INLINE_LINK.sub(r"\1", rendered)
    rendered = INLINE_EMPHASIS.sub(r"\2", rendered)
    slug = SLUG_STRIP.sub("", rendered.strip().lower()).replace(" ", "-")
    count = seen.get(slug, 0)
    seen[slug] = count + 1
    return slug if count == 0 else f"{slug}-{count}"


def _heading_slugs(text: str) -> set[str]:
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    in_fence = False
    for line in text.splitlines():
        if ANY_FENCE_LINE.match(line):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        match = HEADING_LINE.match(line)
        if match:
            slugs.add(_heading_to_slug(match.group("text"), seen=seen))
    return slugs


def validate_document(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    display_path = _display_path(path)

    for match in (*LINK_PATTERN.finditer(text), *REFERENCE_PATTERN.finditer(text)):
        raw_target = match.group("target")
        target = _local_target(raw_target)
        if target is not None and target and not (path.parent / target).resolve().exists():
            errors.append(f"{display_path}: missing local link target {target!r}")
            continue
        anchor = _anchor(raw_target)
        if anchor is None:
            continue
        target_path = (path.parent / target).resolve() if target else path
        if target_path.suffix != ".md" or not target_path.exists():
            continue
        if anchor not in _heading_slugs(target_path.read_text(encoding="utf-8")):
            errors.append(f"{display_path}: missing anchor {anchor!r} in {_display_path(target_path)}")

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
