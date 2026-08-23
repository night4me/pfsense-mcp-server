"""Regression protection for README.md's Quick start install command.

Found 2026-08-22: the Quick start section pinned an exact release
version (``pfsense-mcp-server==0.5.1``) that was never updated across
two subsequent releases (v0.6.0, v0.7.0) -- stale by the time v0.7.0
published, and (because hatchling embeds README.md verbatim as the
wheel/sdist long_description at build time) permanently frozen into
that already-published, immutable PyPI artifact. README.md now uses an
unpinned ``pip install --upgrade pfsense-mcp-server`` instead, which
cannot go stale by construction -- this test guards against a future
regression back to a hardcoded, driftable version pin.

Scoped deliberately to the fenced code block directly under the
"## Quick start" heading, not the whole document: found 2026-08-23 that
an unscoped, whole-document regex false-positives on this project's own
"Release status" prose, which quotes the historical stale command
(backtick-quoted, describing what was wrong) as part of explaining the
fix -- a legitimate historical reference, not a live install
instruction, and exactly the false-positive class this test must not
reject.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
PACKAGE_NAME = "pfsense-mcp-server"

QUICK_START_FENCE = re.compile(r"^## Quick start\s*\n+```(?:\w+)?\s*\n(?P<body>.*?)```", re.DOTALL | re.MULTILINE)

# Matches a `pip install` line naming this package, optionally pinned to
# an exact version, e.g.:
#   pip install pfsense-mcp-server
#   pip install --upgrade pfsense-mcp-server
#   pip install 'pfsense-mcp-server==0.7.0'
INSTALL_LINE = re.compile(r"pip install(?:\s+--\S+)*\s+'?" + re.escape(PACKAGE_NAME) + r"(?:==(?P<version>[\d.]+))?'?")


def _current_version() -> str:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(metadata["version"])


def _quick_start_code_block() -> str:
    text = README.read_text(encoding="utf-8")
    match = QUICK_START_FENCE.search(text)
    assert match, "README.md has no fenced code block directly under '## Quick start'"
    return match.group("body")


def test_readme_has_an_install_command_for_this_package():
    body = _quick_start_code_block()
    matches = INSTALL_LINE.findall(body)
    assert matches, f"README.md's Quick start code block has no 'pip install {PACKAGE_NAME}' line to validate"


def test_readme_install_command_never_pins_a_stale_version():
    body = _quick_start_code_block()
    current = _current_version()
    for match in INSTALL_LINE.finditer(body):
        pinned = match.group("version")
        if pinned is not None:
            assert pinned == current, (
                f"README.md's Quick start pins pfsense-mcp-server=={pinned}, "
                f"but pyproject.toml's current version is {current}. Update the "
                "README pin (or switch to an unpinned 'pip install --upgrade "
                f"{PACKAGE_NAME}') before this is published."
            )
