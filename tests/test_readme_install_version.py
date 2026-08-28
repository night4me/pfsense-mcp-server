"""Regression protection for the public install commands shown in
README.md's Quick start and docs/GETTING_STARTED.md's Step 1.

Found 2026-08-22: the Quick start section pinned an exact release
version (``pfsense-mcp-server==0.5.1``) that was never updated across
two subsequent releases (v0.6.0, v0.7.0) -- stale by the time v0.7.0
published, and (because hatchling embeds README.md verbatim as the
wheel/sdist long_description at build time) permanently frozen into
that already-published, immutable PyPI artifact. This test guards
against a future regression back to a hardcoded, driftable version pin
in either document's install command.

Found 2026-08-28 via a real clean-room install on Ubuntu 24.04 LTS: the
Quick start / Getting started install command was a bare
``pip install pfsense-mcp-server`` -- invalid on any PEP 668
"externally managed" system Python (refused outright unless the user
passes ``--break-system-packages``, which this project does not
recommend), and the clean host in question did not even have ``pip``
importable at all. Both documents now recommend ``pipx install
pfsense-mcp-server`` instead, which installs into its own isolated
environment regardless of the host's PEP 668 status. This test guards
against a silent regression back to the unsafe bare-pip form.

Scoped deliberately to the fenced code block directly under each
document's own install heading, not the whole document: found
2026-08-23 that an unscoped, whole-document regex false-positives on
this project's own "Release status" prose, which quotes a historical
stale command (backtick-quoted, describing what was wrong) as part of
explaining the fix -- a legitimate historical reference, not a live
install instruction, and exactly the false-positive class this test
must not reject.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
GETTING_STARTED = ROOT / "docs" / "GETTING_STARTED.md"
PACKAGE_NAME = "pfsense-mcp-server"

QUICK_START_FENCE = re.compile(r"^## Quick start\s*\n+```(?:\w+)?\s*\n(?P<body>.*?)```", re.DOTALL | re.MULTILINE)
GETTING_STARTED_INSTALL_FENCE = re.compile(
    r"^## 1\. Install\s*\n+```(?:\w+)?\s*\n(?P<body>.*?)```", re.DOTALL | re.MULTILINE
)

# Matches a `pipx install` line naming this package, optionally pinned to
# an exact version, e.g.:
#   pipx install pfsense-mcp-server
#   pipx install pfsense-mcp-server==0.9.0
INSTALL_LINE = re.compile(r"pipx install\s+'?" + re.escape(PACKAGE_NAME) + r"(?:==(?P<version>[\d.]+))?'?")

# A bare `pip install <package>` (optionally `--upgrade`/pinned, but NOT
# preceded by `-m ` -- i.e. not `python -m pip install` /
# `.venv/bin/python -m pip install`, this project's own documented safe
# venv form) is the exact PEP-668-unsafe form this project no longer
# recommends as the primary Quick start / Getting started command --
# see module docstring.
BARE_PIP_INSTALL_LINE = re.compile(r"(?<!-m )pip install(?:\s+--\S+)*\s+'?" + re.escape(PACKAGE_NAME))


def _current_version() -> str:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return str(metadata["version"])


def _quick_start_code_block() -> str:
    text = README.read_text(encoding="utf-8")
    match = QUICK_START_FENCE.search(text)
    assert match, "README.md has no fenced code block directly under '## Quick start'"
    return match.group("body")


def _getting_started_install_code_block() -> str:
    text = GETTING_STARTED.read_text(encoding="utf-8")
    match = GETTING_STARTED_INSTALL_FENCE.search(text)
    assert match, "docs/GETTING_STARTED.md has no fenced code block directly under '## 1. Install'"
    return match.group("body")


def test_readme_has_an_install_command_for_this_package():
    body = _quick_start_code_block()
    matches = INSTALL_LINE.findall(body)
    assert matches, f"README.md's Quick start code block has no 'pipx install {PACKAGE_NAME}' line to validate"


def test_readme_install_command_never_pins_a_stale_version():
    body = _quick_start_code_block()
    current = _current_version()
    for match in INSTALL_LINE.finditer(body):
        pinned = match.group("version")
        if pinned is not None:
            assert pinned == current, (
                f"README.md's Quick start pins pfsense-mcp-server=={pinned}, "
                f"but pyproject.toml's current version is {current}. Update the "
                "README pin (or switch to an unpinned 'pipx install "
                f"{PACKAGE_NAME}') before this is published."
            )


def test_readme_quick_start_never_regresses_to_bare_pip_install():
    body = _quick_start_code_block()
    match = BARE_PIP_INSTALL_LINE.search(body)
    assert match is None, (
        "README.md's Quick start code block contains a bare "
        f"'pip install {PACKAGE_NAME}' line -- this is refused outright "
        "on any PEP 668 'externally managed' system Python (e.g. "
        "Debian/Ubuntu 23.04+) unless the user passes "
        "--break-system-packages, which this project does not "
        "recommend. Use 'pipx install "
        f"{PACKAGE_NAME}' (or a '.venv/bin/python -m pip install "
        f"{PACKAGE_NAME}' form inside an isolated virtual environment) "
        "instead."
    )


def test_getting_started_has_an_install_command_for_this_package():
    body = _getting_started_install_code_block()
    matches = INSTALL_LINE.findall(body)
    assert matches, f"docs/GETTING_STARTED.md's Step 1 code block has no 'pipx install {PACKAGE_NAME}' line to validate"


def test_getting_started_install_command_never_pins_a_stale_version():
    body = _getting_started_install_code_block()
    current = _current_version()
    for match in INSTALL_LINE.finditer(body):
        pinned = match.group("version")
        if pinned is not None:
            assert pinned == current, (
                f"docs/GETTING_STARTED.md's Step 1 pins pfsense-mcp-server=={pinned}, "
                f"but pyproject.toml's current version is {current}."
            )


def test_getting_started_install_never_regresses_to_bare_pip_install():
    body = _getting_started_install_code_block()
    match = BARE_PIP_INSTALL_LINE.search(body)
    assert match is None, (
        "docs/GETTING_STARTED.md's Step 1 code block contains a bare "
        f"'pip install {PACKAGE_NAME}' line -- see "
        "test_readme_quick_start_never_regresses_to_bare_pip_install's "
        "reasoning; the same regression must not land here either."
    )
