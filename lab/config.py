"""Disposable-lab configuration loader.

This module has no code path capable of loading a production credential
(I2 of disposable_lab_execution_model.md): it never imports
`pfsense_mcp.config` and never references `PFSENSE_API_URL`/
`PFSENSE_API_KEY_FILE` — it defines its own, distinctly-named environment
variables (`PFSENSE_LAB_*`) end to end. `tests/tier1/test_isolation.py`'s
AST-based discipline is mirrored here by `lab/tests/test_config.py`,
which greps/AST-walks this file to prove that structurally, not just by
convention.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor

_REQUIRED_VARS = (
    "PFSENSE_LAB_API_URL",
    "PFSENSE_LAB_IDENTITY",
    "PFSENSE_LAB_API_KEY_FILE",
    "PFSENSE_LAB_CANDIDATE",
)
_KEY_FILE_MAX_BYTES = 16 * 1024
_KEY_LINE_MAX_LENGTH = 4096

# I1: the harness refuses to start against anything that does not match
# one of these lab-only host shapes — a `.lab.invalid` hostname
# convention, or an RFC 5737 TEST-NET address literal. Deliberately does
# not match any real, resolvable, or production-shaped host.
_LAB_HOST_ALLOW_PATTERNS = (
    re.compile(r"^https://[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.lab\.invalid(?::\d{1,5})?$"),
    re.compile(r"^https://(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}(?::\d{1,5})?$"),
)


class LabConfigError(Exception):
    """Raised when lab configuration cannot be loaded — the harness
    refuses to start rather than falling back to anything
    production-shaped or partially configured."""


@dataclass(frozen=True)
class LabConfig:
    base_url: str
    identity: str
    key_file: Path
    candidate: str


def _host_is_lab_allowed(base_url: str) -> bool:
    return any(pattern.fullmatch(base_url) for pattern in _LAB_HOST_ALLOW_PATTERNS)


def load_lab_config(env: dict[str, str] | None = None) -> LabConfig:
    """Refuses to load if any lab-scoped variable is missing, or if the
    resolved `base_url` does not match the lab host allow-list (I1).
    Setting only the production `PFSENSE_API_URL`/`PFSENSE_API_KEY_FILE`
    variables — without also setting the `PFSENSE_LAB_*` ones — is
    indistinguishable from setting nothing at all: this function never
    reads those names. `env` defaults to `os.environ`, matching
    `pfsense_mcp.config.load_config`'s existing testable-injection
    convention."""

    source = env if env is not None else os.environ

    missing = [name for name in _REQUIRED_VARS if not source.get(name)]
    if missing:
        raise LabConfigError(
            f"Lab configuration requires all of {', '.join(_REQUIRED_VARS)} to be set; missing: {', '.join(missing)}."
        )

    base_url = source["PFSENSE_LAB_API_URL"]
    if not _host_is_lab_allowed(base_url):
        raise LabConfigError(f"{base_url!r} does not match the lab-only host allow-list.")

    return LabConfig(
        base_url=base_url,
        identity=source["PFSENSE_LAB_IDENTITY"],
        key_file=Path(source["PFSENSE_LAB_API_KEY_FILE"]),
        candidate=source["PFSENSE_LAB_CANDIDATE"],
    )


def load_lab_key_material(key_file: Path) -> str:
    """Reads the lab API key through one non-following descriptor,
    reusing `pfsense_mcp.secure_file`'s generic O_NOFOLLOW/fstat
    primitives — never `pfsense_mcp.config.load_api_key()` itself, which
    is scoped to the production credential path (I2). The returned value
    must never be logged, printed, or included in any exception message
    by any caller."""

    descriptor = open_nofollow(key_file, on_error=LabConfigError)
    try:
        validate_descriptor(key_file, descriptor, max_bytes=_KEY_FILE_MAX_BYTES, on_error=LabConfigError)
        try:
            first_line = os.read(descriptor, _KEY_LINE_MAX_LENGTH + 1).split(b"\n", maxsplit=1)[0]
        except OSError:
            raise LabConfigError(f"Lab key file could not be read: {key_file}") from None
    finally:
        try:
            os.close(descriptor)
        except OSError:
            raise LabConfigError(f"Lab key file descriptor could not be closed: {key_file}") from None

    if len(first_line) > _KEY_LINE_MAX_LENGTH:
        raise LabConfigError(f"Lab key file first line is too long: {key_file}")
    if b"\x00" in first_line:
        raise LabConfigError(f"Lab key file first line contains a NUL byte: {key_file}")
    if any(byte < 32 or byte == 127 for byte in first_line):
        raise LabConfigError(f"Lab key file first line contains control characters: {key_file}")
    try:
        key = first_line.decode("utf-8").strip()
    except UnicodeDecodeError:
        raise LabConfigError(f"Lab key file first line is not valid UTF-8: {key_file}") from None
    if not key:
        raise LabConfigError(f"Lab key file is empty: {key_file}")
    return key
