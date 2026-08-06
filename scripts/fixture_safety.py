#!/usr/bin/env python3
"""fixture_safety.py — deeper, fixture-specific safety checks beyond
the repo-wide security_scan.py: only RFC 5737 IP ranges (or netmask/
loopback, which are structural, not host, values), only locally-
administered MAC placeholders, no real Netgate IDs, no credential
paths, and an advisory (non-failing) heuristic against accidentally
committing a large, unsanitized live response.

Read-only. Exits 0 (clean, possibly with advisory warnings printed)
or 1 (a hard-failure finding was found).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.security_patterns import (  # noqa: E402
    find_ipv4_literals,
    find_mac_literals,
    is_locally_administered_mac,
    is_safe_ipv4,
)
from lib.security_policy import find_prohibited_credential_fields  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"

_APPROVED_NETGATE_ID_PLACEHOLDER = "ANONYMIZED0000000000"
# Constructed via concatenation rather than as one contiguous literal:
# security-scan markers are not honored in scripts/, so this file's own
# pattern definitions must not contain their complete literal form.
_CREDENTIAL_PATH_PATTERNS = ("api-mcp-admin" + ".key", "/private" + "/pfsense")

# Advisory only: a fixture whose top-level "data" array is larger than
# this looks like it might be an unsanitized full live dump rather than
# a small synthetic example. Not a hard guarantee — flagged for human
# review, never a pipeline failure on its own.
_ADVISORY_MAX_DATA_ENTRIES = 10


def _fixture_files() -> list[Path]:
    return sorted(FIXTURES_DIR.glob("*.json"))


def _find_netgate_ids(obj) -> list[str]:
    found = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "netgate_id" and isinstance(value, str):
                found.append(value)
            found.extend(_find_netgate_ids(value))
    elif isinstance(obj, list):
        for item in obj:
            found.extend(_find_netgate_ids(item))
    return found


def check_fixture_text(name: str, text: str) -> tuple[list[str], list[str]]:
    """Returns (hard_failures, advisories). Pure function of the
    fixture's display name and raw text, so it's testable against
    synthetic content without touching the filesystem."""
    failures: list[str] = []
    advisories: list[str] = []

    for ip in find_ipv4_literals(text):
        if not is_safe_ipv4(ip):
            failures.append(f"{name}: non-RFC5737 IPv4 literal found: {ip}")

    for mac in find_mac_literals(text):
        if not is_locally_administered_mac(mac):
            failures.append(f"{name}: MAC address without locally-administered bit set: {mac}")

    for pattern in _CREDENTIAL_PATH_PATTERNS:
        if pattern in text:
            failures.append(f"{name}: credential-path-like string found: {pattern!r}")

    doc = json.loads(text)

    for field_path in find_prohibited_credential_fields(doc):
        failures.append(f"{name}: prohibited credential field found at {field_path}")

    for netgate_id in _find_netgate_ids(doc):
        if netgate_id != _APPROVED_NETGATE_ID_PLACEHOLDER:
            failures.append(f"{name}: netgate_id is not the approved placeholder: {netgate_id!r}")

    data = doc.get("data") if isinstance(doc, dict) else doc
    if isinstance(data, list) and len(data) > _ADVISORY_MAX_DATA_ENTRIES:
        advisories.append(
            f"{name}: 'data' array has {len(data)} entries (> {_ADVISORY_MAX_DATA_ENTRIES}); "
            "review to confirm this is still a small synthetic fixture, not a full live dump."
        )

    return failures, advisories


def check_fixture(path: Path) -> tuple[list[str], list[str]]:
    return check_fixture_text(path.name, path.read_text(encoding="utf-8"))


def run() -> tuple[list[str], list[str]]:
    all_failures: list[str] = []
    all_advisories: list[str] = []
    for path in _fixture_files():
        failures, advisories = check_fixture(path)
        all_failures.extend(failures)
        all_advisories.extend(advisories)
    return all_failures, all_advisories


def main() -> int:
    failures, advisories = run()

    if advisories:
        print("fixture_safety: ADVISORY")
        for a in advisories:
            print(f"  {a}")

    if failures:
        print("fixture_safety: FAILED", file=sys.stderr)
        for f in failures:
            print(f"  {f}", file=sys.stderr)
        return 1

    print("fixture_safety: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
