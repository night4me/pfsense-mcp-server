#!/usr/bin/env python3
"""security_scan.py — repo-wide scan for real IPs, real MAC addresses,
credential paths, and API-key-adjacent hints across every file that
could conceivably be committed.

Every tracked/untracked (non-ignored) file is scanned in full, line by
line. There is no whole-file exclusion mechanism.

The one narrow escape hatch — the marker comment defined below as
_SUPPRESSION_MARKER — is honored ONLY in the explicit allow-list below
(_APPROVED_MARKER_FILES): the adversarial unit tests for this scanner
and its sibling fixture checker, which must deliberately embed
known-bad example values (a real-looking IP, a vendor MAC, a
credential path) to prove the checkers catch them. It suppresses
exactly the one marked line, never a whole file — any other unmarked
line in the same approved file, including a genuinely leaked secret,
is still scanned and would still fail.

A marker found anywhere else (src/, scripts/ itself, tests/fixtures/,
project configuration, README/documentation) is NOT honored — the
underlying line is still fully checked, AND the unauthorized marker is
itself reported as a finding.

Read-only. Never modifies anything. Exits 0 (clean) or 1 (findings
printed to stderr).
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from lib.security_patterns import (
    find_ipv4_literals,
    find_mac_literals,
    is_locally_administered_mac,
    is_safe_ipv4,
)

# Deliberately constructed via concatenation rather than as one
# contiguous literal: markers are not honored in scripts/ (this file
# included, per _APPROVED_MARKER_FILES below), so this scanner's own
# pattern definitions must not contain their complete literal form —
# otherwise this line would flag itself with no way to suppress it.
_CREDENTIAL_PATH_PATTERNS = ("api-mcp-admin" + ".key", "/private" + "/pfsense")

# Built via concatenation, not one contiguous literal — the definition
# line itself would otherwise self-match as an "unauthorized marker"
# (this file is not in _APPROVED_MARKER_FILES).
_SUPPRESSION_MARKER = "security-scan" + ": allow"

# The ONLY files in which _SUPPRESSION_MARKER is honored. Deliberately
# a narrow, explicit allow-list rather than a path pattern: adding a
# new adversarial test file to this scanner's own test suite requires
# a conscious edit here, not an incidental match.
_APPROVED_MARKER_FILES = {
    "tests/test_security_patterns.py",
    "tests/test_security_scan.py",
    "tests/test_fixture_safety.py",
}

# Binary/large files that are never meaningfully "scanned" as text and
# would only produce noise (none currently exist in this repo, but
# scanning is skipped defensively rather than erroring on decode failure).
_SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf"}


def _commit_candidate_files() -> list[Path]:
    output = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return [Path(line) for line in output.splitlines() if line]


def scan_line(path: Path, lineno: int, line: str) -> list[str]:
    findings = []

    has_marker = _SUPPRESSION_MARKER in line
    marker_is_authorized = str(path) in _APPROVED_MARKER_FILES

    if has_marker and not marker_is_authorized:
        findings.append(
            f"{path}:{lineno}: unauthorized suppression marker "
            f"(markers are only honored in: {', '.join(sorted(_APPROVED_MARKER_FILES))})"
        )

    if has_marker and marker_is_authorized:
        return findings

    for ip in find_ipv4_literals(line):
        if not is_safe_ipv4(ip):
            findings.append(f"{path}:{lineno}: non-RFC5737 IPv4 literal found: {ip}")

    for mac in find_mac_literals(line):
        if not is_locally_administered_mac(mac):
            findings.append(f"{path}:{lineno}: MAC address without locally-administered bit set: {mac}")

    for pattern in _CREDENTIAL_PATH_PATTERNS:
        if pattern in line:
            findings.append(f"{path}:{lineno}: credential-path-like string found: {pattern!r}")

    return findings


def scan_text(path: Path, text: str) -> list[str]:
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        findings.extend(scan_line(path, lineno, line))
    return findings


def run() -> list[str]:
    findings = []
    for path in _commit_candidate_files():
        if path.suffix.lower() in _SKIP_SUFFIXES or not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        findings.extend(scan_text(path, text))
    return findings


def main() -> int:
    findings = run()
    if findings:
        print("security_scan: FAILED", file=sys.stderr)
        for f in findings:
            print(f"  {f}", file=sys.stderr)
        return 1
    print("security_scan: OK (no real IPs, MACs, or credential paths found)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
