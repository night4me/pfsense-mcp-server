#!/usr/bin/env python3
"""audit_fixture.py — independent, untrusting re-verification gate for
a capture_fixture.py proposal, before it may be copied into
tests/fixtures/.

Treats the proposal (and its manifest) as untrusted input, even though
.fixture_proposals/ is gitignored: everything here is re-derived from
the files on disk, nothing capture_fixture.py claimed at capture time
is trusted without independent re-verification. Checks, in order:
  1. the proposal's SHA-256 matches the manifest's recorded digest
     (refuses if either file changed since capture),
  2. the manifest schema version is understood,
  3. fixture_safety.check_fixture_text() passes (reused, not
     duplicated),
  4. security_scan.scan_text() passes (reused, not duplicated —
     the proposal path is never in security_scan's
     _APPROVED_MARKER_FILES, so any suppression marker inside it is
     correctly treated as unauthorized),
  5. the declared response shape/item count match what the proposal
     file actually contains,
  6. every IP/MAC literal is from an approved documentation range,
  7. no sensitive-looking field remains unaccounted for (reuses
     sanitizer.audit_sanitized_data, the same function
     capture_fixture.py's own self-check already ran).

Without --approve: reports pass/fail only, never touches the
filesystem — safe to re-run at any time.

With --approve, and only if every check above passes: copies (never
moves) the proposal into tests/fixtures/<name>.json. Refuses to
overwrite an existing tracked fixture. Never executes `git add` —
only prints the command for a human to run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fixture_safety
import security_scan
from lib.capture_policies import CAPTURE_POLICIES
from lib.sanitizer import audit_sanitized_data

MANIFEST_SCHEMA_VERSION = 1
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
_PROPOSED_SUFFIX = ".proposed.json"


class AuditFailure(Exception):
    pass


def _manifest_path_for(proposal_path: Path) -> Path:
    if not proposal_path.name.endswith(_PROPOSED_SUFFIX):
        raise AuditFailure(f"{proposal_path.name}: expected a '*{_PROPOSED_SUFFIX}' file")
    base = proposal_path.name[: -len(_PROPOSED_SUFFIX)]
    return proposal_path.with_name(f"{base}.manifest.json")


def run_audit(proposal_path: Path) -> list[str]:
    """Returns a list of problems; empty means the proposal is clean."""
    if not proposal_path.is_file():
        return [f"proposal file not found: {proposal_path}"]

    manifest_path = _manifest_path_for(proposal_path)
    if not manifest_path.is_file():
        return [f"manifest file not found: {manifest_path}"]

    proposal_bytes = proposal_path.read_bytes()

    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"manifest is not valid JSON: {exc}"]

    schema_version = manifest.get("manifest_schema_version")
    if schema_version != MANIFEST_SCHEMA_VERSION:
        return [f"unrecognized manifest schema version: {schema_version!r} (expected {MANIFEST_SCHEMA_VERSION})"]

    recorded_digest = manifest.get("sha256_sanitized_proposal")
    actual_digest = hashlib.sha256(proposal_bytes).hexdigest()
    if recorded_digest != actual_digest:
        return [
            "proposal SHA-256 does not match the manifest — the proposal or manifest changed since capture "
            f"(recorded={recorded_digest!r}, actual={actual_digest!r})"
        ]

    try:
        proposal_data = json.loads(proposal_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return [f"proposal is not valid JSON: {exc}"]

    endpoint_symbol = manifest.get("endpoint_symbol")
    policy = CAPTURE_POLICIES.get(endpoint_symbol) if endpoint_symbol else None
    if policy is None:
        return [f"manifest's endpoint_symbol {endpoint_symbol!r} has no CAPTURE_POLICIES entry"]

    problems: list[str] = []

    proposal_text = proposal_bytes.decode("utf-8")
    fs_failures, _fs_advisories = fixture_safety.check_fixture_text(proposal_path.name, proposal_text)
    problems.extend(fs_failures)
    problems.extend(security_scan.scan_text(proposal_path, proposal_text))

    data = proposal_data.get("data")
    declared_shape = manifest.get("response_shape")
    if declared_shape == "list":
        if not isinstance(data, list):
            problems.append("manifest declares response_shape='list' but proposal 'data' is not a list")
        elif len(data) != manifest.get("item_count"):
            problems.append(
                f"manifest item_count ({manifest.get('item_count')}) does not match the proposal's "
                f"actual item count ({len(data)})"
            )
    elif declared_shape == "object":
        if not isinstance(data, dict):
            problems.append("manifest declares response_shape='object' but proposal 'data' is not an object")
    else:
        problems.append(f"manifest has an unrecognized response_shape: {declared_shape!r}")

    redacted_field_names = set(manifest.get("redacted_field_names") or [])
    problems.extend(audit_sanitized_data(proposal_data, policy, redacted_field_names=redacted_field_names))

    return problems


def approve(proposal_path: Path) -> Path:
    """Copies (never moves) the proposal into tests/fixtures/. Callers
    must have already confirmed run_audit() returned no problems."""
    base = proposal_path.name[: -len(_PROPOSED_SUFFIX)]
    target = FIXTURES_DIR / f"{base}.json"
    if target.exists():
        raise AuditFailure(
            f"refusing to overwrite existing tracked fixture: {target} "
            "(a replacement workflow is not yet designed — remove or rename the existing fixture "
            "manually first if a genuine replacement is intended)"
        )
    FIXTURES_DIR.mkdir(parents=True, exist_ok=True)
    target.write_bytes(proposal_path.read_bytes())
    return target


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_fixture.py",
        description="Independently re-verify a capture_fixture.py proposal before it may become a real fixture.",
    )
    parser.add_argument("proposal", type=Path)
    parser.add_argument("--approve", action="store_true", help="Copy into tests/fixtures/ if every check passes.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        problems = run_audit(args.proposal)
    except AuditFailure as exc:
        print(f"audit_fixture: FAILED\n  {exc}", file=sys.stderr)
        return 1

    if problems:
        print("audit_fixture: FAILED", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1

    print("audit_fixture: OK (all checks passed)")

    if not args.approve:
        print("audit_fixture: dry-run only (pass --approve to copy into tests/fixtures/)")
        return 0

    try:
        target = approve(args.proposal)
    except AuditFailure as exc:
        print(f"audit_fixture: APPROVE FAILED\n  {exc}", file=sys.stderr)
        return 1

    print(f"audit_fixture: approved -> {target}")
    print(f"  Next: git add {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
