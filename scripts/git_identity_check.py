#!/usr/bin/env python3
"""Fail closed when Git identity (configured or committed) matches a
known-leaked personal identity.

Exists because of a real incident (2026-08-09): the Public Exposure
Audit's history rewrite corrected every historical commit's
author/committer identity, but nothing checked the local clone's own Git
identity *configuration* going forward -- it still held the real personal
identity, so two ordinary commits silently carried it again, undetected
by `make quick`/`make validate`/`security_scan.py` (none of which inspect
commit metadata) through a full CI/CodeQL-green cycle.

Deliberately does not store the leaked name/email as plaintext in this
public source file -- that would recreate exactly the disclosure this
check exists to prevent. It stores a SHA-256 hash of each forbidden
value instead and compares hashes, the same non-reversible-comparison
principle used elsewhere in this project (e.g. HMAC-authenticated
records) applied to a much simpler problem.

This is a blocklist, not an allowlist: it rejects one specific known-bad
identity, not anything other than one approved maintainer identity --
this repository accepts external contributions, and a real contributor's
own name/email on their own commits is normal and correct, not a finding.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

#: SHA-256 of the exact leaked values, lowercased. Never the plaintext --
#: see module docstring. Extend this set only for a confirmed, resolved
#: leak; it is a historical-incident blocklist, not a general policy.
_FORBIDDEN_IDENTITY_HASHES = frozenset(
    {
        "22d414ba6eb6c9fe7e60f6b405d99655b92b49ebb00075d70b056b26a5f55519",  # leaked personal email
        "97cd9aed69e0bb8804e03591d2906a89b284a652973cda3112f639d82bfc44e4",  # leaked personal username
    }
)

#: How many of the most recent commits reachable from HEAD to check.
#: Bounded deliberately: the one-time historical rewrite is already
#: verified across full history separately (see
#: reports-ai/reviews/PUBLIC_EXPOSURE_AUDIT.md); this check's job is
#: catching a *new* leak in *new* commits going forward, which will
#: always be recent. A shallow CI checkout naturally limits this further
#: to whatever commits are actually present.
_RECENT_COMMIT_WINDOW = 20


class GitIdentityLeakError(ValueError):
    """A known-leaked personal identity was found in Git identity or commit metadata."""


def _hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def _run_git(*args: str) -> str | None:
    try:
        result = subprocess.run(["git", *args], capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None
    return result.stdout.strip()


def check_configured_identity() -> list[str]:
    """Flag the locally configured commit identity, if set and forbidden.

    Unset configuration is not itself a finding -- this check has nothing
    to compare in that case, and Git will not let an unconfigured
    identity author a commit anyway.
    """

    findings: list[str] = []
    name = _run_git("config", "--get", "user.name")
    email = _run_git("config", "--get", "user.email")
    if name and _hash(name) in _FORBIDDEN_IDENTITY_HASHES:
        findings.append("configured git user.name matches a known-leaked identity")
    if email and _hash(email) in _FORBIDDEN_IDENTITY_HASHES:
        findings.append("configured git user.email matches a known-leaked identity")
    return findings


def check_recent_commit_identity(window: int = _RECENT_COMMIT_WINDOW) -> list[str]:
    """Flag any of the most recent reachable commits carrying a forbidden
    author or committer identity."""

    log = _run_git(
        "log",
        f"-{window}",
        "--format=%H%x1f%an%x1f%ae%x1f%cn%x1f%ce",
    )
    if not log:
        return []

    findings: list[str] = []
    for line in log.splitlines():
        parts = line.split("\x1f")
        if len(parts) != 5:
            continue
        sha, author_name, author_email, committer_name, committer_email = parts
        for role, name, email in (
            ("author", author_name, author_email),
            ("committer", committer_name, committer_email),
        ):
            if _hash(name) in _FORBIDDEN_IDENTITY_HASHES or _hash(email) in _FORBIDDEN_IDENTITY_HASHES:
                findings.append(f"{sha[:12]}: {role} matches a known-leaked identity")
    return findings


def check_git_identity(repo_root: Path | None = None) -> list[str]:
    """Run every check. `repo_root`, if given, is used only to `cd` there
    first (tests construct a throwaway repo elsewhere on disk)."""

    import os

    original_cwd = Path.cwd()
    try:
        if repo_root is not None:
            os.chdir(repo_root)
        return [*check_configured_identity(), *check_recent_commit_identity()]
    finally:
        os.chdir(original_cwd)


def main() -> int:
    findings = check_git_identity()
    if findings:
        print("git_identity_check: FAILED")
        for finding in findings:
            print(f"  - {finding}")
        print(
            "  Fix: git config user.name/user.email to the project's public "
            "identity, and if a commit already carries the leaked identity, "
            "it must be corrected before pushing (see AGENTS.md's approval "
            "boundaries -- history rewriting requires explicit approval)."
        )
        return 1
    print("git_identity_check: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
