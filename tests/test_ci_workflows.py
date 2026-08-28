"""Structural tests for CI workflow content (v1.0.0 Phase 2 hardening,
H1/H2). Parse the workflow files as text directly (never invoke `gh`/
GitHub Actions, matching this repository's own established pattern for
`tests/test_makefile_quick_target.py`) to confirm the constraints agreed
for this hardening pass:

- `codeql.yml` uploads SARIF (`upload: always`) and grants
  `security-events: write` -- both were missing before this arc, when
  `upload: never` silently discarded every finding.
- `ci.yml` has a `release-state` job that runs
  `scripts/release_state_check.py`, `scripts/validate_docs.py`, and
  `scripts/fixture_safety.py` against a `fetch-depth: 0` checkout --
  the exact standalone scripts whose end-to-end invocation against real
  repository state was previously never exercised anywhere in CI.
"""

from __future__ import annotations

import re
from pathlib import Path

WORKFLOWS = Path(__file__).resolve().parent.parent / ".github" / "workflows"

#: Matches the real YAML key (start-of-line, ignoring leading
#: whitespace) -- never a `#`-comment mentioning the same words as
#: historical prose, which this file's own comment does deliberately.
_UPLOAD_KEY_RE = re.compile(r"^\s*upload:\s*(\S+)\s*$", re.MULTILINE)


def _text(name: str) -> str:
    return (WORKFLOWS / name).read_text(encoding="utf-8")


def test_codeql_uploads_sarif():
    text = _text("codeql.yml")
    match = _UPLOAD_KEY_RE.search(text)
    assert match is not None, "no `upload:` key found in codeql.yml"
    assert match.group(1) == "always"


def test_codeql_has_security_events_write_permission():
    text = _text("codeql.yml")
    assert "security-events: write" in text


def test_ci_has_release_state_job():
    text = _text("ci.yml")
    assert "release-state:" in text


def test_release_state_job_runs_all_three_scripts():
    text = _text("ci.yml")
    job_start = text.index("release-state:")
    next_job = text.index("\n  docs:", job_start)
    job_text = text[job_start:next_job]

    assert "scripts/release_state_check.py" in job_text
    assert "scripts/validate_docs.py" in job_text
    assert "scripts/fixture_safety.py" in job_text
    assert "fetch-depth: 0" in job_text


def test_no_workflow_comment_calls_this_repository_private():
    # This repository is public (confirmed via `gh api` during v1.0.0
    # Phase 2 H1) -- a stale "private repository" premise in a workflow
    # comment previously masked why SARIF upload was disabled. Guard
    # against it silently reappearing.
    for name in ("codeql.yml", "ci.yml"):
        assert "private repository" not in _text(name).lower()
