from __future__ import annotations

import re
from pathlib import Path

CI = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
CODEQL = Path(__file__).parents[1] / ".github" / "workflows" / "codeql.yml"
FULL_SHA_ACTION = re.compile(r"uses:\s+[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$")


def _workflow_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _top_level_permissions(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^permissions:\n(?P<body>(?:  [a-z-]+: [a-z]+\n)+)", text)
    assert match is not None
    return dict(line.strip().split(": ", maxsplit=1) for line in match.group("body").splitlines())


def test_ci_has_supported_python_matrix_and_required_offline_checks():
    text = _workflow_text(CI)
    assert 'python-version: ["3.11", "3.12", "3.13"]' in text
    for command in ("ruff format --check", "ruff check", "mypy", "pytest -q", "make quick"):
        assert command in text
    assert "make coverage" in text
    assert "verify_distribution.py" in text
    assert "make security-static" in text


def test_public_ci_has_no_live_opt_in_or_production_configuration():
    combined = _workflow_text(CI) + _workflow_text(CODEQL)
    assert "PFSENSE_RUN_LIVE_TESTS" not in combined
    assert "PFSENSE_API_KEY_FILE" not in combined
    assert "192.168." not in combined
    assert "pfsense.example" not in combined


def test_workflow_actions_are_pinned_to_full_commit_shas():
    uses_lines = [
        line.strip()
        for path in (CI, CODEQL)
        for line in _workflow_text(path).splitlines()
        if line.strip().startswith("- uses:")
    ]
    assert uses_lines
    assert all(FULL_SHA_ACTION.search(line) for line in uses_lines)


def test_ci_permissions_are_read_only_and_no_release_steps_exist():
    text = _workflow_text(CI)
    assert "contents: read" in text
    assert "contents: write" not in text
    assert "security-events: write" not in text
    assert "gh release" not in text
    assert "git push" not in text


def test_codeql_has_only_required_read_permissions():
    text = _workflow_text(CODEQL)

    assert _top_level_permissions(text) == {
        "actions": "read",
        "contents": "read",
        "packages": "read",
    }


def test_codeql_private_repository_mode_runs_analysis_without_sarif_upload():
    text = _workflow_text(CODEQL)

    assert "github/codeql-action/init@" in text
    assert "github/codeql-action/analyze@" in text
    assert "languages: python" in text
    assert "upload: never" in text
    assert "upload-sarif" not in text
    assert "security-events:" not in text
