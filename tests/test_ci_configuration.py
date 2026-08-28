from __future__ import annotations

import re
from pathlib import Path

CI = Path(__file__).parents[1] / ".github" / "workflows" / "ci.yml"
CODEQL = Path(__file__).parents[1] / ".github" / "workflows" / "codeql.yml"
PUBLISH = Path(__file__).parents[1] / ".github" / "workflows" / "publish.yml"
FULL_SHA_ACTION = re.compile(r"uses:\s+[^@\s]+@[0-9a-f]{40}(?:\s+#.*)?$")
PYPI_PUBLISH_V1_14_2_COMMIT = "dc37677b2e1c63e2034f94d8a5b11f265b73ba33"


def _workflow_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _top_level_permissions(text: str) -> dict[str, str]:
    match = re.search(r"(?m)^permissions:\n(?P<body>(?:  [a-z-]+: [a-z]+\n)+)", text)
    assert match is not None
    return dict(line.strip().split(": ", maxsplit=1) for line in match.group("body").splitlines())


def test_ci_has_supported_python_matrix_and_required_offline_checks():
    text = _workflow_text(CI)
    assert 'python-version: ["3.11", "3.12", "3.13"]' in text
    for command in ("ruff format --check", "ruff check", "mypy", "make quick"):
        assert command in text
    # The full offline pytest suite is required, but only via `make quick`'s
    # own [4/11] stage now -- a standalone `pytest -q` CI step would be a
    # second, redundant full-suite run in the same job/environment/SHA.
    assert "pytest -q" not in text
    assert "make coverage" in text
    assert "verify_distribution.py" in text
    assert "make security-static" in text


def test_ci_package_build_tool_is_bounded():
    assert "python -m pip install 'build>=1.2,<2.0'" in _workflow_text(CI)


def test_public_ci_has_no_live_opt_in_or_production_configuration():
    combined = _workflow_text(CI) + _workflow_text(CODEQL) + _workflow_text(PUBLISH)
    assert "PFSENSE_RUN_LIVE_TESTS" not in combined
    assert "PFSENSE_API_KEY_FILE" not in combined
    assert "192.168." not in combined
    assert "pfsense.example" not in combined


def test_workflow_actions_are_pinned_to_full_commit_shas():
    uses_lines = [
        line.strip()
        for path in (CI, CODEQL, PUBLISH)
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


def test_codeql_has_only_required_permissions():
    text = _workflow_text(CODEQL)

    assert _top_level_permissions(text) == {
        "actions": "read",
        "contents": "read",
        "packages": "read",
        "security-events": "write",
    }


def test_codeql_public_repository_mode_uploads_sarif():
    # This repository is public, so GitHub Code Scanning is free regardless
    # of GitHub Advanced Security licensing (that licensing requirement
    # only applies to private repositories) -- confirmed via `gh api` during
    # the v1.0.0 Phase 2 hardening audit, H1. `upload: never` was based on a
    # false "private repository" premise and silently discarded every
    # finding; `upload: always` populates Security > Code Scanning with
    # real, browsable findings.
    text = _workflow_text(CODEQL)

    assert "github/codeql-action/init@" in text
    assert "github/codeql-action/analyze@" in text
    assert "languages: python" in text
    assert "upload: always" in text
    assert "security-events: write" in text


def test_pypi_publish_workflow_is_oidc_only_and_disabled_by_default():
    text = _workflow_text(PUBLISH)

    assert "types: [published]" in text
    assert "workflow_dispatch:" in text
    assert "PYPI_TRUSTED_PUBLISHING_ENABLED == 'true'" in text
    assert "inputs.confirm == 'publish-pfsense-mcp-server'" in text
    assert "cancel-in-progress: false" in text
    assert "environment:" in text
    assert "name: pypi" in text
    assert "id-token: write" in text
    assert "contents: read" in text
    assert "contents: write" not in text
    assert "security-events:" not in text
    assert "password:" not in text
    assert "user:" not in text
    assert "secrets." not in text
    assert "pypa/gh-action-pypi-publish@" in text


def test_pypi_publish_action_uses_release_commit_not_annotated_tag_object():
    text = _workflow_text(PUBLISH)

    assert f"pypa/gh-action-pypi-publish@{PYPI_PUBLISH_V1_14_2_COMMIT}" in text


def test_pypi_publish_workflow_builds_verified_tagged_artifacts_before_publish():
    text = _workflow_text(PUBLISH)

    assert 'if [ "$RELEASE_TAG" != "v$package_version" ]' in text
    assert "Release tag does not match the package version" in text
    assert "Refusing to build with a pre-existing dist directory" in text
    assert "python -m build --sdist --wheel" in text
    assert "verify_distribution.py dist" in text
    assert "twine check --strict dist/*" in text
    assert "needs: build" in text
    assert "packages-dir: dist/" in text
    assert "attestations: true" in text
