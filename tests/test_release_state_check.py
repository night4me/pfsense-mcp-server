"""Adversarial coverage for release_state_check.py's phase-aware model.

The checker distinguishes a pre-publish **candidate** state (this
version prepared on `main`, not yet tagged/released/published) from a
post-publish **published** state (a real `v{version}` tag exists and is
reachable from `HEAD`). The phase itself is derived from that one
objective git fact only -- never from any document's own self-reported
status text -- so these tests build small, disposable git repositories
under `tmp_path` and control the tag/commit graph directly, rather than
only asserting against this repository's own current state.
"""

from __future__ import annotations

import subprocess  # nosec B404
from pathlib import Path

import pytest

from scripts.release_state_check import (
    ROOT,
    candidate_release_checks,
    determine_release_phase,
    published_release_checks,
    release_checks,
)

# --- disposable git-repo builder -----------------------------------------


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)  # nosec B603 B607


def _build_repo(
    root: Path,
    *,
    version: str,
    tag_version: str | None = None,
    acceptance_status: str | None = "candidate",
    acceptance_filename_version: str | None = None,
    changelog_dated: bool = False,
    readme_claims_baseline: bool = False,
    extra_commit_after_tag: bool = False,
) -> Path:
    """Builds a minimal, real git repository (not a mock) with just
    enough structure for release_state_check.py's own file reads and
    git calls to operate on. `acceptance_filename_version`, if given,
    writes the ACCEPTANCE doc under a *different* version's filename
    than `version` itself -- simulating a cross-binding mistake."""

    (root / "pyproject.toml").write_text(
        f'[project]\nname = "x"\nversion = "{version}"\nlicense = "MIT"\n', encoding="utf-8"
    )
    (root / "LICENSE").write_text("MIT License\n", encoding="utf-8")

    changelog = ["# Changelog\n\n## [Unreleased]\n\n"]
    if changelog_dated:
        changelog.append(f"## [{version}] - 2026-01-01\n\ncontent\n")
    (root / "CHANGELOG.md").write_text("".join(changelog), encoding="utf-8")

    readme = ["# Project\n\n## Release status\n\n"]
    if readme_claims_baseline:
        readme.append(f"**v{version} is the immutable production baseline, published on PyPI**\n")
    else:
        readme.append("**v0.0.0 is the immutable production baseline, published on PyPI**\n")
    (root / "README.md").write_text("".join(readme), encoding="utf-8")

    docs = root / "docs"
    docs.mkdir(exist_ok=True)
    acceptance_version = acceptance_filename_version or version
    if acceptance_status == "candidate":
        (docs / f"ACCEPTANCE_v{acceptance_version}.md").write_text(
            "**Status: release-candidate, not yet tagged, not yet released, not yet published to PyPI.**\n",
            encoding="utf-8",
        )
    elif acceptance_status == "published":
        (docs / f"ACCEPTANCE_v{acceptance_version}.md").write_text(
            "**Status: published -- the tag and PyPI release point at this commit.**\n",
            encoding="utf-8",
        )
    elif acceptance_status == "malformed":
        (docs / f"ACCEPTANCE_v{acceptance_version}.md").write_text("no status line here\n", encoding="utf-8")
    # acceptance_status is None: don't create the file at all.

    _git(root, "init", "--quiet", "--initial-branch=main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "initial")

    if tag_version:
        _git(root, "tag", f"v{tag_version}")
        if extra_commit_after_tag:
            (root / "NOTE.md").write_text("post-tag follow-up\n", encoding="utf-8")
            _git(root, "add", "-A")
            _git(root, "commit", "--quiet", "-m", "follow-up")

    return root


# --- 1: valid candidate state passes candidate check ----------------------


def test_valid_candidate_state_passes_candidate_check(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", acceptance_status="candidate")
    assert determine_release_phase(root, "0.8.0") == "candidate"
    checks = candidate_release_checks(root, "0.8.0")
    assert all(checks.values()), checks


# --- 2: candidate falsely claiming PyPI publication fails -----------------


def test_candidate_falsely_claiming_publication_fails(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", tag_version=None, acceptance_status="published")
    assert determine_release_phase(root, "0.8.0") == "candidate"
    checks = candidate_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["ACCEPTANCE doc honestly declares release-candidate status"] is False


# --- 3: candidate with missing ACCEPTANCE doc fails ------------------------


def test_candidate_with_missing_acceptance_doc_fails(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", acceptance_status=None)
    checks = candidate_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["docs/ACCEPTANCE_v0.8.0.md exists"] is False


# --- 4: candidate with wrong version (cross-binding) fails -----------------


def test_candidate_with_acceptance_doc_for_wrong_version_fails(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", acceptance_status="candidate", acceptance_filename_version="0.8.1")
    checks = candidate_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["docs/ACCEPTANCE_v0.8.0.md exists"] is False


# --- 5: candidate prematurely dated/released inconsistently fails ---------


def test_candidate_with_premature_changelog_heading_fails(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", tag_version=None, changelog_dated=True)
    assert determine_release_phase(root, "0.8.0") == "candidate"
    checks = candidate_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["CHANGELOG has no dated '## [0.8.0] -' heading yet"] is False


# --- 6: valid published state passes published check -----------------------


def test_valid_published_state_passes_published_check(tmp_path):
    root = _build_repo(
        tmp_path,
        version="0.8.0",
        tag_version="0.8.0",
        acceptance_status="published",
        changelog_dated=True,
        readme_claims_baseline=True,
    )
    assert determine_release_phase(root, "0.8.0") == "published"
    checks = published_release_checks(root, "0.8.0")
    assert all(checks.values()), checks


# --- 7: published mode with candidate ACCEPTANCE status fails --------------


def test_published_with_candidate_acceptance_status_fails(tmp_path):
    root = _build_repo(
        tmp_path,
        version="0.8.0",
        tag_version="0.8.0",
        acceptance_status="candidate",
        changelog_dated=True,
        readme_claims_baseline=True,
    )
    assert determine_release_phase(root, "0.8.0") == "published"
    checks = published_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["ACCEPTANCE doc declares published status"] is False


# --- 8: published mode with [Unreleased] instead of dated release fails ---


def test_published_with_unreleased_changelog_fails(tmp_path):
    root = _build_repo(
        tmp_path,
        version="0.8.0",
        tag_version="0.8.0",
        acceptance_status="published",
        changelog_dated=False,
        readme_claims_baseline=True,
    )
    assert determine_release_phase(root, "0.8.0") == "published"
    checks = published_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["released changelog heading"] is False


# --- 9: published mode with stale README baseline fails ---------------------


def test_published_with_stale_readme_baseline_fails(tmp_path):
    root = _build_repo(
        tmp_path,
        version="0.8.0",
        tag_version="0.8.0",
        acceptance_status="published",
        changelog_dated=True,
        readme_claims_baseline=False,
    )
    assert determine_release_phase(root, "0.8.0") == "published"
    checks = published_release_checks(root, "0.8.0")
    assert not all(checks.values())
    assert checks["README immutable production baseline"] is False


# --- 10: wrong release/version cross-binding fails -------------------------


def test_unrelated_tag_for_a_different_version_does_not_grant_published_phase(tmp_path):
    """A `v0.7.2` tag existing and being reachable must never cause the
    checker to treat the *current* `0.8.0` version as published -- the
    phase decision is version-specific, not "any tag exists"."""

    root = _build_repo(tmp_path, version="0.8.0", tag_version="0.7.2", acceptance_status="candidate")
    assert determine_release_phase(root, "0.8.0") == "candidate"
    # The candidate rule set must still apply normally, independent of
    # the unrelated v0.7.2 tag's existence.
    checks = candidate_release_checks(root, "0.8.0")
    assert all(checks.values()), checks


def test_tag_not_reachable_from_head_does_not_grant_published_phase(tmp_path):
    """A `v0.8.0` tag that exists but points at a commit *not* reachable
    from the current `HEAD` (e.g. an orphaned/rewritten branch) must not
    grant published phase."""

    root = _build_repo(tmp_path, version="0.8.0", tag_version="0.8.0")
    # Move HEAD to a new, unrelated root commit so the v0.8.0 tag is no
    # longer an ancestor of HEAD.
    _git(root, "checkout", "--orphan", "other")
    (root / "UNRELATED.md").write_text("unrelated\n", encoding="utf-8")
    _git(root, "add", "-A")
    _git(root, "commit", "--quiet", "-m", "unrelated root")
    assert determine_release_phase(root, "0.8.0") == "candidate"


# --- 11: candidate mode cannot be used to certify post-publication completeness --


def test_candidate_passing_is_never_sufficient_for_published_certification(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", tag_version=None, acceptance_status="candidate")
    candidate_checks = candidate_release_checks(root, "0.8.0")
    assert all(candidate_checks.values())
    # The exact same repository state, evaluated under published rules,
    # must not be all-True -- proving candidate validity is categorically
    # insufficient evidence of real publication.
    published_checks = published_release_checks(root, "0.8.0")
    assert not all(published_checks.values())


# --- 12: no existing security/public-contract behavior changes -----------


def test_release_state_check_changes_do_not_touch_the_public_mcp_contract():
    """This task's scope is `scripts/release_state_check.py` and this
    test file only -- guard that against drift by re-deriving the public
    contract fresh and confirming it is exactly what every prior session
    already established: 101 READ + 2 guidance + 0 WRITE."""

    import public_contract

    contract = public_contract.build_contract()
    tools = contract["tools"]
    assert len(tools) == 103
    assert sum(1 for t in tools if t["tool_class"] == "read") == 101
    assert sum(1 for t in tools if t["tool_class"] == "guidance") == 2
    assert not any(t["tool_class"] == "write" for t in tools)


# --- top-level dispatch sanity ---------------------------------------------


def test_release_checks_top_level_dispatch_includes_phase(tmp_path):
    root = _build_repo(tmp_path, version="0.8.0", tag_version=None, acceptance_status="candidate")
    result = release_checks(root)
    assert result["phase"] == "candidate"
    assert all(v for k, v in result.items() if k != "phase")


# --- real-repository check --------------------------------------------------


def test_current_repository_is_a_valid_release_candidate():
    """The real repository, at whatever commit this test runs from, must
    always be *some* valid, honest state -- either a clean candidate (no
    tag yet for the current `pyproject.toml` version) or a clean
    published release (tag exists and is reachable). Never neither."""

    result = release_checks(ROOT)
    phase = result["phase"]
    assert phase in ("candidate", "published")
    failures = {k: v for k, v in result.items() if k != "phase" and not v}
    assert failures == {}, f"phase={phase}, failures={failures}"


@pytest.mark.parametrize("phase_hint", ["candidate", "published"])
def test_determine_release_phase_is_stable_under_repeated_calls(tmp_path, phase_hint):
    tag_version = "0.8.0" if phase_hint == "published" else None
    root = _build_repo(tmp_path, version="0.8.0", tag_version=tag_version)
    first = determine_release_phase(root, "0.8.0")
    second = determine_release_phase(root, "0.8.0")
    assert first == second == phase_hint
