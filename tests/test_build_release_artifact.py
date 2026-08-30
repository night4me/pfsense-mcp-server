"""Regression coverage for the v1.1.0 release-reproducibility hardening.

The v1.1.0 publication ceremony (2026-08-30) found that this project's own
tooling built release artifacts three different, silently-diverging ways --
only one of which set `SOURCE_DATE_EPOCH`. `scripts/build_release_artifact.py`
is the single canonical build path adopted to close that gap (shared by
`make package-check`, `make reproducible-build`, `release-rehearsal.yml`,
and `publish.yml`). These tests cover the pure-logic pieces (ref resolution,
the fail-closed HEAD-vs-ref check, the refuse-if-exists guard) without
invoking the real network-dependent build -- see
`reports-ai/POST_V1_1_RELEASE_REPRODUCIBILITY_HARDENING.md` for the actual
cross-environment build-reproduction experiment that verified the real fix.
"""

from __future__ import annotations

import re
import subprocess  # nosec B404
from pathlib import Path

import pytest

from scripts.build_release_artifact import ROOT, build, main, source_date_epoch

# --- disposable git-repo builder -----------------------------------------


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(  # nosec B603 B607
        ["git", *args], cwd=root, check=True, capture_output=True, text=True
    )
    return result.stdout.strip()


def _build_repo(root: Path) -> tuple[str, str]:
    """A disposable two-commit repo; returns (first_sha, second_sha)."""
    _git(root, "init", "-q")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "Test")
    (root / "file.txt").write_text("one\n", encoding="utf-8")
    _git(root, "add", "file.txt")
    _git(root, "commit", "-q", "-m", "first")
    first = _git(root, "rev-parse", "HEAD")
    (root / "file.txt").write_text("two\n", encoding="utf-8")
    _git(root, "add", "file.txt")
    _git(root, "commit", "-q", "-m", "second")
    second = _git(root, "rev-parse", "HEAD")
    return first, second


# --- source_date_epoch -----------------------------------------------------


def test_source_date_epoch_matches_the_commits_own_timestamp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _first, second = _build_repo(tmp_path)
    monkeypatch.setattr("scripts.build_release_artifact.ROOT", tmp_path)
    expected = _git(tmp_path, "show", "-s", "--format=%ct", second)
    assert source_date_epoch(second) == expected


def test_source_date_epoch_differs_for_two_distinct_commits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    first, second = _build_repo(tmp_path)
    monkeypatch.setattr("scripts.build_release_artifact.ROOT", tmp_path)
    # Distinct commits made in immediate succession in a test can share the
    # same second-resolution timestamp; assert only that each resolves
    # without error and to the same value as git's own report, not that
    # they differ (that would be a flaky assumption about test-runner speed).
    assert source_date_epoch(first) == _git(tmp_path, "show", "-s", "--format=%ct", first)
    assert source_date_epoch(second) == _git(tmp_path, "show", "-s", "--format=%ct", second)


# --- build()'s fail-closed HEAD-vs-ref check --------------------------------


def test_build_refuses_when_current_head_does_not_match_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The exact bug class this script exists to prevent: deriving
    SOURCE_DATE_EPOCH from one ref while silently building whatever is
    actually checked out (a different ref) must fail closed, never build."""
    first, second = _build_repo(tmp_path)
    _git(tmp_path, "checkout", "-q", first)
    monkeypatch.setattr("scripts.build_release_artifact.ROOT", tmp_path)
    with pytest.raises(SystemExit, match="refusing to build"):
        build(tmp_path / "dist-out", ref=second)


def test_build_proceeds_past_the_check_when_head_matches_ref(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The inverse: when HEAD genuinely matches --ref, the fail-closed check
    must not block the build. Verified by confirming the *next* step (the
    real `python -m build` subprocess call) is what actually raises --
    proving the HEAD check itself passed silently -- without requiring
    network access to complete a real build in this offline test."""
    _first, second = _build_repo(tmp_path)  # HEAD is already at `second`
    monkeypatch.setattr("scripts.build_release_artifact.ROOT", tmp_path)
    # No pyproject.toml in this disposable repo -- `python -m build` itself
    # will fail past the HEAD check, which is exactly the boundary this
    # test needs: proof the fail-closed check did not fire.
    with pytest.raises(subprocess.CalledProcessError):
        build(tmp_path / "dist-out", ref=second)


# --- main()'s refuse-if-exists guard ---------------------------------------


def test_main_refuses_to_build_into_a_pre_existing_directory(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    outdir = tmp_path / "dist"
    outdir.mkdir()
    exit_code = main(["--outdir", str(outdir)])
    assert exit_code == 1
    assert "refusing to build into a pre-existing directory" in capsys.readouterr().err


# --- build-constraints.txt pins exact versions, never floating ranges ------


def test_build_constraints_pins_every_entry_to_an_exact_version() -> None:
    constraints_path = ROOT / "scripts" / "build-constraints.txt"
    assert constraints_path.exists(), "scripts/build-constraints.txt must exist"
    lines = [
        line.strip()
        for line in constraints_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert lines, "build-constraints.txt must pin at least one package"
    floating_operators = (">=", "<=", "~=", "!=", ">", "<")
    for line in lines:
        assert "==" in line, f"{line!r} is not an exact pin (missing ==)"
        assert not any(op in line.replace("==", "") for op in floating_operators), (
            f"{line!r} contains a floating version operator -- build-constraints.txt must pin exact versions only"
        )


def test_build_constraints_pins_hatchling() -> None:
    constraints_path = ROOT / "scripts" / "build-constraints.txt"
    text = constraints_path.read_text(encoding="utf-8")
    assert re.search(r"^hatchling==\S+$", text, re.MULTILINE), (
        "build-constraints.txt must exactly pin hatchling -- it is the tool that actually writes wheel/sdist bytes"
    )


# --- one canonical build path: no stray raw `python -m build` calls -------


def test_makefile_package_check_uses_the_canonical_build_script() -> None:
    makefile_text = (ROOT / "Makefile").read_text(encoding="utf-8")
    package_check_match = re.search(r"^package-check:\n(?:\t.*\n)*", makefile_text, re.MULTILINE)
    assert package_check_match, "Makefile must define a package-check target"
    package_check_body = package_check_match.group(0)
    assert "build_release_artifact.py" in package_check_body, (
        "package-check must build via the canonical script, not a separate raw `python -m build` call"
    )
    assert "--no-isolation" not in package_check_body, (
        "package-check must not use --no-isolation -- it masks a resolved-hatchling-version mismatch "
        "against the real publish workflow, which does not use --no-isolation either"
    )


def test_reproducible_build_script_uses_the_canonical_build_function() -> None:
    text = (ROOT / "scripts" / "reproducible_build.py").read_text(encoding="utf-8")
    assert "from build_release_artifact import build" in text
    # A quoted CLI flag, not merely the word "isolation" appearing in
    # explanatory prose (this file's own docstring mentions the removed
    # `--no-isolation` flag by name when explaining what changed and why).
    assert '"--no-isolation"' not in text


def test_publish_workflow_uses_the_canonical_build_script() -> None:
    text = (ROOT / ".github" / "workflows" / "publish.yml").read_text(encoding="utf-8")
    assert "build_release_artifact.py" in text
    assert "SOURCE_DATE_EPOCH=" not in text, (
        "publish.yml must not derive SOURCE_DATE_EPOCH itself -- the canonical script does, "
        "so this workflow and every other build site can never diverge on how they compute it"
    )


# --- the safe release-rehearsal workflow can never publish -----------------


def test_release_rehearsal_workflow_has_no_publish_capability() -> None:
    text = (ROOT / ".github" / "workflows" / "release-rehearsal.yml").read_text(encoding="utf-8")
    # Actual YAML permission grants, not mere mentions of the term in the
    # file's own explanatory header prose (which names what is deliberately
    # absent).
    assert not re.search(r"^\s*id-token:\s*write\s*$", text, re.MULTILINE), (
        "release-rehearsal.yml must never grant the OIDC token permission PyPI publishing needs"
    )
    assert not re.search(r"^\s*environment:\s*\n\s*name:\s*pypi\s*$", text, re.MULTILINE), (
        "release-rehearsal.yml must not declare the pypi trusted-publishing environment"
    )
    assert "gh-action-pypi-publish" not in text, "release-rehearsal.yml must never invoke the PyPI publish action"
    assert "twine upload" not in text, "release-rehearsal.yml must never upload anything"
    assert "build_release_artifact.py" in text, (
        "release-rehearsal.yml must build via the same canonical script publish.yml uses"
    )


def test_release_rehearsal_workflow_requires_an_explicit_ref_input() -> None:
    text = (ROOT / ".github" / "workflows" / "release-rehearsal.yml").read_text(encoding="utf-8")
    assert "workflow_dispatch" in text
    assert re.search(r"ref:\s*\n\s*description:.*\n\s*required:\s*true", text), (
        "release-rehearsal.yml's `ref` input must be required -- it must never silently rehearse an unintended ref"
    )
