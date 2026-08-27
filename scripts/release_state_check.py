#!/usr/bin/env python3
"""Fail closed when tracked release-state facts are inconsistent or dirty.

Phase-aware: the currently-declared `pyproject.toml` version is either a
**candidate** (prepared on `main`, not yet tagged/released/published) or
**published** (a real `vX.Y.Z` tag exists and is reachable from `HEAD`).
Each phase has its own, differently-shaped set of required invariants --
this is intentionally *not* a single relaxed rule set that both states
must satisfy, because the published-state invariants (dated CHANGELOG
heading, README baseline claim, ACCEPTANCE doc declaring "published")
would otherwise have to be weakened to also tolerate an honest
pre-publish candidate, which is exactly the kind of silent weakening
this module must never do.

The phase itself is never inferred from any document's own self-reported
status text (an ACCEPTANCE doc that still said "release-candidate" after
the real tag/publish would be a documentation bug, not evidence that
publication didn't happen). It is derived from one objective, offline,
non-spoofable git fact: does an annotated or lightweight tag
`v{version}` exist and is it reachable from (an ancestor of, or equal
to) `HEAD`? This is the same fact `.github/workflows/publish.yml`'s own
"Verify tag matches package version" step relies on, so a repository
that has genuinely been tagged and published is always correctly
classified `published`, however stale its own prose might be -- and
prose alone can never downgrade a real publication to `candidate`.
"""

from __future__ import annotations

# Fixed local git query; no shell or caller-controlled argv.
import subprocess  # nosec B404
import tomllib
from pathlib import Path
from typing import Literal

ROOT = Path(__file__).resolve().parents[1]

ReleasePhase = Literal["candidate", "published"]


def _git_ok(root: Path, *args: str) -> bool:
    # Fixed read-only git argv; args are always literal strings below.
    result = subprocess.run(  # nosec B603 B607
        ["git", *args], cwd=root, capture_output=True, text=True
    )
    return result.returncode == 0


def determine_release_phase(root: Path, version: str) -> ReleasePhase:
    """`published` iff `v{version}` exists as a git tag and is reachable
    from (or equal to) `HEAD`; `candidate` otherwise. Deliberately the
    *only* signal used -- never any document's own status text -- so a
    stale or wrong ACCEPTANCE-doc/README claim can never silently
    downgrade an actually-published release to the weaker candidate
    rules, and a repository that merely *talks about* being published
    without the tag to back it up is never upgraded either."""

    tag = f"v{version}"
    if not _git_ok(root, "rev-parse", "--verify", "--quiet", f"{tag}^{{commit}}"):
        return "candidate"
    if not _git_ok(root, "merge-base", "--is-ancestor", tag, "HEAD"):
        return "candidate"
    return "published"


def _mit_license_check(root: Path, metadata: dict[str, object]) -> bool:
    return metadata.get("license") == "MIT" and (root / "LICENSE").is_file()


def candidate_release_checks(root: Path, version: str) -> dict[str, bool]:
    """Pre-publish invariants for an honest, not-yet-tagged release
    candidate. Requires the *absence* of every claim that would only
    become true at actual publication -- this is the check set that
    made `v0.8.0`'s own real release-candidate commit fail under the
    old, single-phase version of this module (see CHANGELOG/git history
    around 2026-08-27): forcing those absent claims to appear here would
    have meant fabricating a false "already published" statement."""

    acceptance_path = root / f"docs/ACCEPTANCE_v{version}.md"
    acceptance_text = acceptance_path.read_text(encoding="utf-8") if acceptance_path.is_file() else ""
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    readme = (root / "README.md").read_text(encoding="utf-8")
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return {
        f"docs/ACCEPTANCE_v{version}.md exists": acceptance_path.is_file(),
        "ACCEPTANCE doc honestly declares release-candidate status": (
            "Status: release-candidate" in acceptance_text and "Status: published" not in acceptance_text
        ),
        f"CHANGELOG has no dated '## [{version}] -' heading yet": f"## [{version}] - " not in changelog,
        f"README does not yet claim v{version} as the published baseline": (
            f"v{version} is the immutable production baseline" not in readme
        ),
        "MIT license metadata": _mit_license_check(root, metadata),
    }


def published_release_checks(root: Path, version: str) -> dict[str, bool]:
    """Post-publish invariants -- unchanged in strength from this
    module's original, single-phase check set. Applies only once
    `determine_release_phase` has independently confirmed a real
    `v{version}` tag is reachable from `HEAD`."""

    acceptance_path = root / f"docs/ACCEPTANCE_v{version}.md"
    acceptance_text = acceptance_path.read_text(encoding="utf-8") if acceptance_path.is_file() else ""
    readme = (root / "README.md").read_text(encoding="utf-8")
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    return {
        f"docs/ACCEPTANCE_v{version}.md exists": acceptance_path.is_file(),
        "ACCEPTANCE doc declares published status": (
            "Status: published" in acceptance_text and "Status: release-candidate" not in acceptance_text
        ),
        "released changelog heading": f"## [{version}] - " in (root / "CHANGELOG.md").read_text(encoding="utf-8"),
        "README immutable production baseline": f"v{version} is the immutable production baseline" in readme,
        "README PyPI publication status": "published on PyPI" in readme,
        "MIT license metadata": _mit_license_check(root, metadata),
    }


def release_checks(root: Path) -> dict[str, bool | str]:
    """Phase-dispatching entry point. Returns the phase-appropriate
    check set plus an explicit `"phase"` key -- the phase is never
    itself counted as a pass/fail check, but every caller (and every
    test) can see, and assert on, which rule set was actually applied."""

    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = metadata["version"]
    phase = determine_release_phase(root, version)
    checks: dict[str, bool | str] = {"phase": phase}
    if phase == "published":
        checks.update(published_release_checks(root, version))
    else:
        checks.update(candidate_release_checks(root, version))
    return checks


def main() -> int:
    # Fixed read-only git argv.
    status = subprocess.check_output(  # nosec B603 B607
        ["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True
    )
    if status:
        print("release_state_check: tracked or untracked working-tree changes are present")
        return 1

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = metadata["version"]
    checks = release_checks(ROOT)
    phase = checks["phase"]
    failures = [name for name, passed in checks.items() if name != "phase" and not passed]
    if failures:
        print(f"release_state_check: inconsistent release state (phase={phase}): {', '.join(failures)}")
        return 1
    print(f"release_state_check: OK (v{version}, phase={phase}, clean tree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
