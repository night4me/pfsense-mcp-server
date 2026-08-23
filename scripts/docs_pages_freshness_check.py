#!/usr/bin/env python3
"""Fail closed when the live `gh-pages` deployment is stale relative to
`docs/`/`mkdocs.yml` on the checked-out branch.

GitHub Pages here is deployed manually via `mkdocs gh-deploy` (see
`mkdocs.yml`'s own comment) -- nothing redeploys it automatically after
a docs change lands on `main`. That gap let the live site drift for
months (found and corrected 2026-08-23: the live site was still serving
the v0.4.2-era, 42-tool description while `main` was at v0.7.1). This
script is a read-only detector for exactly that drift, not a deployer:
it never runs `mkdocs gh-deploy` and never pushes anything.

Convention this relies on: every `mkdocs gh-deploy` invocation for this
repository is made with `-m "Deploy docs from main (<short-sha>)
[<full-sha>]"`, embedding the exact `main` commit the live site was
built from. This script reads that SHA back out of `gh-pages`'s latest
commit message and diffs `docs/`/`mkdocs.yml` between it and the
ref being checked -- if anything changed, the live site no longer
reflects current documentation and this fails.

Requires network access (a `git fetch` of the `gh-pages` ref) -- unlike
`release_state_check.py`, this is not part of the offline `release-check`
gate. Run via `make docs-freshness-check`, or see
`.github/workflows/docs-freshness.yml` for the scheduled/CI equivalent.
"""

from __future__ import annotations

# Fixed local git query; no shell or caller-controlled argv.
import re
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_DEPLOYED_SHA_RE = re.compile(r"\[([0-9a-f]{40})\]\s*$")
_WATCHED_PATHS = ("docs", "mkdocs.yml")


def _git(*args: str) -> str:
    # Fixed read-only git argv; args are always literal strings below.
    return subprocess.check_output(["git", *args], cwd=ROOT, text=True).strip()  # nosec B603 B607


def deployed_sha() -> str | None:
    """The `main` SHA the live `gh-pages` branch was last built from, or
    `None` if the branch is missing or its latest message doesn't match
    the established `mkdocs gh-deploy -m` convention."""

    try:
        _git("fetch", "--quiet", "origin", "gh-pages")
    except subprocess.CalledProcessError:
        return None
    try:
        message = _git("log", "origin/gh-pages", "-1", "--format=%s")
    except subprocess.CalledProcessError:
        return None
    match = _DEPLOYED_SHA_RE.search(message)
    return match.group(1) if match else None


def stale_paths(deployed: str, current_ref: str = "HEAD") -> list[str]:
    """Paths under the watched set that changed between `deployed` and
    `current_ref`. Empty means the live site is current."""

    changed = _git("diff", "--name-only", f"{deployed}..{current_ref}", "--", *_WATCHED_PATHS)
    return [line for line in changed.splitlines() if line]


def main() -> int:
    deployed = deployed_sha()
    if deployed is None:
        print(
            "docs_pages_freshness_check: could not determine the deployed gh-pages SHA "
            "(missing branch, or its latest commit message doesn't match the established "
            "'mkdocs gh-deploy -m \"Deploy docs from main (...) [sha]\"' convention)"
        )
        return 1

    changed = stale_paths(deployed)
    if changed:
        print(
            f"docs_pages_freshness_check: STALE -- gh-pages was last built from {deployed}, "
            f"but {len(changed)} watched path(s) changed since then:"
        )
        for path in changed:
            print(f"  - {path}")
        print("Redeploy with: mkdocs gh-deploy --strict -m '<see this module's docstring for the message format>'")
        return 1

    print(f"docs_pages_freshness_check: OK (gh-pages current as of {deployed})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
