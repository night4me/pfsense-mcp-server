#!/usr/bin/env python3
"""Build this project's sdist and wheel the one, canonical way -- the same
way for a local release-readiness audit, `make package-check`, `make
reproducible-build`, the safe non-publishing rehearsal workflow, and the
real `.github/workflows/publish.yml`.

Exists because the v1.1.0 publication ceremony (2026-08-30) found that the
project had three *different* build invocations that could each populate
`dist/`, and only one of them (the manual recipe documented in
`docs/PYPI_RELEASE.md`, and `scripts/reproducible_build.py`'s own internal
pair) set `SOURCE_DATE_EPOCH`. `make package-check` -- whose output is what
`make artifact-manifest`/`make release-check` actually hash and report to
the owner -- built with `--no-isolation` and never set it, so the artifact
an owner was asked to approve could never have been guaranteed to match what
the trusted `publish.yml` workflow (which does set it) would later produce,
even though both satisfied the same declared `hatchling` version range.
Reproduced and confirmed exactly with a controlled experiment: building at
the exact RC commit with `SOURCE_DATE_EPOCH` unset reproduces the audited
RC hash; building with it set to that commit's own timestamp reproduces the
actual published PyPI hash, byte for byte, both directions. See
`reports-ai/POST_V1_1_RELEASE_REPRODUCIBILITY_HARDENING.md`.

Two invariants this script enforces that ad hoc `python -m build` calls
did not:

1. `SOURCE_DATE_EPOCH` is always derived from the built ref's own commit
   timestamp (`git show -s --format=%ct <ref>`), never left to whatever
   moment the build happened to run.
2. `hatchling` and its own transitive build-dependency closure are pinned
   to exact versions via `scripts/build-constraints.txt` (applied through
   the standard `PIP_CONSTRAINT` environment variable, which `python -m
   build`'s PEP 517 isolated installer honors) -- closing the residual risk
   that `pyproject.toml`'s deliberately-flexible `hatchling>=1.25,<1.32`
   range resolves a different patch release depending on *when* a build
   happens to run, even with `SOURCE_DATE_EPOCH` held fixed.

Always builds under full PEP 517 isolation (no `--no-isolation`) -- the
same mode `publish.yml` uses -- so a resolved hatchling version mismatch
between an audit environment and the real build environment would surface
here too, rather than being silently masked by reusing whatever happens to
already be installed locally.
"""

from __future__ import annotations

import argparse
import os
import subprocess  # nosec B404 -- fixed interpreter/build argv, no shell, no caller-controlled tokens
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONSTRAINTS_FILE = ROOT / "scripts" / "build-constraints.txt"


def source_date_epoch(ref: str) -> str:
    """The exact commit timestamp of `ref`, as `python -m build` expects it."""
    return subprocess.check_output(  # nosec B603 B607 -- fixed read-only git argv
        ["git", "show", "-s", "--format=%ct", ref], cwd=ROOT, text=True
    ).strip()


def _current_head() -> str:
    return subprocess.check_output(  # nosec B603 B607 -- fixed read-only git argv
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True
    ).strip()


def _resolved_commit(ref: str) -> str:
    return subprocess.check_output(  # nosec B603 B607 -- fixed read-only git argv
        ["git", "rev-parse", f"{ref}^{{commit}}"], cwd=ROOT, text=True
    ).strip()


def build(output_dir: Path, ref: str = "HEAD") -> None:
    """Build sdist + wheel from `ref` into `output_dir`, deterministically.

    `ref` is never checked out by this function -- it must already be what
    is on disk at `ROOT`. This is a fail-closed check, not a convenience:
    silently building from whatever happens to be checked out while
    deriving `SOURCE_DATE_EPOCH` from a *different* ref (e.g. a caller
    that passes an explicit historical SHA without checking it out first)
    would embed a timestamp that has nothing to do with the actual source
    being packaged -- exactly the kind of silent mismatch this script
    exists to eliminate. Callers that need to build a specific ref they
    have not already checked out (e.g. a safe rehearsal workflow building
    an arbitrary tag) must check it out themselves first (a real `git
    checkout`/`actions/checkout@... ref:` step, not this script).
    """
    if _current_head() != _resolved_commit(ref):
        raise SystemExit(
            f"build_release_artifact: refusing to build -- current HEAD ({_current_head()}) "
            f"does not match --ref {ref!r} ({_resolved_commit(ref)}). Check out {ref!r} first."
        )
    epoch = source_date_epoch(ref)
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = epoch
    environment["PIP_CONSTRAINT"] = str(CONSTRAINTS_FILE)
    subprocess.run(  # nosec B603 -- fixed interpreter/build argv, no shell
        [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(output_dir)],
        cwd=ROOT,
        env=environment,
        check=True,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--outdir", type=Path, default=ROOT / "dist", help="directory to build into (default: dist)")
    parser.add_argument("--ref", default="HEAD", help="git ref to derive SOURCE_DATE_EPOCH from (default: HEAD)")
    parser.add_argument(
        "--allow-existing",
        action="store_true",
        help="do not refuse to build if --outdir already exists (scripts/reproducible_build.py's own "
        "always-fresh temp directories pass this; every other caller should not)",
    )
    args = parser.parse_args(argv)

    if args.outdir.exists() and not args.allow_existing:
        print(
            f"build_release_artifact: refusing to build into a pre-existing directory: {args.outdir}", file=sys.stderr
        )
        return 1

    args.outdir.mkdir(parents=True, exist_ok=True)
    build(args.outdir, args.ref)
    epoch = source_date_epoch(args.ref)
    print(f"build_release_artifact: OK (ref={args.ref}, SOURCE_DATE_EPOCH={epoch}, outdir={args.outdir})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
