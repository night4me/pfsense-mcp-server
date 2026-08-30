#!/usr/bin/env python3
"""Build twice from HEAD via `scripts/build_release_artifact.py` -- the same
canonical, full-isolation, SOURCE_DATE_EPOCH-and-constraint-pinned build
path `make package-check`, the safe release-rehearsal workflow, and the
real `.github/workflows/publish.yml` all use -- and require the two builds
to be byte-identical.

Previously used a separate, ad hoc `--no-isolation` build here that never
shared a code path with any of the other three build sites; that let this
check pass (proving only that *this script's own pair* of builds, using
whatever build tooling happened to already be installed in the invoking
environment, was internally consistent) while the actual artifact `make
package-check` built -- and that `make artifact-manifest`/`make
release-check` hashed and reported to the owner -- was built a third,
different way and could diverge from what the real publish workflow later
produced. See `reports-ai/POST_V1_1_RELEASE_REPRODUCIBILITY_HARDENING.md`
for the concrete v1.1.0 incident this closes.

A passing result here means: this project's one canonical build path is
internally deterministic (same source, same declared build-dependency
pins, byte-identical output) -- not a substitute for the safe release-
rehearsal workflow's evidence that a real GitHub Actions run of the exact
same path produces the same bytes too.
"""

from __future__ import annotations

import hashlib
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build_release_artifact import build, source_date_epoch


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    epoch = source_date_epoch("HEAD")
    with (
        tempfile.TemporaryDirectory(prefix="pfsense-build-a-") as first_dir,
        tempfile.TemporaryDirectory(prefix="pfsense-build-b-") as second_dir,
    ):
        first = Path(first_dir)
        second = Path(second_dir)
        build(first, "HEAD")
        build(second, "HEAD")
        first_names = {path.name for path in first.iterdir()}
        second_names = {path.name for path in second.iterdir()}
        if first_names != second_names:
            print("reproducible_build: artifact filename sets differ")
            return 1
        mismatches = [name for name in sorted(first_names) if _sha256(first / name) != _sha256(second / name)]
        if mismatches:
            print(f"reproducible_build: byte mismatch: {', '.join(mismatches)}")
            return 1
    print(f"reproducible_build: OK ({len(first_names)} artifacts, SOURCE_DATE_EPOCH={epoch})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
