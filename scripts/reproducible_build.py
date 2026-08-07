#!/usr/bin/env python3
"""Build twice from HEAD and require byte-identical Python distributions."""

from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_date_epoch() -> str:
    return subprocess.check_output(["git", "show", "-s", "--format=%ct", "HEAD"], cwd=ROOT, text=True).strip()


def _build(output: Path, epoch: str) -> None:
    environment = dict(os.environ)
    environment["SOURCE_DATE_EPOCH"] = epoch
    subprocess.run(
        [sys.executable, "-m", "build", "--no-isolation", "--sdist", "--wheel", "--outdir", str(output)],
        cwd=ROOT,
        env=environment,
        check=True,
        stdout=subprocess.DEVNULL,
    )


def main() -> int:
    epoch = _source_date_epoch()
    with tempfile.TemporaryDirectory(prefix="pfsense-build-a-") as first_dir:
        with tempfile.TemporaryDirectory(prefix="pfsense-build-b-") as second_dir:
            first = Path(first_dir)
            second = Path(second_dir)
            _build(first, epoch)
            _build(second, epoch)
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
