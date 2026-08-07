#!/usr/bin/env python3
"""Emit a machine-independent manifest for locally built release artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json

# Fixed local git query; no shell or caller-controlled argv.
import subprocess  # nosec B404
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def _git_value(format_string: str) -> str:
    # Fixed read-only git argv.
    return subprocess.check_output(  # nosec B603 B607
        ["git", "show", "-s", f"--format={format_string}", "HEAD"], cwd=ROOT, text=True
    ).strip()


def build_manifest(directory: Path) -> dict[str, Any]:
    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = metadata["version"]
    artifacts = sorted(
        path
        for pattern in (f"pfsense_mcp_server-{version}-*.whl", f"pfsense_mcp_server-{version}.tar.gz")
        for path in directory.glob(pattern)
    )
    if len(artifacts) != 2:
        raise ValueError(f"expected one wheel and one sdist for version {version}")
    epoch = int(_git_value("%ct"))
    return {
        "format": 1,
        "package": metadata["name"],
        "version": version,
        "requires_python": metadata["requires-python"],
        "source_commit": _git_value("%H"),
        "source_date_epoch": epoch,
        "build_time_utc": datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(),
        "artifacts": [
            {
                "filename": path.name,
                "bytes": path.stat().st_size,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for path in artifacts
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", default=ROOT / "dist")
    args = parser.parse_args()
    try:
        manifest = build_manifest(args.directory)
    except (OSError, ValueError) as exc:
        parser.exit(1, f"artifact_manifest: ERROR {exc}\n")
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
