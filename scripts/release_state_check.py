#!/usr/bin/env python3
"""Fail closed when tracked release-state facts are inconsistent or dirty."""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    status = subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=normal"], cwd=ROOT, text=True)
    if status:
        print("release_state_check: tracked or untracked working-tree changes are present")
        return 1

    metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = metadata["version"]
    checks = {
        f"docs/ACCEPTANCE_v{version}.md": (ROOT / f"docs/ACCEPTANCE_v{version}.md").is_file(),
        "released changelog heading": f"## [{version}] - " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8"),
        "README current release state": f"v{version} is the current release state"
        in (ROOT / "README.md").read_text(encoding="utf-8"),
        "README publication disclaimer": "not yet published on PyPI"
        in (ROOT / "README.md").read_text(encoding="utf-8"),
        "MIT license metadata": metadata.get("license") == "MIT" and (ROOT / "LICENSE").is_file(),
    }
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        print(f"release_state_check: inconsistent release state: {', '.join(failures)}")
        return 1
    print(f"release_state_check: OK (v{version}, clean tree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
