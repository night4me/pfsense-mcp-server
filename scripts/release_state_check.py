#!/usr/bin/env python3
"""Fail closed when tracked release-state facts are inconsistent or dirty."""

from __future__ import annotations

# Fixed local git query; no shell or caller-controlled argv.
import subprocess  # nosec B404
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def release_checks(root: Path) -> dict[str, bool]:
    metadata = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    version = metadata["version"]
    readme = (root / "README.md").read_text(encoding="utf-8")
    return {
        f"docs/ACCEPTANCE_v{version}.md": (root / f"docs/ACCEPTANCE_v{version}.md").is_file(),
        "released changelog heading": f"## [{version}] - " in (root / "CHANGELOG.md").read_text(encoding="utf-8"),
        "README immutable production baseline": f"v{version} is the immutable production baseline" in readme,
        "README PyPI publication status": "published on PyPI" in readme,
        "MIT license metadata": metadata.get("license") == "MIT" and (root / "LICENSE").is_file(),
    }


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
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        print(f"release_state_check: inconsistent release state: {', '.join(failures)}")
        return 1
    print(f"release_state_check: OK (v{version}, clean tree)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
