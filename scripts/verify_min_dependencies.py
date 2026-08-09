#!/usr/bin/env python3
"""Install this project at its declared minimum dependency versions
(`uv pip install --resolution=lowest-direct`) into a throwaway venv and
run the full offline test suite against it.

This exists because a declared `>=X` lower bound is a claim, not a fact,
until something actually resolves and runs at exactly that floor. This
project's own `mcp>=1.0.0` floor was found and fixed (2026-08-09) after
being long false: every `mcp` release from 1.0.0 through 1.21.0 either
fails to import (`mcp.server.fastmcp`/`mcp.types.ToolAnnotations` did not
exist yet) or crashes on tool registration
(`TypeError: issubclass() arg 1 must be a class` inside `mcp`'s own
`fastmcp/tools/base.py`) -- `1.21.1` is the first version confirmed to
actually work end to end, discovered by exactly the bisection this script
now automates. Deliberately outside `quick`/`validate` (network-dependent,
slower than either) -- wired into `release-check` only, matching
`reproducible-build`'s own scoping.
"""

from __future__ import annotations

import shutil

# Fixed local uv/python commands; no shell or caller-controlled argv.
import subprocess  # nosec B404
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _require_uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        print("verify_min_dependencies: requires uv (https://docs.astral.sh/uv/)", file=sys.stderr)
        raise SystemExit(1)
    return uv


def main() -> int:
    uv = _require_uv()
    with tempfile.TemporaryDirectory(prefix="pfsense-min-deps-") as tmp_dir:
        venv = Path(tmp_dir) / "venv"
        # Fixed uv/local-path argv only -- no caller-controlled input.
        subprocess.run([uv, "venv", "--quiet", "--python", "3.11", str(venv)], cwd=ROOT, check=True)  # nosec B603
        python = venv / "bin" / "python"
        install = subprocess.run(  # nosec B603
            [
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--resolution=lowest-direct",
                "-e",
                ".[dev]",
            ],
            cwd=ROOT,
        )
        if install.returncode != 0:
            print("verify_min_dependencies: install at lowest-direct resolution failed", file=sys.stderr)
            return 1

        test = subprocess.run([str(python), "-m", "pytest", "-q"], cwd=ROOT)  # nosec B603
        if test.returncode != 0:
            print("verify_min_dependencies: test suite failed at minimum dependency versions", file=sys.stderr)
            return 1

    print("verify_min_dependencies: OK (install + full test suite pass at lowest-direct resolution)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
