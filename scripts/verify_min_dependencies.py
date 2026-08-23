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

**Performance note (2026-08-23):** the test phase below reuses the exact
`pytest-xdist -n 6 --dist=loadscope` + small-serial-tail split the
Makefile's own `XDIST_ARGS`/`XDIST_SERIAL_ONLY` already use for the
normal-environment suite (`make quick`/`make validate`) -- see
`reports-ai/MIN_DEPS_PERFORMANCE_2026-08-23.md` for full before/after
timing evidence. `pytest-xdist` is not a new dependency: it is already
declared in `pyproject.toml`'s `[dev]` extra (`pytest-xdist>=3.8,<4.0`)
and this script already installs `.[dev]` -- only the invocation
changed, never what gets installed or what floor version is being
verified. The two test IDs below are duplicated from the Makefile's own
`XDIST_SERIAL_ONLY`, not imported from it -- this floor-environment
verification and the normal-environment `quick`/`validate` path are two
different guarantees (different Python version, different dependency
versions, a genuinely fresh environment every run) and are deliberately
kept as separate, independently-readable pytest invocations rather than
merged into shared tooling; if a new xdist-incompatible test is ever
added to the Makefile's own list, add it here too.
"""

from __future__ import annotations

import shutil

# Fixed local uv/python commands; no shell or caller-controlled argv.
import subprocess  # nosec B404
import sys
import tempfile
import time
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Mirrors Makefile's own XDIST_SERIAL_ONLY exactly -- see that file's
# own comment for why each test is here. Duplicated, not imported: see
# this module's own docstring for why the two verification paths are
# kept structurally separate rather than merged.
_XDIST_SERIAL_ONLY = (
    "tests/tier1/test_crypto.py::test_random_ciphertext_never_raises_anything_but_artifact_decryption_error",
    "tests/tier1/test_acceptance_isolation.py::test_importing_mcp_entrypoints_never_loads_acceptance_module",
)


def _require_uv() -> str:
    uv = shutil.which("uv")
    if uv is None:
        print("verify_min_dependencies: requires uv (https://docs.astral.sh/uv/)", file=sys.stderr)
        raise SystemExit(1)
    return uv


def _timed(label: str, fn: Callable[[], int]) -> int:
    """Runs `fn`, prints a durable `label: N.Ns` timing line to stdout
    regardless of outcome, and returns `fn`'s own return code. Every
    phase in `main()` is wrapped in this so a slow run's CI log always
    shows exactly which phase dominated, without needing a second,
    ad hoc instrumented rerun to find out."""

    start = time.monotonic()
    try:
        return fn()
    finally:
        elapsed = time.monotonic() - start
        print(f"verify_min_dependencies: [timing] {label}: {elapsed:.1f}s")


def main() -> int:
    uv = _require_uv()
    overall_start = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="pfsense-min-deps-") as tmp_dir:
        venv = Path(tmp_dir) / "venv"
        python = venv / "bin" / "python"

        def _create_venv() -> int:
            # Fixed uv/local-path argv only -- no caller-controlled input.
            return subprocess.run(  # nosec B603
                [uv, "venv", "--quiet", "--python", "3.11", str(venv)], cwd=ROOT
            ).returncode

        if _timed("venv creation (incl. Python 3.11 acquisition)", _create_venv) != 0:
            print("verify_min_dependencies: venv creation failed", file=sys.stderr)
            return 1

        def _install() -> int:
            return subprocess.run(  # nosec B603
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
            ).returncode

        if _timed("dependency resolution + install (incl. editable package install)", _install) != 0:
            print("verify_min_dependencies: install at lowest-direct resolution failed", file=sys.stderr)
            return 1

        deselect_args = [arg for test_id in _XDIST_SERIAL_ONLY for arg in ("--deselect", test_id)]

        def _test_parallel() -> int:
            return subprocess.run(  # nosec B603
                [str(python), "-m", "pytest", "-q", "-n", "6", "--dist=loadscope", *deselect_args], cwd=ROOT
            ).returncode

        parallel_rc = _timed("pytest execution (parallel, 6 workers)", _test_parallel)

        def _test_serial() -> int:
            return subprocess.run([str(python), "-m", "pytest", "-q", *_XDIST_SERIAL_ONLY], cwd=ROOT).returncode  # nosec B603

        serial_rc = _timed(f"pytest execution (serial tail, {len(_XDIST_SERIAL_ONLY)} deselected tests)", _test_serial)

        if parallel_rc != 0 or serial_rc != 0:
            print("verify_min_dependencies: test suite failed at minimum dependency versions", file=sys.stderr)
            return 1

    total = time.monotonic() - overall_start
    print(f"verify_min_dependencies: [timing] total: {total:.1f}s")
    print("verify_min_dependencies: OK (install + full test suite pass at lowest-direct resolution)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
