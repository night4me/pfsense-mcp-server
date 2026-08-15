"""Proves `signing/` (W3 Slice 5's off-host, operator-only signing tool)
is never imported by, and never runs inside, `src/pfsense_mcp` --
ADR-028's own "Signing-side CLI trust boundary" and
`docs/tier1/specs/confirmation_authority.md`'s G3 requirement, checked
by direct AST inspection rather than trusted by convention alone.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"


def _imports_signing(path: Path) -> bool:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "signing":
            return True
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] == "signing" for alias in node.names):
            return True
    return False


def test_no_production_module_imports_the_signing_package():
    offenders = [path.relative_to(ROOT).as_posix() for path in PRODUCTION_ROOT.rglob("*.py") if _imports_signing(path)]
    assert offenders == []


def test_signing_package_never_appears_in_pfsense_mcp_dependency_declarations():
    """`signing/` must never become an installable/importable dependency
    of the shipped package -- it is not listed in pyproject.toml's wheel
    packaging, and no production source file references its distribution
    name."""

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert '"signing"' not in pyproject
    assert 'packages = ["src/pfsense_mcp"]' in pyproject


def test_signing_package_is_excluded_from_default_pytest_collection():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "--ignore=signing" in pyproject
