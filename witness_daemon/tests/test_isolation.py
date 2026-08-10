"""Structural proof, by direct AST inspection (not by trusting module
docstrings), that `witness_daemon` and `pfsense_mcp` have zero
relationship in either direction:

  - no file under `src/pfsense_mcp/` imports `witness_daemon` (the
    Proxmox-host daemon must never become reachable from the guest
    package, in either the shipped MCP server or any inert Tier 1
    module);
  - no file under `witness_daemon/` imports `pfsense_mcp` at all (the
    daemon has no relationship to pfSense, the MCP protocol, or any
    guest-side code -- it only ever talks to the physical TPM and the
    network).

Mirrors `tests/tier1/test_isolation.py`'s own AST-based approach.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imported_modules(tree: ast.AST) -> set[str]:
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }


def test_no_production_file_imports_witness_daemon():
    production = ROOT / "src/pfsense_mcp"
    for path in production.rglob("*.py"):
        imported = _imported_modules(_tree(path))
        assert not any(module == "witness_daemon" or module.startswith("witness_daemon.") for module in imported), (
            f"{path.relative_to(production)} imports witness_daemon -- the guest must never reach the host daemon"
        )


def test_witness_daemon_never_imports_pfsense_mcp():
    package_root = ROOT / "witness_daemon"
    for path in package_root.rglob("*.py"):
        if "tests" in path.relative_to(package_root).parts:
            continue
        imported = _imported_modules(_tree(path))
        assert not any(module == "pfsense_mcp" or module.startswith("pfsense_mcp.") for module in imported), (
            f"{path.relative_to(package_root)} imports pfsense_mcp -- the daemon must have zero relationship to it"
        )


def test_witness_daemon_scripts_do_not_import_pfsense_mcp():
    for path in ROOT.glob("scripts/*.py"):
        imported = _imported_modules(_tree(path))
        assert not any(module == "witness_daemon" or module.startswith("witness_daemon.") for module in imported), (
            f"{path.name} imports witness_daemon -- deployment scripts for the guest package must not reference "
            "the separate host daemon"
        )
