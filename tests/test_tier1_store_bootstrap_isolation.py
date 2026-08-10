"""Structural proof that `scripts/tier1_store_bootstrap.py` -- the one
operator entrypoint for the Tier 1 production store, per the anti-
rollback anchor's production bootstrap mission -- cannot reach pfSense.

Mirrors `tests/tier1/test_isolation.py`'s own AST-based approach rather
than trusting the script's docstring claims. Also confirms none of the
production application files (`application.py`/`factory.py`/`server.py`)
import this script's own module or `pfsense_mcp.tier1.production_store` --
this mission deliberately did not wire either into the running MCP
server; only a standalone script invocation can construct the production
store.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
SCRIPT = ROOT / "scripts" / "tier1_store_bootstrap.py"

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
}
_FORBIDDEN_CALLS = {"delete", "patch", "post", "put", "request", "tool"}


def _tree(path: Path) -> ast.AST:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_tier1_store_bootstrap_script_cannot_reach_pfsense():
    tree = _tree(SCRIPT)

    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any(
        module == root or module.startswith(f"{root}.") for module in imported for root in _FORBIDDEN_IMPORT_ROOTS
    ), "tier1_store_bootstrap.py imports a module capable of reaching pfSense"

    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    assert called_attributes.isdisjoint(_FORBIDDEN_CALLS), "tier1_store_bootstrap.py calls a forbidden attribute name"


def test_production_application_files_do_not_import_the_store_bootstrap():
    production = ROOT / "src/pfsense_mcp"
    forbidden_modules = {"pfsense_mcp.tier1", "pfsense_mcp.tier1.production_store"}
    for path in production.rglob("*.py"):
        if "tier1" in path.relative_to(production).parts:
            continue
        tree = _tree(path)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
            node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
        }
        assert not any(
            module == root or module.startswith(f"{root}.") for module in imported for root in forbidden_modules
        ), f"{path.relative_to(production)} imports the Tier 1 store bootstrap -- production remains unwired"
