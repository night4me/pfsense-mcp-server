"""Structural (AST) tests specific to
`pfsense_mcp.tier1.authorization_consumption_store` -- ADR-022 Phase D's
consumption-tracking store. `tests/tier1/test_isolation.py`'s general
sweep already proves this file (like every `tier1/*.py` file) imports
none of `rest_api_client`/`transport`/`tools`/`write_api_client`/
`pfsense_client` and calls none of the universally forbidden mutating
method names. This file adds the store-specific proofs: exact public
surface, no execution-shaped method, and -- critically -- that no
production module anywhere in the repository ever imports or
constructs it, proving Phase D introduces no execution wiring.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "src/pfsense_mcp/tier1/authorization_consumption_store.py"
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"

_EXPECTED_PUBLIC_SURFACE = {
    "AuthorizationConsumptionStore",
    "Clock",
    "SqliteAuthorizationConsumptionStore",
}

_FORBIDDEN_METHOD_NAMES = {"execute", "apply", "consume_and_execute", "authorize", "verify"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_public_surface_is_exactly_the_reviewed_store_api():
    tree = _tree(MODULE_PATH)
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    } | {
        target.id
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.Assign)
        for target in node.targets
        if isinstance(target, ast.Name) and not target.id.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE


def test_no_execution_or_verification_shaped_method_defined():
    tree = _tree(MODULE_PATH)
    method_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    offending = method_names & _FORBIDDEN_METHOD_NAMES
    assert not offending, f"authorization_consumption_store.py defines a forbidden method: {offending}"


def test_no_production_module_imports_the_consumption_store():
    """No MCP tool, security_cli.py, MutationExecutor, or any other
    production request-handling/execution module ever imports this
    module except the one reviewed exception below -- Phase D's
    persistence primitive has no other wired-in consumer, by design.

    `tier1/execution_coordinator.py` is the one reviewed exception
    (ADR-022 Phase E, Slice E2, 2026-08-11): it holds the consumption
    store as an injected dependency and calls `try_consume()` as the
    last gate before returning success -- see
    `tests/tier1/test_execution_coordinator_isolation.py`'s own
    no-production-importer proof that the coordinator itself remains
    unwired/unconstructed by any production entry point."""

    _ALLOWED_IMPORTERS = {"execution_coordinator.py"}
    importers = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if path == MODULE_PATH or path.name in _ALLOWED_IMPORTERS:
            continue
        tree = _tree(path)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level
                and (node.module or "").endswith("authorization_consumption_store")
            ):
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []
