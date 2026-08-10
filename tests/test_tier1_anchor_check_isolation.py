"""Stronger, dedicated structural tests for
`pfsense_mcp.tier1_anchor_check` -- the one narrow exception to
production never importing `pfsense_mcp.tier1`
(`tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`). These prove, by
direct AST inspection of the actual shipped source (not by trusting the
module's own docstring), that the exception is exactly as narrow as
claimed: read-only, opt-in, cannot reach PREPARE/EXECUTE/WRITE, and does
not change the public MCP contract.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/tier1_anchor_check.py"

# Every tier1 method name that mutates state (a store write, a TPM
# advance, provisioning, confirmation, rollback, execution, key
# rotation) -- this module may only ever call read-shaped methods
# (load_production_store_config, open_production_store,
# anchor_provisioning_status, read).
_FORBIDDEN_MUTATING_CALLS = {
    "advance",
    "advance_calls",
    "provision_anchor_baseline",
    "provision_production_anchor_baseline",
    "seed",
    "mark_complete",
    "_persist",
    "transition",
    "create",
    "confirm",
    "rollback",
    "execute",
    "rotate_key",
    "increment_counter",
}

# Symbols whose mere presence would indicate this module is reaching
# toward PREPARE/EXECUTE/WRITE, not just reading anchor state.
_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "WriteEndpoints",
    "CapabilityAdapter",
}

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.contract",
}


def _tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))


def test_module_exists_and_is_the_only_isolation_exemption():
    assert MODULE_PATH.is_file()


def test_never_calls_a_mutating_tier1_method():
    tree = _tree()
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"tier1_anchor_check.py calls mutating method(s): {offending}"


def test_never_references_prepare_execute_or_write_symbols():
    tree = _tree()
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"tier1_anchor_check.py references forbidden symbol(s): {offending}"


def test_never_imports_write_or_execution_capable_modules():
    tree = _tree()
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"tier1_anchor_check.py imports forbidden module(s): {offending}"


def test_run_anchor_startup_check_is_the_only_public_entrypoint():
    """No other function in this module is exported without a leading
    underscore -- the smaller the public surface, the easier this stays
    auditable as "one call site, one behavior" from application.py."""

    tree = _tree()
    top_level_public_functions = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.FunctionDef) and not node.name.startswith("_")
    }
    assert top_level_public_functions == {"run_anchor_startup_check"}


def test_application_py_does_not_import_pfsense_mcp_tier1_directly():
    """application.py itself must only ever import
    tier1_anchor_check.run_anchor_startup_check(), never
    pfsense_mcp.tier1 directly -- keeping the isolation exemption's
    surface to exactly one file, not application.py too."""

    app_path = ROOT / "src/pfsense_mcp/application.py"
    tree = ast.parse(app_path.read_text(encoding="utf-8"), filename=str(app_path))
    imported = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(module == "pfsense_mcp.tier1" or module.startswith("pfsense_mcp.tier1.") for module in imported)
    assert "tier1_anchor_check" in {
        (node.module or "").rsplit(".", 1)[-1] for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
