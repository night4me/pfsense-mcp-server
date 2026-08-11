"""Structural (AST) tests for `pfsense_mcp.security_plan_freshness` --
ADR-022 Phase E, Slice E1. Proves, by direct inspection of the actual
shipped source, that this module:

  - imports zero `pfsense_mcp.tier1` submodules at all (mirrors
    `security_plan.py`'s own existing invariant -- no new tier1
    isolation exemption is introduced);
  - never references MutationExecutor/RecoveryContract/state-machine/
    consumption-store/WriteApiClient/WriteEndpoints/coordinator-family
    symbols;
  - never calls a mutating/IO-shaped method name beyond what
    generate_security_posture_plan()/verify_plan_digest() themselves
    already legitimately perform;
  - never defines an execute/apply/consume-shaped method;
  - has exactly the reviewed public surface;
  - is never imported by any production module -- only by its own
    tests -- proving this slice introduces no wiring.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_plan_freshness.py"
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"

_FORBIDDEN_REFERENCED_NAMES = {
    "MutationExecutor",
    "RecoveryContract",
    "RecoveryState",
    "SqliteRecoveryContractStore",
    "AuthorizationConsumptionStore",
    "SqliteAuthorizationConsumptionStore",
    "PlanAuthorization",
    "DeprovisionAuthorization",
    "WriteApiClient",
    "WriteEndpoints",
    "ExecutionCoordinator",
    "ConfirmationEvidence",
    "PinnedAuthoritySet",
}

_FORBIDDEN_MUTATING_CALLS = {
    "advance",
    "advance_calls",
    "provision_anchor_baseline",
    "provision_production_anchor_baseline",
    "seed",
    "mark_complete",
    "transition",
    "create",
    "confirm",
    "rollback",
    "execute",
    "apply",
    "try_consume",
    "connect",
    "commit",
}

_EXPECTED_PUBLIC_SURFACE = {
    "PlanFreshnessError",
    "plan_authorization_is_fresh",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_imports_zero_pfsense_mcp_tier1_submodules():
    tree = _tree(MODULE_PATH)
    tier1_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module == "pfsense_mcp.tier1" or module.startswith("pfsense_mcp.tier1."):
                tier1_imports.add(module)
            elif node.level and module == "tier1":
                tier1_imports.add("tier1")
            elif node.level and module.startswith("tier1."):
                tier1_imports.add(module)
    assert not tier1_imports, f"security_plan_freshness.py must not import pfsense_mcp.tier1: {tier1_imports}"


def test_never_calls_a_mutating_or_io_shaped_method():
    tree = _tree(MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_plan_freshness.py calls mutating/IO method(s): {offending}"


def test_never_calls_sqlite3_connect_or_open_directly():
    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_execution_or_consumption_family_symbols():
    tree = _tree(MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_plan_freshness.py references forbidden symbol(s): {offending}"


def test_never_defines_an_execute_or_apply_or_consume_shaped_method():
    tree = _tree(MODULE_PATH)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    forbidden = {"execute", "apply", "consume", "consume_and_execute", "is_authorized_for_runtime", "authorize_runtime"}
    offending = function_names & forbidden
    assert not offending, (
        f"security_plan_freshness.py defines a forbidden bearer-capability-shaped function: {offending}"
    )


def test_public_surface_is_exactly_the_reviewed_freshness_api():
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


def test_only_imports_security_discovery_and_security_plan_family_within_the_package():
    tree = _tree(MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_discovery", "security_plan", "security_plan_digest"}


def test_no_production_module_imports_security_plan_freshness():
    """No MCP tool, security_cli.py, MutationExecutor, or any other
    production module imports this module except the one reviewed
    exception below -- Slice E1 introduces the primitive only, never
    wiring it to anything itself.

    `tier1/execution_coordinator.py` is the one reviewed exception
    (ADR-022 Phase E, Slice E2, 2026-08-11): it composes
    `plan_authorization_is_fresh()` as its own freshness gate -- see
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
                and (node.module or "").endswith("security_plan_freshness")
            ):
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []
