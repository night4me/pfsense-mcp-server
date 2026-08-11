"""Structural (AST) tests for `pfsense_mcp.tier1.execution_coordinator`
-- ADR-022 Phase E, Slice E2. Proves, by direct inspection of the
actual shipped source, that this module:

  - only imports `authorization_consumption_store`, `ed25519_authority`,
    and `errors` from `pfsense_mcp.tier1` (never `executor`,
    `state_machine`, `store`, `contract`, or any other tier1 submodule);
  - never imports `write_api_client`/`pfsense_client`/`rest_api_client`/
    `transport`/`tools` (the coordinator reaches nothing beyond its five
    composed primitives in this slice -- it does not even reach
    `MutationExecutor` yet, let alone anything beyond it);
  - never calls a mutating/IO-shaped method name other than its own,
    single, legitimate `try_consume` call;
  - never references RecoveryContract/MutationExecutor/store/state-
    machine/WriteEndpoints-family symbols;
  - never defines an `execute`/`apply`/`consume`-shaped method (its own
    `authorize_and_consume` is a distinct, reviewed name, not one of the
    forbidden exact names);
  - has exactly the reviewed public surface;
  - is never imported by any production module -- proving Slice E2
    introduces no wiring, no construction site, no MCP exposure;
  - never references `target_identity_digest`/`netgate_id`/`pfhostid`
    or any substitute appliance-identity mechanism.

Mirrors `tests/test_security_authorization_verifier_isolation.py`'s
structure, adapted for a tier1-native module reaching outward into the
`security_` family (ADR-024's "sixth exception, other direction").
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[2]
MODULE_PATH = ROOT / "src/pfsense_mcp/tier1/execution_coordinator.py"
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"

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
    "apply",
    "rotate_key",
    "increment_counter",
    "connect",
    "commit",
    # Deliberately NOT included: "try_consume" -- this module's one,
    # legitimate, reviewed state-changing call.
}

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "WriteEndpoints",
    "SqliteRecoveryContractStore",
    "RecoveryState",
    "ProtectedArtifact",
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "ReconciliationEvidence",
    "ReconciliationVerifier",
    "target_identity_digest",
    "netgate_id",
    "pfhostid",
}

_EXPECTED_PUBLIC_SURFACE = {
    "ExecutionCoordinator",
    "PreExecutionAuthorizationDenied",
    "PreExecutionAuthorizationGranted",
}

_ALLOWED_TIER1_RELATIVE_IMPORTS = {"authorization_consumption_store", "ed25519_authority", "errors"}

_ALLOWED_RELATIVE_IMPORTS = _ALLOWED_TIER1_RELATIVE_IMPORTS | {
    "security_authorization",
    "security_authorization_verifier",
    "security_discovery",
    "security_plan_freshness",
}

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.state_machine",
    "pfsense_mcp.tier1.store",
    "pfsense_mcp.tier1.contract",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_only_imports_reviewed_tier1_submodules():
    tree = _tree(MODULE_PATH)
    tier1_imports: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 1:
            module = node.module or ""
            if module in _ALLOWED_TIER1_RELATIVE_IMPORTS:
                tier1_imports.add(module)
            elif module:
                raise AssertionError(f"execution_coordinator.py imports unreviewed tier1 sibling: {module}")
    assert tier1_imports == _ALLOWED_TIER1_RELATIVE_IMPORTS, (
        f"execution_coordinator.py must import exactly {_ALLOWED_TIER1_RELATIVE_IMPORTS}, got {tier1_imports}"
    )


def test_only_imports_reviewed_modules_within_the_package():
    tree = _tree(MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == _ALLOWED_RELATIVE_IMPORTS


def test_never_imports_forbidden_roots():
    tree = _tree(MODULE_PATH)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and not node.level
    }
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"execution_coordinator.py imports forbidden module(s): {offending}"


def test_never_calls_a_mutating_or_io_shaped_method_beyond_try_consume():
    tree = _tree(MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"execution_coordinator.py calls mutating/IO method(s): {offending}"


def test_never_calls_sqlite3_connect_or_open_directly():
    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_forbidden_symbols():
    tree = _tree(MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"execution_coordinator.py references forbidden symbol(s): {offending}"


def test_never_defines_an_execute_or_apply_or_consume_shaped_method():
    tree = _tree(MODULE_PATH)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))}
    forbidden = {"execute", "apply", "consume", "consume_and_execute", "is_authorized_for_runtime", "authorize_runtime"}
    offending = function_names & forbidden
    assert not offending, f"execution_coordinator.py defines a forbidden bearer-capability-shaped function: {offending}"


def test_public_surface_is_exactly_the_reviewed_api():
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


def test_does_not_create_a_recovery_contract_or_call_store_create():
    source = MODULE_PATH.read_text(encoding="utf-8")
    for forbidden in (
        "RecoveryContract(",
        "store.create(",
        "store.confirm(",
        ".execute(",
        "SqliteRecoveryContractStore(",
    ):
        assert forbidden not in source


def test_no_production_module_imports_execution_coordinator():
    """No factory/application/tool-registration module, and no other
    tier1 module, imports `execution_coordinator` yet -- Slice E2
    introduces the coordinator itself, no construction site, no
    consumer."""

    importers = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if path == MODULE_PATH:
            continue
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level and (node.module or "") == "execution_coordinator":
                importers.append(path.relative_to(ROOT).as_posix())
            if (
                isinstance(node, ast.ImportFrom)
                and not node.level
                and (node.module or "") in {"pfsense_mcp.tier1.execution_coordinator", "tier1.execution_coordinator"}
            ):
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []


def test_no_production_module_constructs_execution_coordinator():
    """Belt-and-suspenders on top of the import check above: even an
    aliased/renamed import could not be followed by construction without
    the literal `ExecutionCoordinator(` call text appearing somewhere."""

    offenders = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if path == MODULE_PATH:
            continue
        if "ExecutionCoordinator(" in path.read_text(encoding="utf-8"):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []
