"""Structural (AST) tests for `pfsense_mcp.security_authorization_verifier`
-- ADR-022 Phase D's pure signature/expiry/step-scope verification.
Proves, by direct inspection of the actual shipped source, that this
module:

  - only ever imports `ed25519_authority` from `pfsense_mcp.tier1`
    (never `store`, `contract`, `executor`, `state_machine`,
    `confirmation`, `reconciliation`, or any other tier1 submodule);
  - never calls a mutating/IO-shaped method name;
  - never references RecoveryContract/MutationExecutor/store/state-
    machine/WriteEndpoints-family symbols;
  - never defines an execute/apply/consume-shaped method;
  - has exactly the reviewed public surface;
  - is never imported by any production module -- only by its own
    tests -- proving Phase D introduces no execution wiring.

Mirrors `tests/test_security_authorization_isolation.py`'s structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_authorization_verifier.py"
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
    "try_consume",
    "rotate_key",
    "increment_counter",
    "connect",
    "commit",
}

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "WriteEndpoints",
    "SqliteRecoveryContractStore",
    "SqliteAuthorizationConsumptionStore",
    "AuthorizationConsumptionStore",
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "ReconciliationEvidence",
    "ReconciliationVerifier",
    "RecoveryState",
}

_EXPECTED_PUBLIC_SURFACE = {
    "plan_authorization_authorizes_step",
    "plan_authorization_is_current",
    "verify_plan_authorization_signature",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_only_imports_ed25519_authority_from_pfsense_mcp_tier1():
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

    allowed = {"pfsense_mcp.tier1.ed25519_authority", "tier1.ed25519_authority"}
    offending = tier1_imports - allowed
    assert not offending, f"security_authorization_verifier.py imports forbidden tier1 submodule(s): {offending}"
    assert tier1_imports, (
        "security_authorization_verifier.py must import tier1.ed25519_authority -- reuse, not reinvent"
    )


def test_never_calls_a_mutating_or_io_shaped_method():
    tree = _tree(MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_authorization_verifier.py calls mutating/IO method(s): {offending}"


def test_never_calls_sqlite3_connect_or_open_directly():
    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_execution_or_persistence_symbols():
    tree = _tree(MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_authorization_verifier.py references forbidden symbol(s): {offending}"


def test_never_defines_an_execute_or_apply_or_consume_shaped_method():
    tree = _tree(MODULE_PATH)
    function_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    forbidden = {"execute", "apply", "consume", "consume_and_execute", "is_authorized_for_runtime", "authorize_runtime"}
    offending = function_names & forbidden
    assert not offending, (
        f"security_authorization_verifier.py defines a forbidden bearer-capability-shaped function: {offending}"
    )


def test_public_surface_is_exactly_the_reviewed_verifier_api():
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


def test_only_imports_security_authorization_and_tier1_ed25519_authority_within_the_package():
    tree = _tree(MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_authorization", "tier1.ed25519_authority"}


def test_no_production_module_imports_security_authorization_verifier():
    """No MCP tool, security_cli.py, MutationExecutor, or any other
    production request-handling/execution module ever imports this
    module -- Phase D introduces no consumer, only the verification
    primitive itself."""

    importers = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if path == MODULE_PATH:
            continue
        tree = _tree(path)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and node.level
                and (node.module or "") == "security_authorization_verifier"
            ):
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []
