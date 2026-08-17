"""Stronger, dedicated structural tests for
`pfsense_mcp.security_privileges` and
`pfsense_mcp.security_bootstrap_transaction` (`ADR-033` implementation
Phase B) -- proving both are pure, read-only, and have no relationship
to Tier 1's cryptographic authorization chain, by direct AST inspection
of the actual shipped source. Mirrors
`tests/test_security_discovery_isolation.py`/
`tests/test_security_doctor_isolation.py`'s structure exactly.

Neither module is a `tier1` isolation exemption -- both must never
import `pfsense_mcp.tier1` in any form.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
PRIVILEGES_MODULE_PATH = ROOT / "src/pfsense_mcp/security_privileges.py"
TRANSACTION_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_transaction.py"

#: Deliberately excludes "replace" -- str.replace() is a legitimate,
#: pure, non-mutating call this module uses for URL slugification
#: (compute_privilege_from_url()); it collides in name only with
#: file-replace semantics, not in behavior.
_FORBIDDEN_MUTATING_CALLS = {
    "advance",
    "provision_anchor_baseline",
    "provision_production_anchor_baseline",
    "unlink",
    "rmdir",
    "remove",
    "write_bytes",
    "write_text",
    "rename",
    "write_secure_new",
    "post",
    "patch",
    "put",
    "delete",
}

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "TpmHostWitnessAnchor",
    "RestApiClient",
}

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "httpx",
    "requests",
    "socket",
    "urllib",
}

_PRIVILEGES_EXPECTED_PUBLIC_SURFACE = {
    "EvidenceClass",
    "SchemaPrivilegeLookup",
    "ResolvedPrivilege",
    "ToolPrivilegeRequirement",
    "DriftFindingKind",
    "DriftFinding",
    "DriftReport",
    "VERIFIED_PACKAGE_VERSION_MIN",
    "VERIFIED_PACKAGE_VERSION_MAX",
    "compute_privilege_from_url",
    "full_api_path",
    "lookup_schema_privileges",
    "resolve_privilege",
    "registered_read_tool_requirements",
    "write_protected_tool_requirements",
    "read_profile_requirements",
    "write_protected_profile_requirements",
    "resolve_profile_privileges",
    "distinct_ok_privileges",
    "compute_account_drift",
    "check_package_version_support",
}

_TRANSACTION_EXPECTED_PUBLIC_SURFACE = {
    "BOOTSTRAP_ONLY_PRIVILEGE",
    "BootstrapState",
    "InvariantViolation",
    "BootstrapTransaction",
    "allowed_next_states",
    "is_legal_transition",
    "check_invariants",
    "is_steady_state_privilege_set",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> set[str]:
    tree = _tree(path)
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }


def _called_attributes(path: Path) -> set[str]:
    tree = _tree(path)
    return {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }


def _referenced_names(path: Path) -> set[str]:
    tree = _tree(path)
    return {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }


def _public_surface(path: Path) -> set[str]:
    tree = _tree(path)
    return {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    } | {
        node.targets[0].id
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and not node.targets[0].id.startswith("_")
    }


def test_both_modules_exist():
    assert PRIVILEGES_MODULE_PATH.is_file()
    assert TRANSACTION_MODULE_PATH.is_file()


def test_neither_module_imports_pfsense_mcp_tier1_in_any_form():
    for path in (PRIVILEGES_MODULE_PATH, TRANSACTION_MODULE_PATH):
        imported = _imports(path)
        offending = {
            module
            for module in imported
            for root in _FORBIDDEN_IMPORT_ROOTS
            if module == root or module.startswith(f"{root}.")
        }
        assert not offending, f"{path.name} imports forbidden module(s): {offending}"


def test_neither_module_calls_a_mutating_or_network_method():
    for path in (PRIVILEGES_MODULE_PATH, TRANSACTION_MODULE_PATH):
        offending = _called_attributes(path) & _FORBIDDEN_MUTATING_CALLS
        assert not offending, f"{path.name} calls mutating/network method(s): {offending}"


def test_neither_module_references_execution_capable_symbols():
    for path in (PRIVILEGES_MODULE_PATH, TRANSACTION_MODULE_PATH):
        offending = _referenced_names(path) & _FORBIDDEN_REFERENCED_NAMES
        assert not offending, f"{path.name} references forbidden symbol(s): {offending}"


def test_security_privileges_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(PRIVILEGES_MODULE_PATH) == _PRIVILEGES_EXPECTED_PUBLIC_SURFACE


def test_security_bootstrap_transaction_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(TRANSACTION_MODULE_PATH) == _TRANSACTION_EXPECTED_PUBLIC_SURFACE


def test_neither_module_is_in_the_tier1_isolation_exemption_list():
    """Neither needs to be -- neither imports pfsense_mcp.tier1 at all."""

    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_privileges.py" not in source
    assert "security_bootstrap_transaction.py" not in source


def test_security_privileges_not_yet_wired_into_security_cli():
    """This phase is explicitly library-only -- no CLI subcommand was
    added. If a future phase wires this in, this test should be updated
    deliberately, not silently pass either way."""

    cli_source = (ROOT / "src/pfsense_mcp/security_cli.py").read_text(encoding="utf-8")
    assert "security_privileges" not in cli_source
    assert "security_bootstrap_transaction" not in cli_source


def test_security_privileges_not_wired_into_doctor():
    """Requirement 6: do not add remote doctor checks this phase."""

    doctor_source = (ROOT / "src/pfsense_mcp/security_doctor.py").read_text(encoding="utf-8")
    assert "security_privileges" not in doctor_source
    assert "security_bootstrap_transaction" not in doctor_source
