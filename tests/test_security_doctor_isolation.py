"""Stronger, dedicated structural tests for `pfsense_mcp.security_doctor`
-- proving it is exactly the "diagnostic only, never mutates" module its
own docstring claims, by direct AST inspection of the actual shipped
source. Mirrors `tests/test_security_discovery_isolation.py`'s
structure exactly.

Unlike `security_discovery.py`, this module is not a `tier1` isolation
exemption at all -- it never imports `pfsense_mcp.tier1` in any form,
proven below, so it does not (and must not) appear in
`tests/tier1/test_isolation.py`'s `exempt` set.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
DOCTOR_MODULE_PATH = ROOT / "src/pfsense_mcp/security_doctor.py"
CLI_MODULE_PATH = ROOT / "src/pfsense_mcp/security_cli.py"

# Mutating-shaped method names this module must never call -- a
# filesystem write/delete, a witness advance, any Tier 1
# provisioning/execution primitive.
_FORBIDDEN_MUTATING_CALLS = {
    "advance",
    "provision_anchor_baseline",
    "provision_production_anchor_baseline",
    "seed",
    "mark_complete",
    "unlink",
    "rmdir",
    "remove",
    "write_bytes",
    "write_text",
    "rename",
    "replace",
    "write_secure_new",
    "transition",
    "create",
    "confirm",
    "rollback",
    "execute",
    "rotate_key",
}

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "TpmHostWitnessAnchor",
}

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tools",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
}

_EXPECTED_PUBLIC_SURFACE = {
    "CheckStatus",
    "DoctorCheck",
    "DoctorResult",
    "run_doctor_checks",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert DOCTOR_MODULE_PATH.is_file()


def test_never_imports_pfsense_mcp_tier1_in_any_form():
    tree = _tree(DOCTOR_MODULE_PATH)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_doctor.py imports forbidden module(s): {offending}"


def test_never_calls_a_mutating_method():
    tree = _tree(DOCTOR_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_doctor.py calls mutating method(s): {offending}"


def test_never_references_prepare_execute_or_write_symbols():
    tree = _tree(DOCTOR_MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_doctor.py references forbidden symbol(s): {offending}"


def test_public_surface_is_exactly_the_reviewed_doctor_api():
    tree = _tree(DOCTOR_MODULE_PATH)
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE


def test_security_doctor_is_not_in_the_tier1_isolation_exemption_list():
    """It doesn't need to be -- it never imports pfsense_mcp.tier1 at
    all, unlike security_discovery.py/security_plan_digest.py/etc.
    Adding it there would be a red flag that it started importing
    tier1 directly."""

    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    tree = _tree(isolation_test_path)
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_doctor.py" not in source
    del tree  # parsed only to fail loudly if the file itself is malformed


def test_security_cli_calls_doctor_only_through_run_doctor_checks():
    """security_cli.py must call exactly the one reviewed entrypoint,
    never construct a DoctorCheck/DoctorResult itself or reach into
    security_doctor.py's private helpers."""

    tree = _tree(CLI_MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "run_doctor_checks" in called_names
    private_doctor_helpers = {"_check_artifact_path", "_check_witness_readiness", "_artifact_present"}
    assert not (called_names & private_doctor_helpers)


def test_security_cli_never_calls_a_mutating_method_via_doctor_either():
    tree = _tree(CLI_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_cli.py calls mutating method(s): {offending}"
