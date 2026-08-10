"""Stronger, dedicated structural tests for `pfsense_mcp.security_discovery`
-- the second, narrow exception to production never importing
`pfsense_mcp.tier1` (`tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`). These prove, by
direct AST inspection of the actual shipped source (not by trusting the
module's own docstring), that ADR-021 Phase B's discovery CLI is
exactly as narrow as claimed: read-only, cannot reach PREPARE/EXECUTE/
WRITE, never calls `advance()` or any provisioning primitive, and does
not change the public MCP contract.

Mirrors `tests/test_tier1_anchor_check_isolation.py`'s structure
exactly, adapted for the two differences this module legitimately has:
it reads (never mutates) `WriteEndpoints`/`Capability`/profile state as
part of capability-posture discovery, which `tier1_anchor_check.py`
never needed to.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
DISCOVERY_MODULE_PATH = ROOT / "src/pfsense_mcp/security_discovery.py"
CLI_MODULE_PATH = ROOT / "src/pfsense_mcp/security_cli.py"

# Every tier1 method name that mutates state (a store write, a TPM
# advance, provisioning, confirmation, rollback, execution, key
# rotation) -- this module may only ever call read-shaped methods
# (load_production_store_config, open_production_store,
# anchor_provisioning_status, read, active_entries).
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
# toward PREPARE/EXECUTE/WRITE, not just reading capability/anchor
# state. Deliberately does NOT include "WriteEndpoints" -- unlike
# tier1_anchor_check.py, this module legitimately reads (never
# mutates) it via WriteEndpoints.active_entries() as part of
# capability-posture discovery.
_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
}

# Deliberately does NOT include "pfsense_mcp.write_endpoints" -- see
# above.
_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tools",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.contract",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
}

_EXPECTED_PUBLIC_SURFACE = {
    "CapabilityPosture",
    "AnchorAssurance",
    "AnchorEvidenceState",
    "CapabilityPostureDiscovery",
    "AnchorAssuranceDiscovery",
    "SecurityPostureDiscovery",
    "discover_capability_posture",
    "discover_anchor_assurance",
    "discover_security_posture",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists_and_is_the_second_isolation_exemption():
    assert DISCOVERY_MODULE_PATH.is_file()


def test_never_calls_a_mutating_tier1_method():
    tree = _tree(DISCOVERY_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_discovery.py calls mutating method(s): {offending}"


def test_never_references_prepare_execute_or_write_symbols():
    tree = _tree(DISCOVERY_MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_discovery.py references forbidden symbol(s): {offending}"


def test_never_imports_write_or_execution_capable_modules():
    tree = _tree(DISCOVERY_MODULE_PATH)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_discovery.py imports forbidden module(s): {offending}"


def test_public_surface_is_exactly_the_reviewed_discovery_api():
    """The smaller and more exact this set, the easier the module stays
    auditable as "read-only discovery data model, nothing else"."""

    tree = _tree(DISCOVERY_MODULE_PATH)
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE


def test_security_cli_does_not_import_pfsense_mcp_tier1_directly():
    """security_cli.py (the actual `pfsense-mcp-security` entrypoint)
    must only ever import from security_discovery.py, never
    pfsense_mcp.tier1 directly -- keeping the isolation exemption's
    surface to exactly security_discovery.py, mirroring
    tier1_anchor_check.py/application.py's own established pattern."""

    tree = _tree(CLI_MODULE_PATH)
    imported_modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(
        module == "pfsense_mcp.tier1" or module.startswith("pfsense_mcp.tier1.") for module in imported_modules
    )
    relative_imports = {
        (node.module or "") for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level
    }
    assert "security_discovery" in relative_imports


def test_security_cli_never_calls_a_mutating_tier1_method_either():
    """Defense in depth: even though security_cli.py never imports
    pfsense_mcp.tier1, it must never call a mutating-shaped method name
    either -- it only ever calls security_discovery's own read-only
    functions."""

    tree = _tree(CLI_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_cli.py calls mutating method(s): {offending}"
