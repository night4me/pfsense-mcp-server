"""Stronger, dedicated structural tests for
`pfsense_mcp.security_discovery_export` -- the eighth, narrow exception
to production never importing `pfsense_mcp.tier1`
(`tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`).

These prove, by direct AST inspection of the actual shipped source (not
by trusting the module's own docstring), that the isolated Batch-1
signer's off-runtime anchor-assurance discovery path is exactly as
narrow as claimed: it never imports `pfsense_mcp.tier1.production_
store` (and therefore never `sqlite3`, never a runtime store key of any
kind), never calls a mutating tier1 method (in particular, never
`TpmHostWitnessAnchor.advance()` -- only `.read()`), and exposes exactly
one public function.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_discovery_export.py"

# Same discipline as test_security_discovery_isolation.py's own list --
# this module must never call any of these either.
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
    "sign_anchor_evidence_export",
}

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "WriteEndpoints",
    "CapabilityAdapter",
    "sign_anchor_evidence_export",
}

# The whole point of this module: it must never import the runtime
# store, and therefore never sqlite3, and never any write/execution
# capable module either.
_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1.production_store",
    "pfsense_mcp.tier1.executor",
    "pfsense_mcp.tier1.contract",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "sqlite3",
}

# The only pfsense_mcp.tier1 submodules this file may ever import.
_ALLOWED_TIER1_IMPORT_ROOTS = {
    "pfsense_mcp.tier1.anchor_evidence_export",
    "pfsense_mcp.tier1.anti_rollback_tpm_witness",
    "pfsense_mcp.tier1.ed25519_authority",
    "pfsense_mcp.tier1.errors",
}

_EXPECTED_PUBLIC_SURFACE = {"discover_anchor_assurance_from_export"}


def _tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))


def _imported_modules(tree: ast.Module) -> set[str]:
    # security_discovery_export.py lives directly inside the pfsense_mcp
    # package, so a level-1 relative import (`from .tier1.foo import
    # bar`) resolves to `pfsense_mcp.tier1.foo` -- resolved explicitly
    # here so the forbidden/allowed root checks below see the same
    # fully-qualified names regardless of whether the source used an
    # absolute or relative import.
    absolute = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    from_imports: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom):
            continue
        if node.level == 0:
            from_imports.add(node.module or "")
        elif node.level == 1:
            from_imports.add(f"pfsense_mcp.{node.module}" if node.module else "pfsense_mcp")
    return absolute | from_imports


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_never_calls_a_mutating_tier1_method():
    tree = _tree()
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_discovery_export.py calls mutating/signing method(s): {offending}"


def test_never_references_prepare_execute_write_or_signing_symbols():
    tree = _tree()
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_discovery_export.py references forbidden symbol(s): {offending}"


def test_never_imports_the_runtime_store_or_write_capable_modules():
    imported = _imported_modules(_tree())
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"security_discovery_export.py imports forbidden module(s): {offending}"


def test_only_imports_the_reviewed_tier1_submodules():
    imported = _imported_modules(_tree())
    tier1_imports = {
        module for module in imported if module == "pfsense_mcp.tier1" or module.startswith("pfsense_mcp.tier1.")
    }
    offending = tier1_imports - _ALLOWED_TIER1_IMPORT_ROOTS
    assert not offending, f"security_discovery_export.py imports unreviewed pfsense_mcp.tier1 submodule(s): {offending}"
    assert tier1_imports, "expected this module to import at least one reviewed pfsense_mcp.tier1 submodule"


def test_public_surface_is_exactly_one_function():
    tree = _tree()
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE
