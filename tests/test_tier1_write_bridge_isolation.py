"""Structural (AST) tests for `pfsense_mcp.tier1_write_bridge` -- W3
Slice 4's sixth, narrowest-possible exception to `pfsense_mcp.tier1`
never being imported from outside its own package. Proves, by direct
inspection of the actual shipped source:

  - this module imports only `tier1.alias_description.AliasDescriptionChangeV1`
    and `tier1.production_runtime.{ProductOutcomeState, build_production_runtime}`
    -- never `store`, `contract`, `executor`, `state_machine`,
    `confirmation`, `reconciliation`, `authorization_consumption_store`,
    or any other tier1 submodule;
  - this module never constructs, calls, or references a lower-level
    Tier-1 object (RecoveryContract, MutationExecutor, WriteApiClient,
    SqliteRecoveryContractStore, PinnedAuthoritySet, ...);
  - no private signing key material is loaded, accepted, or referenced;
  - neither `tools/registry.py` nor
    `tools/write/set_firewall_alias_description.py` import
    `pfsense_mcp.tier1` at all -- only this module's own two exposed
    functions are ever called, keeping the isolation exemption's surface
    to exactly this one file (mirrors `tier1_anchor_check.py`'s own
    precedent, verified the same way by
    `tests/test_tier1_anchor_check_isolation.py`).

Mirrors `tests/test_security_authorization_verifier_isolation.py`'s
structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/tier1_write_bridge.py"
PRODUCTION_ROOT = ROOT / "src/pfsense_mcp"
REGISTRY_PATH = PRODUCTION_ROOT / "tools/registry.py"
WRITE_TOOL_PATH = PRODUCTION_ROOT / "tools/write/set_firewall_alias_description.py"

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "SqliteRecoveryContractStore",
    "SqliteAuthorizationConsumptionStore",
    "AuthorizationConsumptionStore",
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "ReconciliationEvidence",
    "ReconciliationVerifier",
    "RecoveryState",
    "PinnedAuthority",
    "PinnedAuthoritySet",
    "PlanAuthorizationV2",
    "Ed25519PrivateKey",
    "private_key",
    "load_key_material",
}

_EXPECTED_PUBLIC_SURFACE = {"can_construct_write_runtime", "request_alias_description_change"}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_only_imports_the_two_accepted_tier1_submodules():
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

    allowed = {
        "pfsense_mcp.tier1.alias_description",
        "tier1.alias_description",
        "pfsense_mcp.tier1.production_runtime",
        "tier1.production_runtime",
    }
    offending = tier1_imports - allowed
    assert not offending, f"tier1_write_bridge.py imports forbidden tier1 submodule(s): {offending}"
    assert tier1_imports, "tier1_write_bridge.py must import from tier1.alias_description/production_runtime"


def test_never_references_lower_level_tier1_symbols():
    tree = _tree(MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"tier1_write_bridge.py references forbidden symbol(s): {offending}"


def test_public_surface_is_exactly_the_two_reviewed_functions():
    tree = _tree(MODULE_PATH)
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE


def test_never_constructs_a_runtime_object_directly():
    """Only ever calls `build_production_runtime()` -- never constructs
    `ProductionAliasDescriptionRuntime` itself, which would be a second
    construction path outside W2's own sole factory."""

    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "ProductionAliasDescriptionRuntime" not in called_names


def _is_tier1_module(module: str) -> bool:
    return module == "tier1" or module.startswith("tier1.")


def _find_direct_tier1_imports(path: Path) -> list[str]:
    tree = _tree(path)
    offending = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if _is_tier1_module(module.removeprefix("pfsense_mcp.")) or (node.level and _is_tier1_module(module)):
                offending.append(module)
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_tier1_module(alias.name.removeprefix("pfsense_mcp.")):
                    offending.append(alias.name)
    return offending


def test_tools_registry_never_imports_tier1_directly():
    offending = _find_direct_tier1_imports(REGISTRY_PATH)
    assert offending == [], f"tools/registry.py imports pfsense_mcp.tier1 directly: {offending}"


def test_write_tool_module_never_imports_tier1_directly():
    offending = _find_direct_tier1_imports(WRITE_TOOL_PATH)
    assert offending == [], (
        f"tools/write/set_firewall_alias_description.py imports pfsense_mcp.tier1 directly: {offending}"
    )


def test_write_tool_module_imports_only_the_bridge_and_result_model():
    tree = _tree(WRITE_TOOL_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports <= {"", "tier1_write_bridge", "models.write_outcome"}
