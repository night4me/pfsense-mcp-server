"""Structural (AST) tests for `pfsense_mcp.security_plan` -- the
`DISCOVER -> SELECT TARGET -> EVALUATE VALIDITY -> ASSESS PREREQUISITES
-> GENERATE PLAN` slice. Proves, by direct inspection of the actual
shipped source (not by trusting the module's own docstring), that this
module:

  - never imports `pfsense_mcp.tier1` at all (unlike
    `security_discovery.py`, it needs no isolation exemption --
    `tests/tier1/test_isolation.py`'s exemption list is unchanged by
    this slice);
  - never calls a mutating-shaped method name;
  - never references PREPARE/EXECUTE/WRITE-capable symbols;
  - never imports a write/execution-capable module;
  - has exactly the reviewed public surface;
  - never emits `MutationClass.DESTRUCTIVE_DEPROVISIONING` or
    `AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION` from any
    step-construction call site (declared for schema forward-
    compatibility only -- see `security_plan.py`'s own docstrings).

Mirrors `tests/test_security_discovery_isolation.py`'s structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
PLAN_MODULE_PATH = ROOT / "src/pfsense_mcp/security_plan.py"
CLI_MODULE_PATH = ROOT / "src/pfsense_mcp/security_cli.py"

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

_FORBIDDEN_REFERENCED_NAMES = {
    "RecoveryContract",
    "MutationExecutor",
    "WriteApiClient",
    "PfSenseClient",
    "CapabilityAdapter",
    "WriteEndpoints",
    "SqliteRecoveryContractStore",
}

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.tools",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
}

_EXPECTED_PUBLIC_SURFACE = {
    "TargetValidity",
    "AxisTransitionKind",
    "MutationClass",
    "AuthorizationLevel",
    "SecurityImpact",
    "PlanOverallStatus",
    "PlanStep",
    "SecurityPosturePlan",
    "generate_security_posture_plan",
}

_NEVER_EMITTED_ENUM_LITERALS = {
    "DESTRUCTIVE_DEPROVISIONING",
    "SEPARATE_DEPROVISION_AUTHORIZATION",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert PLAN_MODULE_PATH.is_file()


def test_never_imports_pfsense_mcp_tier1_at_all():
    """Unlike security_discovery.py, this module needs no tier1
    isolation exemption -- it must never import pfsense_mcp.tier1 in
    any form."""

    tree = _tree(PLAN_MODULE_PATH)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    offending = {m for m in imported for root in _FORBIDDEN_IMPORT_ROOTS if m == root or m.startswith(f"{root}.")}
    assert not offending, f"security_plan.py imports forbidden module(s): {offending}"


def test_never_calls_a_mutating_tier1_method():
    tree = _tree(PLAN_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_plan.py calls mutating method(s): {offending}"


def test_never_references_prepare_execute_or_write_symbols():
    tree = _tree(PLAN_MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_plan.py references forbidden symbol(s): {offending}"


def test_public_surface_is_exactly_the_reviewed_planning_api():
    tree = _tree(PLAN_MODULE_PATH)
    top_level_public_names = {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    }
    assert top_level_public_names == _EXPECTED_PUBLIC_SURFACE


def test_only_imports_from_security_discovery_within_the_package():
    """The one and only intra-package import this module needs is
    security_discovery's own already-read-only public surface --
    proves this module adds no new source of live evidence."""

    tree = _tree(PLAN_MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_discovery"}


def test_no_step_construction_site_ever_passes_the_never_emitted_enum_members():
    """Static defense-in-depth alongside test_security_plan.py's
    behavioral sweep: no PlanStep(...) call anywhere in the module's
    source literally spells out MutationClass.DESTRUCTIVE_DEPROVISIONING
    or AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION as an
    argument -- the only occurrences of these names may be their own
    enum member definitions."""

    tree = _tree(PLAN_MODULE_PATH)
    offending_lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "PlanStep":
            for keyword in node.keywords:
                if isinstance(keyword.value, ast.Attribute) and keyword.value.attr in _NEVER_EMITTED_ENUM_LITERALS:
                    offending_lines.append(node.lineno)
    assert not offending_lines, f"PlanStep(...) call(s) at line(s) {offending_lines} pass a never-emitted enum member"


def test_security_cli_plan_subcommand_does_not_import_pfsense_mcp_tier1():
    tree = _tree(CLI_MODULE_PATH)
    imported_modules = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
    assert not any(
        module == "pfsense_mcp.tier1" or module.startswith("pfsense_mcp.tier1.") for module in imported_modules
    )
    relative_imports = {
        (node.module or "") for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level
    }
    assert "security_plan" in relative_imports
    assert "security_discovery" in relative_imports


def test_security_cli_never_calls_a_mutating_tier1_method_either():
    tree = _tree(CLI_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_cli.py calls mutating method(s): {offending}"
