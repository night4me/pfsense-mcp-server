"""Structural (AST) tests for `pfsense_mcp.security_plan_digest` --
ADR-022 Phase B's canonical `PlanDigest` computation. Proves, by direct
inspection of the actual shipped source, that this module:

  - only ever imports `canonical` from `pfsense_mcp.tier1` (never
    `store`, `contract`, `executor`, `confirmation`, `anti_rollback`, or
    any other tier1 submodule this exemption's two siblings legitimately
    do need);
  - never calls a mutating-shaped method name;
  - never references PREPARE/EXECUTE/WRITE/authorization-artifact-capable
    symbols;
  - never imports a write/execution-capable module;
  - has exactly the reviewed public surface;
  - is only ever imported, within the package, by `security_cli.py`.

Mirrors `tests/test_security_plan_isolation.py`'s structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
DIGEST_MODULE_PATH = ROOT / "src/pfsense_mcp/security_plan_digest.py"
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
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "ReconciliationEvidence",
}

# The only tier1 submodule this module may ever import is `canonical`
# (pure, stateless canonicalization/hashing, zero I/O). Every other
# tier1 submodule -- including the ones security_discovery.py
# legitimately needs -- is forbidden here.
_ALLOWED_TIER1_SUBMODULE = "canonical"

_EXPECTED_PUBLIC_SURFACE = {
    "PLAN_DIGEST_SCHEMA_VERSION",
    "compute_plan_digest",
    "verify_plan_digest",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert DIGEST_MODULE_PATH.is_file()


def test_only_imports_canonical_from_pfsense_mcp_tier1():
    tree = _tree(DIGEST_MODULE_PATH)
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

    allowed = {"pfsense_mcp.tier1.canonical", "tier1.canonical"}
    offending = tier1_imports - allowed
    assert not offending, f"security_plan_digest.py imports forbidden tier1 submodule(s): {offending}"
    assert tier1_imports, "security_plan_digest.py must import tier1.canonical -- reuse, not reinvent"


def test_never_calls_a_mutating_or_io_shaped_method():
    tree = _tree(DIGEST_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_plan_digest.py calls mutating/IO method(s): {offending}"


def test_never_calls_sqlite3_connect_or_open_directly():
    tree = _tree(DIGEST_MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_prepare_execute_write_or_authorization_artifact_symbols():
    tree = _tree(DIGEST_MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_plan_digest.py references forbidden symbol(s): {offending}"


def test_public_surface_is_exactly_the_reviewed_digest_api():
    tree = _tree(DIGEST_MODULE_PATH)
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


def test_only_imports_security_plan_and_tier1_canonical_within_the_package():
    """The only two relative imports this module may ever have: its
    sibling `security_plan` (the plan content it hashes) and the tier1
    subpackage's `canonical` (the hashing primitive it reuses) --
    covered separately, more strictly, by
    `test_only_imports_canonical_from_pfsense_mcp_tier1` above."""

    tree = _tree(DIGEST_MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_plan", "tier1.canonical"}


def test_security_cli_imports_security_plan_digest_for_display_only():
    tree = _tree(CLI_MODULE_PATH)
    relative_imports = {
        (node.module or "") for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level
    }
    assert "security_plan_digest" in relative_imports

    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "") == "security_plan_digest"
        for alias in node.names
    }
    # security_cli.py must never import verify_plan_digest -- there is
    # nothing in this build for it to verify against (no authorization
    # artifact exists), and importing it would invite a future,
    # unreviewed "just wire it up" temptation.
    assert imported_names == {"PLAN_DIGEST_SCHEMA_VERSION", "compute_plan_digest"}
