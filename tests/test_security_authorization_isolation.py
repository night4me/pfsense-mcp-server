"""Structural (AST) tests for `pfsense_mcp.security_authorization` --
ADR-022 Phase C's `PlanAuthorization`/`DeprovisionAuthorization` data
models and signature construction. Proves, by direct inspection of the
actual shipped source, that this module:

  - only ever imports `canonical` from `pfsense_mcp.tier1` (never
    `store`, `contract`, `executor`, `confirmation`, `anti_rollback`, or
    any other tier1 submodule);
  - never calls a mutating/IO-shaped method name (`private_key.sign()`
    is legitimate signing construction, not a mutation, and is
    deliberately not in the forbidden set);
  - never references PREPARE/EXECUTE/WRITE/RecoveryContract/
    ConfirmationEvidence-family symbols;
  - has exactly the reviewed public surface;
  - is never imported by `security_cli.py`, any MCP tool, or any other
    production request-handling module -- only by its own tests.

Mirrors `tests/test_security_plan_digest_isolation.py`'s structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_authorization.py"
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
    "ReconciliationVerifier",
}

_ALLOWED_TIER1_SUBMODULE = "canonical"

_EXPECTED_PUBLIC_SURFACE = {
    "AUTHORIZATION_SIGNING_ALGORITHM",
    "DEPROVISION_AUTHORIZATION_SCHEMA_VERSION",
    "PLAN_AUTHORIZATION_SCHEMA_VERSION",
    "AuthorizationEvidenceFingerprint",
    "DeprovisionAuthorization",
    "DeprovisionAuthorizationPayload",
    "PlanAuthorization",
    "PlanAuthorizationPayload",
    "SecurityAuthorizationError",
    "build_deprovision_authorization_payload",
    "build_plan_authorization_payload",
    "deprovision_authorization_signing_payload",
    "plan_authorization_payload_of",
    "plan_authorization_signing_payload",
    "sign_deprovision_authorization",
    "sign_plan_authorization",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_only_imports_canonical_from_pfsense_mcp_tier1():
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

    allowed = {"pfsense_mcp.tier1.canonical", "tier1.canonical"}
    offending = tier1_imports - allowed
    assert not offending, f"security_authorization.py imports forbidden tier1 submodule(s): {offending}"
    assert tier1_imports, "security_authorization.py must import tier1.canonical -- reuse, not reinvent"


def test_never_calls_a_mutating_or_io_shaped_method():
    tree = _tree(MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_authorization.py calls mutating/IO method(s): {offending}"


def test_never_calls_sqlite3_connect_or_open_directly():
    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_recovery_contract_or_confirmation_family_symbols():
    tree = _tree(MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_authorization.py references forbidden symbol(s): {offending}"


def test_never_defines_an_execute_or_apply_or_runtime_validity_method():
    tree = _tree(MODULE_PATH)
    method_names = {node.name for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)}
    forbidden = {"execute", "apply", "is_authorized_for_runtime", "verify", "consume"}
    offending = method_names & forbidden
    assert not offending, f"security_authorization.py defines a forbidden bearer-capability-shaped method: {offending}"


def test_public_surface_is_exactly_the_reviewed_authorization_api():
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


def test_only_imports_security_plan_family_and_tier1_canonical_within_the_package():
    tree = _tree(MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_plan", "security_plan_digest", "tier1.canonical"}


def test_no_production_module_imports_security_authorization():
    """No MCP tool, `security_cli.py`, or any other production
    request-handling module ever imports this module -- signing
    construction happens only on the signing/operator side, never inside
    the MCP server's own process (module docstring "CLI boundary").

    `security_authorization_verifier.py` is the one reviewed exception
    (ADR-022 Phase D, 2026-08-11): a pure, read-only verifier that reads
    `PlanAuthorization`'s own already-signed fields -- never signs,
    never touches key material, never wired into any request-handling
    path itself either (see
    `tests/test_security_authorization_verifier_isolation.py`'s own
    no-production-importer proof)."""

    _ALLOWED_IMPORTERS = {"security_authorization_verifier.py"}
    importers = []
    for path in PRODUCTION_ROOT.rglob("*.py"):
        if path == MODULE_PATH or path.name in _ALLOWED_IMPORTERS:
            continue
        tree = _tree(path)
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.level and (node.module or "") == "security_authorization":
                importers.append(path.relative_to(ROOT).as_posix())
    assert importers == []
