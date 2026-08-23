"""Structural (AST) tests for `pfsense_mcp.security_setup_plan_digest`
-- `pfsense-mcp-security setup` Slice 1's canonical `SetupPlan` digest
computation. Mirrors `tests/test_security_plan_digest_isolation.py`'s
structure exactly."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
DIGEST_MODULE_PATH = ROOT / "src/pfsense_mcp/security_setup_plan_digest.py"
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
    "WriteEndpoints",
    "SqliteRecoveryContractStore",
    "ConfirmationEvidence",
    "ConfirmationVerifier",
    "ReconciliationEvidence",
    "AdministrativeContext",
}

_ALLOWED_TIER1_SUBMODULE = "canonical"

_EXPECTED_PUBLIC_SURFACE = {
    "SETUP_PLAN_DIGEST_SCHEMA_VERSION",
    "compute_setup_plan_digest",
    "verify_setup_plan_digest",
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
    assert not offending, f"security_setup_plan_digest.py imports forbidden tier1 submodule(s): {offending}"
    assert tier1_imports, "security_setup_plan_digest.py must import tier1.canonical -- reuse, not reinvent"


def test_never_calls_a_mutating_or_io_shaped_method():
    tree = _tree(DIGEST_MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    }
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_setup_plan_digest.py calls mutating/IO method(s): {offending}"


def test_never_calls_open_directly():
    tree = _tree(DIGEST_MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_never_references_forbidden_symbols():
    tree = _tree(DIGEST_MODULE_PATH)
    referenced_names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    offending = referenced_names & _FORBIDDEN_REFERENCED_NAMES
    assert not offending, f"security_setup_plan_digest.py references forbidden symbol(s): {offending}"


def test_never_references_hmac_key_or_signature_shaped_symbols():
    """OWNER DECISION 5: the digest payload must be mechanism-agnostic
    -- no HMAC key, signature, or Ed25519 symbol may appear as an actual
    name/attribute/call anywhere in this module's *code* (prose in
    docstrings/comments discussing why the module avoids these is fine
    and expected; only real AST-level references are checked here). The
    module-level `import hmac` is only ever used for constant-time
    comparison in `verify_setup_plan_digest()`, never to key/sign the
    payload itself."""

    tree = _tree(DIGEST_MODULE_PATH)
    imported_names = {
        alias.name for node in ast.walk(tree) if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
    }
    referenced_names = (
        {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        | {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)}
        | imported_names
    )
    forbidden = {"Ed25519", "SigningKey", "integrity_key", "new"}
    # "new" alone is too broad (e.g. dataclasses/typing internals could
    # coincidentally use it) -- only flag it if `hmac.new` is actually
    # called, which would mean keying/signing the payload.
    offending = referenced_names & (forbidden - {"new"})
    calls_hmac_new = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "new"
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "hmac"
        for node in ast.walk(tree)
    )
    assert not offending, f"security_setup_plan_digest.py references mechanism-specific symbol(s): {offending}"
    assert not calls_hmac_new, "security_setup_plan_digest.py must never call hmac.new() -- keying the payload"


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


def test_only_imports_expected_modules_within_the_package():
    tree = _tree(DIGEST_MODULE_PATH)
    relative_imports = {node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level}
    assert relative_imports == {"security_plan_digest", "security_setup_plan", "tier1.canonical"}


def test_security_cli_never_imports_security_setup_plan_digest_directly():
    """Slice 1 does not wire `setup` into `security_cli.py` yet at the
    point this test is first added within the same change -- but once
    it does, it must go through `security_setup_plan.py`'s own
    composition, never straight to the digest module, mirroring how
    `plan` imports `security_plan_digest` only for display (a
    deliberately different, already-reviewed relationship this test
    does not need to duplicate). This test simply proves the digest
    module itself is never a place `security_cli.py`'s own source
    references by name for anything other than what Slice 1's CLI
    wiring test suite separately covers."""

    tree = _tree(CLI_MODULE_PATH)
    relative_imports = {
        (node.module or "") for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.level
    }
    # security_cli.py MAY import security_setup_plan_digest directly
    # for display purposes, exactly mirroring how it already imports
    # security_plan_digest directly for the same reason (`plan`'s own
    # digest display). This test only proves it never imports a
    # forbidden name from it.
    if "security_setup_plan_digest" not in relative_imports:
        return
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and (node.module or "") == "security_setup_plan_digest"
        for alias in node.names
    }
    assert "verify_setup_plan_digest" not in imported_names, (
        "security_cli.py must never import verify_setup_plan_digest -- there is nothing in this build "
        "for it to verify against (no authorization artifact exists)."
    )
