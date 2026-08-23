"""Structural (AST) tests for `pfsense_mcp.security_setup_plan` --
`pfsense-mcp-security setup` Slice 1's non-mutating discovery/plan
composition. Proves, by direct inspection of the actual shipped source,
that this module:

  - never imports `pfsense_mcp.tier1` (any submodule);
  - never imports the admin-composition/bootstrap/recovery stack, a raw
    transport/HTTP library, or `pfsense_mcp.tier1`/`pfsense_mcp.
    write_api_client`/`pfsense_mcp.pfsense_client`/`pfsense_mcp.
    rest_api_client`;
  - never calls a mutating-shaped HTTP method name;
  - has exactly the reviewed public surface;
  - correctly reaches `security_discovery`, `security_plan`, and
    `security_privileges` (positive proof of the intended composition,
    not just an absence proof);
  - `security_cli.py` never imports `security_privileges` directly
    (mirrors `tests/test_security_privileges_isolation.py`'s own
    `test_security_privileges_not_yet_wired_into_security_cli()` --
    this test proves the *reason* that one still passes: reachability
    is indirect, via this bridge module, exactly as that test's own
    docstring invites)."""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_setup_plan.py"
CLI_MODULE_PATH = ROOT / "src/pfsense_mcp/security_cli.py"

_FORBIDDEN_IMPORT_ROOTS = {
    "tier1",
    "pfsense_mcp.tier1",
    "security_admin_composition",
    "security_bootstrap_engine",
    "security_bootstrap_client",
    "security_bootstrap_recovery",
    "security_bootstrap_orchestration",
    "security_recovery_confirmation",
    "security_recovery_orchestration",
    "security_operation_journal",
    "security_operation_lock",
    "security_auth_transition",
    "pfsense_mcp.transport",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.rest_api_client",
    "httpx",
    "requests",
    "socket",
    "urllib",
}

_FORBIDDEN_MUTATING_CALLS = {
    "post",
    "patch",
    "put",
    "delete",
    "connect",
    "commit",
    "write_bytes",
    "write_text",
    "advance",
    "provision_service_account",
    "revoke_failed_bootstrap_api_key",
    "delete_dedicated_recovery_user",
}

_EXPECTED_PUBLIC_SURFACE = {
    "SETUP_PLAN_SCHEMA_VERSION",
    "INTENDED_SERVICE_ACCOUNT_IDENTITY",
    "TargetDescriptor",
    "PrivilegePlan",
    "VersionEvidence",
    "SetupPlan",
    "generate_setup_plan",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> set[str]:
    tree = _tree(path)
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            modules.add(module)
            if node.level:
                modules.add(f"{'.' * node.level}{module}")
    return modules


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_never_imports_a_forbidden_module():
    imports = _imports(MODULE_PATH)
    offending = {
        found
        for found in imports
        for forbidden in _FORBIDDEN_IMPORT_ROOTS
        if found == forbidden or found.startswith(f"{forbidden}.") or found.lstrip(".") == forbidden
    }
    assert not offending, f"security_setup_plan.py imports forbidden module(s): {offending}"


def test_never_calls_a_mutating_or_provisioning_shaped_method():
    tree = _tree(MODULE_PATH)
    called_attributes = {
        node.func.attr for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
    } | {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
    offending = called_attributes & _FORBIDDEN_MUTATING_CALLS
    assert not offending, f"security_setup_plan.py calls mutating/provisioning method(s): {offending}"


def test_never_calls_open_directly():
    tree = _tree(MODULE_PATH)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert "open" not in called_names


def test_public_surface_is_exactly_the_reviewed_api():
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


def _relative_imports(path: Path) -> set[str]:
    return {node.module or "" for node in ast.walk(_tree(path)) if isinstance(node, ast.ImportFrom) and node.level}


def test_correctly_reaches_security_discovery_security_plan_and_security_privileges():
    assert _relative_imports(MODULE_PATH) == {"security_discovery", "security_plan", "security_privileges"}


def test_security_cli_imports_security_setup_plan():
    assert "security_setup_plan" in _relative_imports(CLI_MODULE_PATH)


def test_security_cli_never_imports_security_privileges_directly():
    """`security_cli.py` reaches `security_privileges` only indirectly,
    through this bridge module -- mirrors
    `tests/test_security_privileges_isolation.py::test_security_privileges_not_yet_wired_into_security_cli()`,
    which asserts on the literal absence of the substring
    "security_privileges" from `security_cli.py`'s source text. That
    test continues to pass unmodified; this test independently proves
    *why* it is still correct to do so now that `setup` exists."""

    assert "security_privileges" not in _relative_imports(CLI_MODULE_PATH)
