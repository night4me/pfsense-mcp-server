"""Structural isolation tests for `security_tier1_lab_credential_
recovery.py`, mirroring `tests/test_security_bootstrap_engine_
isolation.py`'s established pattern by direct AST/source inspection of
the actual shipped file -- never by importing and trusting runtime
behavior -- that:

- the module is reachable from no MCP tool, no `pfsense-mcp-security`
  CLI subcommand, `doctor`, or normal application startup;
- it never calls `Transport.request()` directly (all HTTP goes through
  `BootstrapProvisioningClient`, exactly like `security_bootstrap_
  engine.py`);
- it is not, and must never become, a fourth entry in `scripts/
  get_only_check.py`'s allow-list;
- it imports no `pfsense_mcp.tier1` module in any form;
- its public surface is exactly its reviewed API.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE_PATH = ROOT / "src/pfsense_mcp/security_tier1_lab_credential_recovery.py"

_RUNTIME_ENTRY_POINTS = (
    ROOT / "src/pfsense_mcp/server.py",
    ROOT / "src/pfsense_mcp/application.py",
    ROOT / "src/pfsense_mcp/factory.py",
    ROOT / "src/pfsense_mcp/security_cli.py",
    ROOT / "src/pfsense_mcp/security_doctor.py",
    ROOT / "src/pfsense_mcp/security_setup_apply.py",
)

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "httpx",
    "requests",
    "socket",
}

_EXPECTED_PUBLIC_SURFACE = {
    "TARGET_LABEL",
    "TARGET_HOSTNAME",
    "EXPECTED_USER_ID",
    "EXPECTED_USERNAME",
    "EXPECTED_USER_DESCR",
    "EXPECTED_STARTING_PRIVILEGES",
    "TEMPORARY_PRIVILEGES",
    "FINAL_PRIVILEGES",
    "RecoveryOutcome",
    "RecoveryResult",
    "recover_tier1_lab_credential",
}


def _tree() -> ast.Module:
    return ast.parse(MODULE_PATH.read_text(encoding="utf-8"), filename=str(MODULE_PATH))


def _imports() -> set[str]:
    tree = _tree()
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }


def test_module_exists():
    assert MODULE_PATH.is_file()


def test_public_surface_is_exactly_the_reviewed_api():
    tree = _tree()
    public = (
        {
            node.name
            for node in ast.iter_child_nodes(tree)
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
        }
        | {
            node.targets[0].id
            for node in ast.iter_child_nodes(tree)
            if isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and not node.targets[0].id.startswith("_")
        }
        | {
            node.target.id
            for node in ast.iter_child_nodes(tree)
            if isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and not node.target.id.startswith("_")
        }
    )
    assert public == _EXPECTED_PUBLIC_SURFACE


def test_module_never_calls_transport_request_directly():
    """All HTTP must funnel through `BootstrapProvisioningClient` --
    this module itself must never hold or call a bare `Transport`."""

    source = MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source


def test_module_is_not_in_get_only_checks_allow_list():
    """This module must never become a fourth caller of
    `Transport.request()` -- it composes `security_bootstrap_client.py`
    (already on the allow-list) instead."""

    get_only_check_source = (ROOT / "scripts/get_only_check.py").read_text(encoding="utf-8")
    assert "security_tier1_lab_credential_recovery.py" not in get_only_check_source


def test_module_does_not_import_pfsense_mcp_tier1_or_a_raw_http_library():
    imported = _imports()
    offending = {
        module
        for module in imported
        for root in _FORBIDDEN_IMPORT_ROOTS
        if module == root or module.startswith(f"{root}.")
    }
    assert not offending, f"module imports forbidden module(s): {offending}"


def test_module_imports_the_bootstrap_client_and_transaction_model():
    """The inverse of the isolation checks: this module is *expected*
    to compose `security_bootstrap_client.py` and `security_bootstrap_
    transaction.py` unmodified (that is its entire purpose) -- confirms
    this isn't accidentally isolated into uselessness."""

    imported = _imports()
    assert "security_bootstrap_client" in imported
    assert "security_bootstrap_transaction" in imported


def test_no_shipped_runtime_entry_point_references_this_module():
    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        assert "security_tier1_lab_credential_recovery" not in source, f"{entry_point.name} references it"


def test_no_tool_under_tools_references_this_module():
    tools_dir = ROOT / "src/pfsense_mcp/tools"
    for path in sorted(tools_dir.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "security_tier1_lab_credential_recovery" not in source, f"{path} references it"


def test_module_is_not_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_tier1_lab_credential_recovery.py" not in source


def test_module_does_not_register_commands_or_expose_mcp_tools():
    source = MODULE_PATH.read_text(encoding="utf-8")
    assert "@app.command" not in source
    assert "add_parser(" not in source
    assert "mcp.tool" not in source
    assert "FastMCP" not in source


def test_module_does_not_construct_its_own_http_transport():
    imported = _imports()
    offending = {
        m for m in imported if m == "pfsense_mcp.transport.http" or m.startswith("pfsense_mcp.transport.http.")
    }
    assert not offending


def test_basic_auth_transport_remains_unwired_from_runtime_entry_points():
    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        assert "BasicAuthHttpTransport" not in source, f"{entry_point.name} wires BasicAuthHttpTransport"
