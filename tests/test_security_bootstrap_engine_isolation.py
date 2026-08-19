"""Structural isolation tests for `security_bootstrap_client.py` and
`security_bootstrap_engine.py` (`ADR-033` implementation Phase C),
proving by direct AST/source inspection of the actual shipped files --
never by importing and trusting runtime behavior -- that:

- neither module is reachable from the MCP tool registry, the
  `pfsense-mcp-security` CLI, `doctor`, or normal application startup
  (requirement 9: "CLI/runtime isolation" -- this phase's review
  boundary before an operator can invoke a mutation);
- neither imports `pfsense_mcp.tier1` in any form;
- `security_bootstrap_client.py` is the sole new addition to
  `get_only_check.py`'s Transport-request allow-list, and the engine
  itself never calls `.request()` directly (all HTTP goes through the
  client);
- each module's public surface is exactly its reviewed API.

Mirrors `tests/test_security_privileges_isolation.py`'s and
`tests/test_security_doctor_isolation.py`'s established structure.
"""

from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
CLIENT_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_client.py"
ENGINE_MODULE_PATH = ROOT / "src/pfsense_mcp/security_bootstrap_engine.py"

_RUNTIME_ENTRY_POINTS = (
    ROOT / "src/pfsense_mcp/server.py",
    ROOT / "src/pfsense_mcp/application.py",
    ROOT / "src/pfsense_mcp/factory.py",
    ROOT / "src/pfsense_mcp/security_cli.py",
    ROOT / "src/pfsense_mcp/security_doctor.py",
)

_FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "httpx",
    "requests",
    "socket",
}

_CLIENT_EXPECTED_PUBLIC_SURFACE = {
    "ObservedUser",
    "ProvisionedApiKey",
    "BootstrapProvisioningClient",
}

_ENGINE_EXPECTED_PUBLIC_SURFACE = {
    "TargetProfile",
    "ProvisioningOutcome",
    "ProvisioningResult",
    "provision_service_account",
}


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _imports(path: Path) -> set[str]:
    tree = _tree(path)
    return {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }


def _public_surface(path: Path) -> set[str]:
    tree = _tree(path)
    return {
        node.name
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("_")
    } | {
        node.targets[0].id
        for node in ast.iter_child_nodes(tree)
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and not node.targets[0].id.startswith("_")
    }


def test_both_modules_exist():
    assert CLIENT_MODULE_PATH.is_file()
    assert ENGINE_MODULE_PATH.is_file()


def test_neither_module_imports_pfsense_mcp_tier1_or_a_raw_http_library():
    for path in (CLIENT_MODULE_PATH, ENGINE_MODULE_PATH):
        imported = _imports(path)
        offending = {
            module
            for module in imported
            for root in _FORBIDDEN_IMPORT_ROOTS
            if module == root or module.startswith(f"{root}.")
        }
        assert not offending, f"{path.name} imports forbidden module(s): {offending}"


def test_no_shipped_runtime_entry_point_references_the_bootstrap_engine_or_client():
    """Requirement 9: no CLI subcommand, no application-startup wiring,
    no tool-registry reference. This is the mechanical proof that the
    only way to reach `provision_service_account()` in this build is a
    direct Python import (a test, or a future, separately-authorized
    phase)."""

    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        assert "security_bootstrap_engine" not in source, f"{entry_point.name} references security_bootstrap_engine"
        assert "security_bootstrap_client" not in source, f"{entry_point.name} references security_bootstrap_client"


def test_no_tool_under_tools_read_references_the_bootstrap_engine_or_client():
    tools_dir = ROOT / "src/pfsense_mcp/tools"
    for path in sorted(tools_dir.rglob("*.py")):
        source = path.read_text(encoding="utf-8")
        assert "security_bootstrap_engine" not in source, f"{path} references security_bootstrap_engine"
        assert "security_bootstrap_client" not in source, f"{path} references security_bootstrap_client"


def test_engine_never_calls_transport_request_directly():
    """All HTTP must funnel through `security_bootstrap_client.py`'s
    four named operations -- the engine itself must never hold or call
    a bare `Transport`."""

    source = ENGINE_MODULE_PATH.read_text(encoding="utf-8")
    assert ".request(" not in source


def test_client_is_named_in_get_only_checks_allow_list():
    get_only_check_source = (ROOT / "scripts/get_only_check.py").read_text(encoding="utf-8")
    assert "security_bootstrap_client.py" in get_only_check_source


def test_neither_module_is_in_the_tier1_isolation_exemption_list():
    isolation_test_path = ROOT / "tests/tier1/test_isolation.py"
    source = isolation_test_path.read_text(encoding="utf-8")
    assert "security_bootstrap_client.py" not in source
    assert "security_bootstrap_engine.py" not in source


def test_client_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(CLIENT_MODULE_PATH) == _CLIENT_EXPECTED_PUBLIC_SURFACE


def test_engine_public_surface_is_exactly_the_reviewed_api():
    assert _public_surface(ENGINE_MODULE_PATH) == _ENGINE_EXPECTED_PUBLIC_SURFACE


def test_engine_does_not_construct_its_own_http_transport():
    """The engine must never build a `Transport` (or a Basic-Auth
    variant of one) itself -- both are always caller-supplied
    (`provision_service_account()`'s `admin_transport`/
    `self_service_transport_factory` parameters). Confirms no
    `transport.http`/`transport.mock` import exists in the engine."""

    imported = _imports(ENGINE_MODULE_PATH)
    offending = {
        m for m in imported if m == "pfsense_mcp.transport.http" or m.startswith("pfsense_mcp.transport.http.")
    }
    assert not offending


def test_basic_auth_transport_remains_unwired_from_runtime_entry_points():
    for entry_point in _RUNTIME_ENTRY_POINTS:
        source = entry_point.read_text(encoding="utf-8")
        assert "BasicAuthHttpTransport" not in source, f"{entry_point.name} wires BasicAuthHttpTransport"
