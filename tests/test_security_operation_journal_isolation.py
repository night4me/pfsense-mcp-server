from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
MODULE = ROOT / "src/pfsense_mcp/security_operation_journal.py"
RUNTIME = (
    ROOT / "src/pfsense_mcp/server.py",
    ROOT / "src/pfsense_mcp/application.py",
    ROOT / "src/pfsense_mcp/factory.py",
    ROOT / "src/pfsense_mcp/security_cli.py",
    ROOT / "src/pfsense_mcp/security_doctor.py",
)


def test_journal_has_no_network_or_mutation_authority():
    tree = ast.parse(MODULE.read_text())
    imports = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names} | {
        node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
    }
    assert not any(name.startswith(("httpx", "requests", "socket", "pfsense_mcp.transport")) for name in imports)
    source = MODULE.read_text()
    for forbidden in (
        ".request(",
        "BootstrapProvisioningClient",
        "WriteApiClient",
        "WriteEndpoints",
        "provision_service_account",
    ):
        assert forbidden not in source


def test_journal_is_unreachable_from_runtime_cli_doctor_and_tools():
    for path in RUNTIME:
        assert "security_operation_journal" not in path.read_text()
    for path in (ROOT / "src/pfsense_mcp/tools").rglob("*.py"):
        assert "security_operation_journal" not in path.read_text()


def test_existing_bootstrap_recovery_transition_remain_unwired():
    names = ("security_bootstrap_engine", "security_bootstrap_recovery", "security_auth_transition")
    for path in RUNTIME:
        source = path.read_text()
        assert all(name not in source for name in names)


def test_no_nexus_runtime_wiring_and_no_tier1_import():
    for path in (ROOT / "src/pfsense_mcp/application.py", ROOT / "src/pfsense_mcp/factory.py"):
        source = path.read_text()
        assert "nexus" not in source and "backends" not in source
    tree = ast.parse(MODULE.read_text())
    assert not any(
        isinstance(node, ast.ImportFrom) and (node.module or "").startswith("pfsense_mcp.tier1")
        for node in ast.walk(tree)
    )
