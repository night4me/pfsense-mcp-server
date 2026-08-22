"""ADR-019 Endpoint Catalogue isolation and no-regression checks -- same
discipline as tests/guidance/test_evidence_isolation.py: no production
bootstrap import, no write transport/client import, no network/cache
module, no MCP registration, no new endpoint/capability, public contract
remains 42 READ / 0 WRITE, no regression in `Endpoints`/`Capability`/
`WriteEndpoints`.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
API_SURFACE_PACKAGE = ROOT / "src/pfsense_mcp/api_surface"

FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.guidance",
    "pfsense_mcp.endpoints",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.capabilities",
    "pfsense_mcp.tools",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.pfsense_client",
    "pfsense_mcp.transport",
}

FORBIDDEN_NETWORK_MODULES = {"socket", "requests", "httpx", "urllib.request"}
FORBIDDEN_CACHE_MODULES = {"sqlite3", "redis", "memcache", "shelve", "dbm"}


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
    return modules


def _tree(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _api_surface_files() -> list[Path]:
    return sorted(API_SURFACE_PACKAGE.glob("*.py"))


def test_api_surface_has_no_safety_authority_or_production_client_import() -> None:
    for path in _api_surface_files():
        imported = _imported_modules(_tree(path))
        offenders = {
            m for m in imported if any(m == root or m.startswith(f"{root}.") for root in FORBIDDEN_IMPORT_ROOTS)
        }
        assert offenders == set(), f"{path.name} imports forbidden module(s): {offenders}"


def test_api_surface_imports_no_network_module() -> None:
    for path in _api_surface_files():
        imported = _imported_modules(_tree(path))
        offenders = imported & FORBIDDEN_NETWORK_MODULES
        assert offenders == set(), f"{path.name} imports network module(s): {offenders}"


def test_api_surface_imports_no_cache_or_database_module() -> None:
    for path in _api_surface_files():
        imported = _imported_modules(_tree(path))
        offenders = imported & FORBIDDEN_CACHE_MODULES
        assert offenders == set(), f"{path.name} imports cache/database module(s): {offenders}"


def test_api_surface_has_no_mcp_registration_call() -> None:
    for path in _api_surface_files():
        source = path.read_text(encoding="utf-8")
        assert "mcp.tool(" not in source
        assert "FastMCP" not in source
        assert "@mcp." not in source
        assert "register_all" not in source


def test_endpoints_and_capabilities_and_registry_do_not_import_api_surface() -> None:
    """The other direction of isolation: production's existing registries
    must not import the catalogue package either."""
    production = ROOT / "src/pfsense_mcp"
    targets = [
        production / "endpoints.py",
        production / "write_endpoints.py",
        production / "capabilities.py",
        production / "tools" / "registry.py",
    ]
    offenders: list[str] = []
    for path in targets:
        imported = _imported_modules(_tree(path))
        if any(m == "pfsense_mcp.api_surface" or m.startswith("pfsense_mcp.api_surface.") for m in imported):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_api_surface_package_is_not_imported_by_production() -> None:
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "api_surface" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(m == "pfsense_mcp.api_surface" or m.startswith("pfsense_mcp.api_surface.") for m in imported):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_importing_api_surface_does_not_activate_tier1() -> None:
    """Only tier1 is asserted absent here -- unlike tier1,
    `pfsense_mcp.tools`/`pfsense_mcp.tools.registry` are legitimately
    imported by many other tests earlier in a full-suite run, so
    asserting their absence from `sys.modules` at this point would be
    order-dependent and would test the wrong thing (the exact class of
    false-premise bug this project's `test_appliance_identity_isolation.py`
    already caught once). Whether api_surface is *itself* ever imported
    by `pfsense_mcp.tools`/`ToolRegistry` is instead verified statically,
    order-independently, by
    test_endpoints_and_capabilities_and_registry_do_not_import_api_surface
    above."""
    for name in list(sys.modules):
        if name == "pfsense_mcp.tier1" or name.startswith("pfsense_mcp.tier1."):
            del sys.modules[name]

    from pfsense_mcp.api_surface.catalogue import EndpointCatalogue, EndpointCatalogueState

    EndpointCatalogue(schema_version=1)
    list(EndpointCatalogueState)

    assert "pfsense_mcp.tier1" not in sys.modules


def test_using_api_surface_does_not_change_write_state() -> None:
    from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
    from pfsense_mcp.profiles import EngineerProfile
    from pfsense_mcp.write_endpoints import WriteEndpoints

    write_capabilities = [c for c in Capability if c.name.endswith("_WRITE")]
    assert all(c not in SUPPORTED_CAPABILITIES_THIS_BUILD for c in write_capabilities)
    assert EngineerProfile.capabilities == frozenset()
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]  # W3 Slice 4's accepted entry


def test_production_bootstrap_never_imports_api_surface() -> None:
    """Import the real bootstrap entry point, then check sys.modules
    directly -- the only way to test what production actually does,
    rather than what an inspection script's own imports happen to load
    (a false-positive pattern this project caught once already, see
    tests/guidance/test_appliance_identity_isolation.py's own history)."""
    for name in list(sys.modules):
        if name.startswith("pfsense_mcp.api_surface"):
            del sys.modules[name]

    import pfsense_mcp.application  # noqa: F401 -- imported for its sys.modules side effect, not used directly

    offenders = [m for m in sys.modules if m.startswith("pfsense_mcp.api_surface")]
    assert offenders == []


def test_public_contract_remains_85_read_0_write_after_api_surface() -> None:
    import asyncio

    from mcp.server.fastmcp import FastMCP

    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.pfsense_client import PfSenseClient
    from pfsense_mcp.profiles import AuditorProfile
    from pfsense_mcp.rest_api_client import RestApiClient
    from pfsense_mcp.tools.registry import ToolRegistry
    from pfsense_mcp.transport.mock import MockTransport

    transport = MockTransport()
    client = PfSenseClient(RestApiClient(transport, identity="test", api_version=ApiVersion.V2))
    mcp = FastMCP("api-surface-regression-check")
    ToolRegistry(mcp, client, "test", AuditorProfile.capabilities, profile_name="auditor").register_all()
    tools = asyncio.run(mcp.list_tools())

    read_tools = [t for t in tools if t.annotations.readOnlyHint]
    write_tools = [t for t in tools if not t.annotations.readOnlyHint]
    assert len(tools) == 85
    assert len(read_tools) == 85
    assert len(write_tools) == 0


def test_endpoint_info_verified_semantics_unchanged() -> None:
    """EndpointInfo.verified is not redefined or overloaded by this
    slice -- re-confirmed directly, not assumed."""
    from pfsense_mcp.endpoints import EndpointInfo

    assert "verified" in EndpointInfo.__dataclass_fields__
    assert EndpointInfo.__dataclass_fields__["verified"].type == "bool"
