"""ADR-018 step 2 isolation and no-regression checks -- same discipline
as test_appliance_identity_isolation.py, extended to evidence.py and
applicability.py: no production bootstrap import, no Tier 1 import, no
write transport/client import, no network client, no cache/database, no
MCP registration, no new endpoint/capability, public contract remains
59 READ / 0 WRITE, and no regression in ApplianceIdentity.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDANCE_PACKAGE = ROOT / "src/pfsense_mcp/guidance"
EVIDENCE = GUIDANCE_PACKAGE / "evidence.py"
APPLICABILITY = GUIDANCE_PACKAGE / "applicability.py"

FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.write_types",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
}

FORBIDDEN_NETWORK_MODULES = {"socket", "requests", "httpx", "urllib.request"}


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


def test_evidence_and_applicability_have_no_safety_authority_import() -> None:
    for path in (EVIDENCE, APPLICABILITY):
        imported = _imported_modules(_tree(path))
        offenders = {
            m for m in imported if any(m == root or m.startswith(f"{root}.") for root in FORBIDDEN_IMPORT_ROOTS)
        }
        assert offenders == set(), f"{path.name} imports safety-authority module(s): {offenders}"


def test_evidence_and_applicability_import_no_network_module() -> None:
    for path in (EVIDENCE, APPLICABILITY):
        imported = _imported_modules(_tree(path))
        offenders = imported & FORBIDDEN_NETWORK_MODULES
        assert offenders == set(), f"{path.name} imports network module(s): {offenders}"


def test_evidence_and_applicability_import_no_cache_or_database_module() -> None:
    forbidden = {"sqlite3", "redis", "memcache", "shelve", "dbm"}
    for path in (EVIDENCE, APPLICABILITY):
        imported = _imported_modules(_tree(path))
        offenders = imported & forbidden
        assert offenders == set(), f"{path.name} imports cache/database module(s): {offenders}"


def test_applicability_module_has_no_mcp_registration_call() -> None:
    """No mcp.tool()-shaped call anywhere in applicability.py's source --
    this module registers no MCP tool, directly verified rather than
    inferred from "nothing imports FastMCP." """
    source = APPLICABILITY.read_text(encoding="utf-8")
    assert "mcp.tool(" not in source
    assert "FastMCP" not in source
    assert "@mcp." not in source


def test_evidence_package_is_not_imported_by_production_yet() -> None:
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "guidance" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(
            module in ("pfsense_mcp.guidance.evidence", "pfsense_mcp.guidance.applicability") for module in imported
        ):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_using_evidence_primitives_does_not_activate_tier1() -> None:
    for name in list(sys.modules):
        if name == "pfsense_mcp.tier1" or name.startswith("pfsense_mcp.tier1."):
            del sys.modules[name]

    from pfsense_mcp.guidance.applicability import compute_overall_state, may_prepare
    from pfsense_mcp.guidance.evidence import ApplicabilityState

    compute_overall_state([ApplicabilityState.APPLICABLE])
    may_prepare(existing_authorization=True, guidance_required=False, guidance_check_passes=False)

    assert "pfsense_mcp.tier1" not in sys.modules


def test_using_evidence_primitives_does_not_change_write_state() -> None:
    from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
    from pfsense_mcp.profiles import EngineerProfile
    from pfsense_mcp.write_endpoints import WriteEndpoints

    write_capabilities = [c for c in Capability if c.name.endswith("_WRITE")]
    assert all(c not in SUPPORTED_CAPABILITIES_THIS_BUILD for c in write_capabilities)
    assert EngineerProfile.capabilities == frozenset()
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]  # W3 Slice 4's accepted entry


def test_pfsense_mcp_info_remains_zero_pfsense_call_after_step_2() -> None:
    """Re-run of the same structural check from step 1 -- explicit
    regression coverage, not assumed to still hold."""
    from pfsense_mcp.tools.read import mcp_info

    signature = inspect.signature(mcp_info.build)
    assert list(signature.parameters) == ["snapshot"]

    tree = _tree(Path(inspect.getfile(mcp_info)))
    imported = _imported_modules(tree)
    assert not any("guidance" in m for m in imported)
    assert not any("pfsense_client" in m for m in imported)


def test_public_contract_remains_59_read_0_write_after_step_2() -> None:
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
    mcp = FastMCP("evidence-step2-regression-check")
    ToolRegistry(mcp, client, "test", AuditorProfile.capabilities, profile_name="auditor").register_all()
    tools = asyncio.run(mcp.list_tools())

    read_tools = [t for t in tools if t.annotations.readOnlyHint]
    write_tools = [t for t in tools if not t.annotations.readOnlyHint]
    assert len(tools) == 59
    assert len(read_tools) == 59
    assert len(write_tools) == 0


def test_appliance_identity_classification_unaffected_by_step_2() -> None:
    """No regression in ApplianceIdentity: same algorithm, same
    boundary results, re-run directly rather than only relying on
    test_appliance_identity.py still passing unmodified."""
    from pfsense_mcp.guidance.appliance_identity import ObservedEdition, infer_edition_from_version_base

    assert infer_edition_from_version_base("2.7.2") is ObservedEdition.KNOWN_CE
    assert infer_edition_from_version_base("26.03.1") is ObservedEdition.KNOWN_PLUS
    assert infer_edition_from_version_base("15.0") is ObservedEdition.UNKNOWN
    assert infer_edition_from_version_base("") is ObservedEdition.UNKNOWN
