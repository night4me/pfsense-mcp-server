"""ADR-018 Step 3 isolation and no-regression checks -- same discipline
as test_evidence_isolation.py/test_appliance_identity_isolation.py,
extended to composition.py, plus a direct re-confirmation of TB-G4's
structural rule: GuidanceEvidence must never be read by
tier1.state_machine or any confirmation-digest computation.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
GUIDANCE_PACKAGE = ROOT / "src/pfsense_mcp/guidance"
COMPOSITION = GUIDANCE_PACKAGE / "composition.py"
TIER1_PACKAGE = ROOT / "src/pfsense_mcp/tier1"

FORBIDDEN_IMPORT_ROOTS = {
    "pfsense_mcp.tier1",
    "pfsense_mcp.write_endpoints",
    "pfsense_mcp.write_api_client",
    "pfsense_mcp.write_types",
    "pfsense_mcp.rest_api_client",
    "pfsense_mcp.transport",
    "pfsense_mcp.tools",
    "pfsense_mcp.endpoints",
    "pfsense_mcp.capabilities",
    "pfsense_mcp.api_surface",
    "pfsense_mcp.pfsense_client",
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


def test_composition_has_no_safety_authority_or_production_client_import() -> None:
    imported = _imported_modules(_tree(COMPOSITION))
    offenders = {m for m in imported if any(m == root or m.startswith(f"{root}.") for root in FORBIDDEN_IMPORT_ROOTS)}
    assert offenders == set(), f"composition.py imports forbidden module(s): {offenders}"


def test_composition_imports_no_network_module() -> None:
    imported = _imported_modules(_tree(COMPOSITION))
    offenders = imported & FORBIDDEN_NETWORK_MODULES
    assert offenders == set(), f"composition.py imports network module(s): {offenders}"


def test_composition_has_no_mcp_registration_call() -> None:
    source = COMPOSITION.read_text(encoding="utf-8")
    assert "mcp.tool(" not in source
    assert "FastMCP" not in source
    assert "@mcp." not in source
    assert "register_all" not in source


def test_composition_module_is_not_imported_by_production() -> None:
    production = ROOT / "src/pfsense_mcp"
    offenders: list[str] = []
    for path in production.rglob("*.py"):
        if "guidance" in path.relative_to(production).parts:
            continue
        imported = _imported_modules(_tree(path))
        if any(m == "pfsense_mcp.guidance.composition" for m in imported):
            offenders.append(path.relative_to(ROOT).as_posix())
    assert offenders == []


def test_tier1_state_machine_never_reads_guidance_tb_g4() -> None:
    """Direct re-confirmation of ADR-018's structural TB-G4 pin, not
    only trusted from the ADR text: state_machine.py must never import
    anything from pfsense_mcp.guidance."""
    state_machine = TIER1_PACKAGE / "state_machine.py"
    imported = _imported_modules(_tree(state_machine))
    offenders = {m for m in imported if m == "pfsense_mcp.guidance" or m.startswith("pfsense_mcp.guidance.")}
    assert offenders == set()


def test_tier1_confirmation_digest_modules_never_read_guidance_tb_g4() -> None:
    """The other half of TB-G4's structural pin: no confirmation-digest
    computation module may import guidance either."""
    digest_modules = [
        TIER1_PACKAGE / "confirmation.py",
        TIER1_PACKAGE / "confirmation_providers.py",
        TIER1_PACKAGE / "reconciliation.py",
        TIER1_PACKAGE / "reconciliation_providers.py",
        TIER1_PACKAGE / "contract.py",
        TIER1_PACKAGE / "store.py",
    ]
    offenders: dict[str, set[str]] = {}
    for path in digest_modules:
        if not path.exists():
            continue
        imported = _imported_modules(_tree(path))
        found = {m for m in imported if m == "pfsense_mcp.guidance" or m.startswith("pfsense_mcp.guidance.")}
        if found:
            offenders[path.name] = found
    assert offenders == {}


def test_using_composition_does_not_activate_tier1() -> None:
    for name in list(sys.modules):
        if name == "pfsense_mcp.tier1" or name.startswith("pfsense_mcp.tier1."):
            del sys.modules[name]

    from pfsense_mcp.guidance.appliance_identity import ApplianceIdentity, ObservedEdition
    from pfsense_mcp.guidance.composition import compose_guidance_evidence

    identity = ApplianceIdentity(
        observed_edition=ObservedEdition.UNKNOWN,
        observed_version=None,
        identity_source="SystemVersion.base (pfsense_get_system_version)",
        resolved_at="2026-08-09T00:00:00+00:00",
    )
    compose_guidance_evidence(capability="ALIAS_READ", identity=identity, guidance=())

    assert "pfsense_mcp.tier1" not in sys.modules


def test_using_composition_does_not_change_write_state() -> None:
    from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
    from pfsense_mcp.profiles import EngineerProfile
    from pfsense_mcp.write_endpoints import WriteEndpoints

    write_capabilities = [c for c in Capability if c.name.endswith("_WRITE")]
    assert all(c not in SUPPORTED_CAPABILITIES_THIS_BUILD for c in write_capabilities)
    assert EngineerProfile.capabilities == frozenset()
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]  # W3 Slice 4's accepted entry


def test_pfsense_mcp_info_remains_zero_pfsense_call_after_step_3() -> None:
    from pfsense_mcp.tools.read import mcp_info

    signature = inspect.signature(mcp_info.build)
    assert list(signature.parameters) == ["snapshot"]

    tree = _tree(Path(inspect.getfile(mcp_info)))
    imported = _imported_modules(tree)
    assert not any("guidance" in m for m in imported)
    assert not any("pfsense_client" in m for m in imported)


def test_public_contract_remains_46_read_0_write_after_step_3() -> None:
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
    mcp = FastMCP("guidance-step3-regression-check")
    ToolRegistry(mcp, client, "test", AuditorProfile.capabilities, profile_name="auditor").register_all()
    tools = asyncio.run(mcp.list_tools())

    read_tools = [t for t in tools if t.annotations.readOnlyHint]
    write_tools = [t for t in tools if not t.annotations.readOnlyHint]
    assert len(tools) == 46
    assert len(read_tools) == 46
    assert len(write_tools) == 0


def test_appliance_identity_and_evidence_types_unaffected_by_step_3() -> None:
    """No regression in Steps 1/2's own shapes, re-run directly."""
    from pfsense_mcp.guidance.appliance_identity import ObservedEdition, infer_edition_from_version_base
    from pfsense_mcp.guidance.evidence import ApplicabilityState

    assert infer_edition_from_version_base("2.7.2") is ObservedEdition.KNOWN_CE
    assert infer_edition_from_version_base("26.03.1") is ObservedEdition.KNOWN_PLUS
    assert not hasattr(ApplicabilityState, "CONFLICTING_GUIDANCE")
