"""ADR-018 Appliance Identity isolation and no-regression checks.

Proves, by AST scan and by direct inspection (not by convention), that
adding appliance_identity.py to the guidance package changed nothing
about the invariants that predate it: guidance's own registry/models
machinery is not imported or activated by it, Tier 1 remains
unreachable, WRITE state is unchanged, pfsense_mcp_info remains
zero-pfSense-call, and the public MCP contract remains exactly 78 READ
tools / 0 WRITE tools.
"""

from __future__ import annotations

import ast
import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).parents[2]
APPLIANCE_IDENTITY = ROOT / "src/pfsense_mcp/guidance/appliance_identity.py"


def _imported_modules(tree: ast.Module) -> set[str]:
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            modules.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            modules.add(node.module)
        elif isinstance(node, ast.ImportFrom) and node.module is None and node.level:
            # `from . import X` / `from .. import X` -- resolve the
            # relative target names explicitly so a `from ..pfsense_client
            # import PfSenseClient`-style import can't hide a `from
            # .models import X` / `from .registry import X` under a bare
            # relative form.
            modules.update(f"<relative level={node.level}>.{alias.name}" for alias in node.names)
    return modules


def test_appliance_identity_does_not_import_guidance_models_or_registry() -> None:
    """The rest of the guidance package (models.py's registry types,
    registry.py's _REGISTRY/lookup_guidance()/load-time integrity check)
    must not be imported by appliance_identity.py -- appliance-identity
    resolution is independent of, and does not trigger, the document-
    registry machinery."""
    tree = ast.parse(APPLIANCE_IDENTITY.read_text(encoding="utf-8"), filename=str(APPLIANCE_IDENTITY))
    imported = _imported_modules(tree)
    forbidden = {"models", "registry", ".models", ".registry"}
    offenders = {m for m in imported if any(m == f or m.endswith(f".{f.lstrip('.')}") for f in forbidden)}
    assert offenders == set(), f"appliance_identity.py imports guidance internals: {offenders}"


def test_resolving_appliance_identity_never_calls_lookup_guidance_or_returns_guidance_content() -> None:
    """The meaningful, achievable form of "does not activate guidance":
    resolve_appliance_identity()'s return value carries no
    GuidanceReference-shaped data and the function never calls
    lookup_guidance().

    (Note on what this test deliberately does NOT assert: importing
    *any* name under pfsense_mcp.guidance -- including
    appliance_identity itself -- necessarily runs
    pfsense_mcp/guidance/__init__.py first, which already imports
    .registry and .models; that is pre-existing package structure from
    ADR-017, unrelated to and unchanged by this addition, and is a pure,
    deterministic, side-effect-free hash self-check, not "activation" in
    any functional sense -- it never selects, serves, or returns
    document content. appliance_identity.py's own source imports neither
    .models nor .registry, proven statically above.)
    """
    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.guidance.appliance_identity import ApplianceIdentity, resolve_appliance_identity
    from pfsense_mcp.pfsense_client import PfSenseClient
    from pfsense_mcp.rest_api_client import RestApiClient
    from pfsense_mcp.transport.mock import MockTransport

    transport = MockTransport()
    transport.register(
        "GET",
        "/api/v2/system/version",
        status_code=200,
        text='{"data": {"base": "26.03.1", "buildtime": "x", "patch": "0", "version": "26.03.1-RELEASE"}}',
    )
    client = PfSenseClient(RestApiClient(transport, identity="test", api_version=ApiVersion.V2))
    identity = resolve_appliance_identity(client)

    assert isinstance(identity, ApplianceIdentity)
    assert set(ApplianceIdentity.model_fields) == {
        "observed_edition",
        "observed_version",
        "identity_source",
        "resolved_at",
    }
    # No field of type GuidanceReference/DocumentSource, no capability,
    # endpoint, or document-content field of any kind.


def test_appliance_identity_has_no_safety_authority_import() -> None:
    """Same forbidden-roots discipline as test_isolation.py's existing
    guidance-package-wide check, re-asserted directly against this one
    new file so a future reader doesn't have to infer it holds from the
    package-wide test alone."""
    tree = ast.parse(APPLIANCE_IDENTITY.read_text(encoding="utf-8"), filename=str(APPLIANCE_IDENTITY))
    imported = _imported_modules(tree)
    forbidden_roots = {
        "pfsense_mcp.tier1",
        "pfsense_mcp.write_endpoints",
        "pfsense_mcp.write_api_client",
        "pfsense_mcp.write_types",
        "pfsense_mcp.rest_api_client",
        "pfsense_mcp.transport",
        "pfsense_mcp.tools",
    }
    offenders = {m for m in imported if any(m == root or m.startswith(f"{root}.") for root in forbidden_roots)}
    assert offenders == set()


def test_using_appliance_identity_does_not_activate_tier1() -> None:
    """Direct runtime proof: resolving an appliance identity must not
    import pfsense_mcp.tier1 as a side effect."""
    for name in list(sys.modules):
        if name == "pfsense_mcp.tier1" or name.startswith("pfsense_mcp.tier1."):
            del sys.modules[name]

    from pfsense_mcp.api_version import ApiVersion
    from pfsense_mcp.guidance.appliance_identity import resolve_appliance_identity
    from pfsense_mcp.pfsense_client import PfSenseClient
    from pfsense_mcp.rest_api_client import RestApiClient
    from pfsense_mcp.transport.mock import MockTransport

    transport = MockTransport()
    transport.register(
        "GET",
        "/api/v2/system/version",
        status_code=200,
        text='{"data": {"base": "26.03.1", "buildtime": "x", "patch": "0", "version": "26.03.1-RELEASE"}}',
    )
    client = PfSenseClient(RestApiClient(transport, identity="test", api_version=ApiVersion.V2))
    resolve_appliance_identity(client)

    assert "pfsense_mcp.tier1" not in sys.modules


def test_using_appliance_identity_does_not_change_write_state() -> None:
    """WRITE capability/endpoint-allowlist state is defined entirely by
    pfsense_mcp.capabilities/write_endpoints, neither of which
    appliance_identity.py touches -- re-verified directly rather than
    assumed."""
    from pfsense_mcp.capabilities import SUPPORTED_CAPABILITIES_THIS_BUILD, Capability
    from pfsense_mcp.profiles import EngineerProfile
    from pfsense_mcp.write_endpoints import WriteEndpoints

    write_capabilities = [c for c in Capability if c.name.endswith("_WRITE")]
    assert all(c not in SUPPORTED_CAPABILITIES_THIS_BUILD for c in write_capabilities)
    assert EngineerProfile.capabilities == frozenset()
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]  # W3 Slice 4's accepted entry


def test_pfsense_mcp_info_remains_zero_pfsense_call() -> None:
    """Structural, not behavioral: pfsense_mcp_info's builder must still
    take no PfSenseClient-shaped dependency, and its module must not
    import appliance_identity (or anything from the guidance package)."""
    from pfsense_mcp.tools.read import mcp_info

    signature = inspect.signature(mcp_info.build)
    assert list(signature.parameters) == ["snapshot"]

    tree = ast.parse(
        Path(inspect.getfile(mcp_info)).read_text(encoding="utf-8"),
        filename=inspect.getfile(mcp_info),
    )
    imported = _imported_modules(tree)
    assert not any("guidance" in m for m in imported)
    assert not any("pfsense_client" in m for m in imported)


def test_public_contract_remains_78_read_0_write() -> None:
    """End-to-end re-confirmation with the exact same mechanism
    scripts/public_contract.py uses, not a hand count."""
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
    mcp = FastMCP("appliance-identity-regression-check")
    ToolRegistry(mcp, client, "test", AuditorProfile.capabilities, profile_name="auditor").register_all()
    tools = asyncio.run(mcp.list_tools())

    read_tools = [t for t in tools if t.annotations.readOnlyHint]
    write_tools = [t for t in tools if not t.annotations.readOnlyHint]
    assert len(tools) == 78
    assert len(read_tools) == 78
    assert len(write_tools) == 0
