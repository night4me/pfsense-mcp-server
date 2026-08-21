"""register_all_write() / the W3 Slice 4 three-condition activation gate
-- reuses the existing FakeMCP test double from test_tool_registry.py
rather than defining a second one.

Every non-"all three hold" combination below is constructed via targeted
monkeypatching (of `WriteEndpoints.FIREWALL_ALIAS_DESCRIPTION` presence
and `tier1_write_bridge.can_construct_write_runtime()`'s return value) --
`WriteEndpoints` itself is a fixed, non-per-test-configurable source-code
fact in this build, so isolating "endpoint absent" or "runtime absent"
requires simulating it rather than genuinely reconfiguring the
environment. `tools/registry.py` and this test file never import
`pfsense_mcp.tier1` directly -- only `pfsense_mcp.tier1_write_bridge`'s
own two exposed functions are ever touched.
"""

from __future__ import annotations

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile, WriteProtectedProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools import registry as registry_module
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport
from pfsense_mcp.write_endpoints import WriteEndpoints
from tests.test_tool_registry import FakeMCP


def _registry(capabilities, *, allowed_tools=None):
    transport = MockTransport()
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    mcp = FakeMCP()
    return (
        ToolRegistry(
            mcp,
            client,
            "api-mcp-admin",
            capabilities,
            allowed_tools=allowed_tools,
            profile_name="synthetic",
        ),
        mcp,
    )


def _write_tool_names(mcp) -> set[str]:
    return {fn.__name__ for fn in mcp.registered if fn.__name__ == "set_firewall_alias_description_v1"}


def test_register_all_write_is_a_no_op_directly():
    registry, mcp = _registry(frozenset())
    registry.register_all_write()
    assert mcp.registered == []


def test_engineer_profile_registers_zero_tools_end_to_end():
    registry, mcp = _registry(EngineerProfile.capabilities)
    registry.register_all()
    assert mcp.registered == []


def test_auditor_profile_registers_only_read_tools_no_write_tools():
    registry, mcp = _registry(AuditorProfile.capabilities)
    registry.register_all()
    registered_names = {fn.__name__ for fn in mcp.registered}
    assert registered_names
    assert all(name.startswith("pfsense_get_") or name == "pfsense_mcp_info" for name in registered_names)
    assert _write_tool_names(mcp) == set()


# ---------------------------------------------------------------------------
# Default / unconfigured
# ---------------------------------------------------------------------------


def test_default_auditor_cannot_reach_alias_write_even_with_endpoint_and_runtime_available(monkeypatch):
    """The default profile itself is condition A's own gate -- proves
    condition A failing alone is sufficient to keep the tool absent,
    with B and C both artificially forced true."""

    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(AuditorProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


# ---------------------------------------------------------------------------
# Single-condition-true combinations (the other two forced false)
# ---------------------------------------------------------------------------


def test_profile_only_does_not_register(monkeypatch):
    """A: True. B: False (endpoint absent). C: False (unconfigured, the
    real, unmocked default in this test environment)."""

    monkeypatch.delattr(WriteEndpoints, "FIREWALL_ALIAS_DESCRIPTION", raising=True)
    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_endpoint_only_does_not_register(monkeypatch):
    """A: False. B: True (real, unmocked default). C: False (forced)."""

    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: False)
    registry, mcp = _registry(AuditorProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_runtime_only_does_not_register(monkeypatch):
    """A: False. B: False (forced absent). C: True (forced)."""

    monkeypatch.delattr(WriteEndpoints, "FIREWALL_ALIAS_DESCRIPTION", raising=True)
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(AuditorProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


# ---------------------------------------------------------------------------
# Two-of-three combinations (every pair)
# ---------------------------------------------------------------------------


def test_profile_and_endpoint_without_runtime_does_not_register(monkeypatch):
    """A: True. B: True (real default). C: False (real, unmocked default
    -- unconfigured in this test environment)."""

    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_profile_and_runtime_without_endpoint_does_not_register(monkeypatch):
    """A: True. B: False (forced absent). C: True (forced)."""

    monkeypatch.delattr(WriteEndpoints, "FIREWALL_ALIAS_DESCRIPTION", raising=True)
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_endpoint_and_runtime_without_profile_does_not_register(monkeypatch):
    """A: False. B: True (real default). C: True (forced)."""

    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(AuditorProfile.capabilities)
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


# ---------------------------------------------------------------------------
# All three
# ---------------------------------------------------------------------------


def test_all_three_conditions_register_exactly_one_write_tool(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all_write()

    assert _write_tool_names(mcp) == {"set_firewall_alias_description_v1"}
    assert len(mcp.registered) == 1
    assert registry._registered_write_names == ["set_firewall_alias_description_v1"]


def test_all_three_conditions_via_full_register_all_still_exactly_70_read_plus_one_write(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all()

    read_names = {fn.__name__ for fn in mcp.registered if fn.__name__ != "set_firewall_alias_description_v1"}
    assert len(read_names) == 70
    assert _write_tool_names(mcp) == {"set_firewall_alias_description_v1"}
    assert len(mcp.registered) == 71


def test_all_three_conditions_produce_no_additional_write_capability_or_tool(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, _mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all()

    assert len(registry._registered_write_names) == 1
    assert WriteEndpoints.active_entries() == ["FIREWALL_ALIAS_DESCRIPTION"]


# ---------------------------------------------------------------------------
# PFSENSE_ALLOWED_TOOLS: may suppress, can never grant
# ---------------------------------------------------------------------------


def test_allowed_tools_can_suppress_the_write_tool_even_with_all_three_conditions_true(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(
        WriteProtectedProfile.capabilities, allowed_tools=frozenset({"pfsense_get_system_status"})
    )
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_allowed_tools_naming_the_write_tool_does_not_grant_it_when_the_gate_is_false(monkeypatch):
    registry, mcp = _registry(
        AuditorProfile.capabilities, allowed_tools=frozenset({"set_firewall_alias_description_v1"})
    )
    registry.register_all_write()
    assert _write_tool_names(mcp) == set()


def test_allowed_tools_naming_the_write_tool_permits_it_when_the_gate_is_true(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(
        WriteProtectedProfile.capabilities, allowed_tools=frozenset({"set_firewall_alias_description_v1"})
    )
    registry.register_all_write()
    assert _write_tool_names(mcp) == {"set_firewall_alias_description_v1"}


def test_allowed_tools_accepts_the_write_tool_name_without_configuration_error():
    # Before W3 Slice 4, this would raise ConfigurationError -- the write
    # tool name was not in KNOWN_READ_TOOL_NAMES and there was no
    # KNOWN_WRITE_TOOL_NAMES at all.
    registry, _mcp = _registry(
        AuditorProfile.capabilities, allowed_tools=frozenset({"set_firewall_alias_description_v1"})
    )
    assert registry is not None


# ---------------------------------------------------------------------------
# Tool annotations
# ---------------------------------------------------------------------------


def test_write_tool_annotations_mark_it_non_read_only(monkeypatch):
    monkeypatch.setattr(registry_module.tier1_write_bridge, "can_construct_write_runtime", lambda: True)
    registry, mcp = _registry(WriteProtectedProfile.capabilities)
    registry.register_all_write()

    assert len(mcp.annotations) == 1
    annotations = mcp.annotations[0]
    assert annotations.readOnlyHint is False
    assert annotations.destructiveHint is False
    assert annotations.idempotentHint is True
