"""register_all_write() registers nothing in this build, for either
profile — reuses the existing FakeMCP test double from
test_tool_registry.py rather than defining a second one."""

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.profiles import AuditorProfile, EngineerProfile
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport
from tests.test_tool_registry import FakeMCP


def _registry(capabilities):
    transport = MockTransport()
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    mcp = FakeMCP()
    return ToolRegistry(mcp, client, "api-mcp-admin", capabilities), mcp


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
