import json

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.tools.registry import ToolRegistry
from pfsense_mcp.transport.mock import MockTransport


class FakeMCP:
    def __init__(self) -> None:
        self.registered = []

    def tool(self):
        def decorator(fn):
            self.registered.append(fn)
            return fn
        return decorator


def _client() -> PfSenseClient:
    transport = MockTransport()
    body = {"data": {
        "platform": "Netgate pfSense Plus", "uptime": "1 Hour", "cpu_model": "x",
        "cpu_count": 1, "cpu_usage": 1.0, "mem_usage": 1, "swap_usage": 0, "disk_usage": 1,
    }}
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client)


def test_registry_registers_system_status_tool_when_capability_present():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_system_status"


def test_registry_registers_nothing_when_no_capabilities():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset())
    registry.register_all()
    assert mcp.registered == []


def test_registered_tool_invokes_client_and_returns_status():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    tool_fn = mcp.registered[0]
    status = tool_fn()
    assert status.platform == "Netgate pfSense Plus"
    assert status.netgate_id is None
