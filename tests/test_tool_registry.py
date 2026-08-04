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


_INTERFACES_BODY = {"data": [{
    "id": 0, "name": "wan", "descr": "WAN", "hwif": "igb0", "macaddr": "02:00:00:aa:bb:cc",
    "mtu": "1500", "enable": True, "status": "up", "ipaddr": "198.51.100.10",
    "subnet": "255.255.255.0", "linklocal": None, "ipaddrv6": None, "subnetv6": None,
    "inerrs": 0, "outerrs": 0, "collisions": 0, "inbytes": 1000, "inbytespass": 1000,
    "outbytes": 2000, "outbytespass": 2000, "inpkts": 10, "inpktspass": 10, "outpkts": 20,
    "outpktspass": 20, "dhcplink": "up", "media": "1000baseT <full-duplex>",
    "gateway": "198.51.100.1", "gatewayv6": None,
}]}

_GATEWAYS_BODY = {"data": [{
    "id": 0, "name": "WAN_DHCP", "descr": "Interface WAN Gateway", "disabled": False,
    "ipprotocol": "inet", "interface": "wan", "gateway": "198.51.100.1",
    "monitor_disable": False, "monitor": "198.51.100.1", "action_disable": False,
    "force_down": False, "dpinger_dont_add_static_route": False, "gw_down_kill_states": "",
    "nonlocalgateway": False, "weight": 1, "data_payload": 1, "latencylow": 200,
    "latencyhigh": 500, "losslow": 10, "losshigh": 20, "interval": 500, "loss_interval": 2000,
    "time_period": 60000, "alert_interval": 1000,
}]}

_GATEWAY_STATUS_BODY = {"data": [{
    "id": 0, "name": "WAN_DHCP", "srcip": "198.51.100.10", "monitorip": "198.51.100.1",
    "delay": 12.345, "stddev": 1.2, "loss": 0.0, "status": "none", "substatus": "none",
}]}


def _client(*, with_interfaces: bool = False, with_gateways: bool = False) -> PfSenseClient:
    transport = MockTransport()
    body = {"data": {
        "platform": "Netgate pfSense Plus", "uptime": "1 Hour", "cpu_model": "x",
        "cpu_count": 1, "cpu_usage": 1.0, "mem_usage": 1, "swap_usage": 0, "disk_usage": 1,
    }}
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    if with_interfaces:
        transport.register("GET", "/api/v2/status/interfaces", status_code=200, text=json.dumps(_INTERFACES_BODY))
    if with_gateways:
        transport.register("GET", "/api/v2/routing/gateways", status_code=200, text=json.dumps(_GATEWAYS_BODY))
        transport.register(
            "GET", "/api/v2/status/gateways", status_code=200, text=json.dumps(_GATEWAY_STATUS_BODY)
        )
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


def test_registry_registers_interfaces_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_interfaces"


def test_registry_does_not_register_interfaces_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_interfaces" not in names


def test_registry_registers_both_tools_when_both_capabilities_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(
        mcp, client, "api-mcp-admin", frozenset({Capability.SYSTEM_READ, Capability.INTERFACE_READ})
    )
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {"pfsense_get_system_status", "pfsense_get_interfaces"}


def test_registered_interfaces_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_interfaces=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.INTERFACE_READ}))
    registry.register_all()
    tool_fn = mcp.registered[0]
    interfaces = tool_fn()
    assert len(interfaces) == 1
    assert interfaces[0].name == "wan"
    assert interfaces[0].macaddr is None
    assert interfaces[0].ipaddr is None
    assert interfaces[0].gateway is None


def test_registry_registers_both_gateway_tools_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {"pfsense_get_gateways", "pfsense_get_gateway_status"}


def test_registry_does_not_register_gateway_tools_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_gateways" not in names
    assert "pfsense_get_gateway_status" not in names


def test_registered_gateways_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    gateways_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_gateways")
    gateways = gateways_fn()
    assert len(gateways) == 1
    assert gateways[0].name == "WAN_DHCP"
    assert gateways[0].gateway is None
    assert gateways[0].monitor is None


def test_registered_gateway_status_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_gateways=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.GATEWAY_READ}))
    registry.register_all()
    status_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_gateway_status")
    statuses = status_fn()
    assert len(statuses) == 1
    assert statuses[0].name == "WAN_DHCP"
    assert statuses[0].srcip is None
    assert statuses[0].monitorip is None


def test_registry_registers_all_tools_when_all_capabilities_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True, with_gateways=True)
    registry = ToolRegistry(
        mcp, client, "api-mcp-admin",
        frozenset({Capability.SYSTEM_READ, Capability.INTERFACE_READ, Capability.GATEWAY_READ}),
    )
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {
        "pfsense_get_system_status", "pfsense_get_interfaces",
        "pfsense_get_gateways", "pfsense_get_gateway_status",
    }
