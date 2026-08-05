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


_INTERFACES_BODY = {
    "data": [
        {
            "id": 0,
            "name": "wan",
            "descr": "WAN",
            "hwif": "igb0",
            "macaddr": "02:00:00:aa:bb:cc",
            "mtu": "1500",
            "enable": True,
            "status": "up",
            "ipaddr": "198.51.100.10",
            "subnet": "255.255.255.0",
            "linklocal": None,
            "ipaddrv6": None,
            "subnetv6": None,
            "inerrs": 0,
            "outerrs": 0,
            "collisions": 0,
            "inbytes": 1000,
            "inbytespass": 1000,
            "outbytes": 2000,
            "outbytespass": 2000,
            "inpkts": 10,
            "inpktspass": 10,
            "outpkts": 20,
            "outpktspass": 20,
            "dhcplink": "up",
            "media": "1000baseT <full-duplex>",
            "gateway": "198.51.100.1",
            "gatewayv6": None,
        }
    ]
}

_GATEWAYS_BODY = {
    "data": [
        {
            "id": 0,
            "name": "WAN_DHCP",
            "descr": "Interface WAN Gateway",
            "disabled": False,
            "ipprotocol": "inet",
            "interface": "wan",
            "gateway": "198.51.100.1",
            "monitor_disable": False,
            "monitor": "198.51.100.1",
            "action_disable": False,
            "force_down": False,
            "dpinger_dont_add_static_route": False,
            "gw_down_kill_states": "",
            "nonlocalgateway": False,
            "weight": 1,
            "data_payload": 1,
            "latencylow": 200,
            "latencyhigh": 500,
            "losslow": 10,
            "losshigh": 20,
            "interval": 500,
            "loss_interval": 2000,
            "time_period": 60000,
            "alert_interval": 1000,
        }
    ]
}

_GATEWAY_STATUS_BODY = {
    "data": [
        {
            "id": 0,
            "name": "WAN_DHCP",
            "srcip": "198.51.100.10",
            "monitorip": "198.51.100.1",
            "delay": 12.345,
            "stddev": 1.2,
            "loss": 0.0,
            "status": "none",
            "substatus": "none",
        }
    ]
}

_FIREWALL_RULES_BODY = {
    "data": [
        {
            "id": 0,
            "type": "pass",
            "interface": ["wan"],
            "ipprotocol": "inet",
            "protocol": "tcp",
            "icmptype": None,
            "source": "198.51.100.10",
            "source_port": None,
            "destination": "203.0.113.5",
            "destination_port": "443",
            "descr": "Allow HTTPS",
            "disabled": False,
            "log": True,
            "dscp": None,
            "tag": "",
            "statetype": "keep state",
            "tcp_flags_any": False,
            "tcp_flags_out_of": None,
            "tcp_flags_set": None,
            "gateway": None,
            "sched": None,
            "dnpipe": None,
            "pdnpipe": None,
            "defaultqueue": None,
            "ackqueue": None,
            "floating": False,
            "quick": None,
            "direction": None,
            "tracker": 1700000000,
            "associated_rule_id": None,
            "created_time": 1700000000,
            "created_by": "admin@198.51.100.20",
            "updated_time": 1700000100,
            "updated_by": "admin@198.51.100.20",
        }
    ]
}

_FIREWALL_STATES_BODY = {
    "data": [
        {
            "id": 0,
            "interface": "wan",
            "protocol": "tcp",
            "direction": "out",
            "source": "198.51.100.10:51234",
            "destination": "203.0.113.5:443",
            "state": "ESTABLISHED:ESTABLISHED",
            "age": "00:05:12",
            "expires_in": "23:59:48",
            "packets_total": 120,
            "packets_in": 60,
            "packets_out": 60,
            "bytes_total": 45000,
            "bytes_in": 20000,
            "bytes_out": 25000,
        }
    ]
}

_FIREWALL_STATES_SIZE_BODY = {
    "data": {
        "maximumstates": 500000,
        "defaultmaximumstates": 500000,
        "currentstates": 42,
    }
}

_FIREWALL_APPLY_BODY = {"data": {"applied": True, "pending_subsystems": []}}

_FIREWALL_ALIASES_BODY = {
    "data": [
        {
            "id": 0,
            "name": "IPTV",
            "descr": "TWE",
            "type": "network",
            "address": ["198.51.100.10/20"],
            "detail": ["REDACTED-detail"],
        }
    ]
}


def _client(
    *,
    with_interfaces: bool = False,
    with_gateways: bool = False,
    with_firewall: bool = False,
    with_alias: bool = False,
) -> PfSenseClient:
    transport = MockTransport()
    body = {
        "data": {
            "platform": "Netgate pfSense Plus",
            "uptime": "1 Hour",
            "cpu_model": "x",
            "cpu_count": 1,
            "cpu_usage": 1.0,
            "mem_usage": 1,
            "swap_usage": 0,
            "disk_usage": 1,
        }
    }
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    if with_interfaces:
        transport.register("GET", "/api/v2/status/interfaces", status_code=200, text=json.dumps(_INTERFACES_BODY))
    if with_gateways:
        transport.register("GET", "/api/v2/routing/gateways", status_code=200, text=json.dumps(_GATEWAYS_BODY))
        transport.register("GET", "/api/v2/status/gateways", status_code=200, text=json.dumps(_GATEWAY_STATUS_BODY))
    if with_firewall:
        transport.register("GET", "/api/v2/firewall/rules", status_code=200, text=json.dumps(_FIREWALL_RULES_BODY))
        transport.register(
            "GET", "/api/v2/firewall/states?limit=100", status_code=200, text=json.dumps(_FIREWALL_STATES_BODY)
        )
        transport.register(
            "GET", "/api/v2/firewall/states/size", status_code=200, text=json.dumps(_FIREWALL_STATES_SIZE_BODY)
        )
        transport.register("GET", "/api/v2/firewall/apply", status_code=200, text=json.dumps(_FIREWALL_APPLY_BODY))
    if with_alias:
        transport.register(
            "GET", "/api/v2/firewall/aliases?limit=100", status_code=200, text=json.dumps(_FIREWALL_ALIASES_BODY)
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


def test_registry_registers_all_firewall_tools_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {
        "pfsense_get_firewall_rules",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_states_size",
        "pfsense_get_firewall_apply_status",
    }


def test_registry_does_not_register_firewall_tools_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_rules" not in names
    assert "pfsense_get_firewall_states" not in names
    assert "pfsense_get_firewall_states_size" not in names
    assert "pfsense_get_firewall_apply_status" not in names


def test_registered_firewall_rules_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    rules_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_rules")
    rules = rules_fn()
    assert len(rules) == 1
    assert rules[0].descr == "Allow HTTPS"
    assert rules[0].source is None
    assert rules[0].destination is None
    assert rules[0].created_by is None
    assert rules[0].updated_by is None


def test_registered_firewall_states_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    states_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_states")
    states = states_fn()
    assert len(states) == 1
    assert states[0].interface == "wan"
    assert states[0].source is None
    assert states[0].destination is None


def test_registered_firewall_states_size_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    size_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_states_size")
    size = size_fn()
    assert size.currentstates == 42


def test_registered_firewall_apply_status_tool_invokes_client():
    mcp = FakeMCP()
    client = _client(with_firewall=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.FIREWALL_READ}))
    registry.register_all()
    apply_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_apply_status")
    status = apply_fn()
    assert status.applied is True
    assert status.pending_subsystems == []


def test_registry_registers_firewall_aliases_tool_when_capability_present():
    mcp = FakeMCP()
    client = _client(with_alias=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.ALIAS_READ}))
    registry.register_all()
    assert len(mcp.registered) == 1
    assert mcp.registered[0].__name__ == "pfsense_get_firewall_aliases"


def test_registry_does_not_register_firewall_aliases_tool_without_capability():
    mcp = FakeMCP()
    registry = ToolRegistry(mcp, _client(), "api-mcp-admin", frozenset({Capability.SYSTEM_READ}))
    registry.register_all()
    names = [fn.__name__ for fn in mcp.registered]
    assert "pfsense_get_firewall_aliases" not in names


def test_registered_firewall_aliases_tool_invokes_client_and_redacts_by_default():
    mcp = FakeMCP()
    client = _client(with_alias=True)
    registry = ToolRegistry(mcp, client, "api-mcp-admin", frozenset({Capability.ALIAS_READ}))
    registry.register_all()
    aliases_fn = next(fn for fn in mcp.registered if fn.__name__ == "pfsense_get_firewall_aliases")
    aliases = aliases_fn()
    assert len(aliases) == 1
    assert aliases[0].name == "IPTV"
    assert aliases[0].descr == "TWE"
    assert aliases[0].address is None
    assert aliases[0].detail is None


def test_registry_registers_all_tools_when_all_capabilities_present():
    mcp = FakeMCP()
    client = _client(with_interfaces=True, with_gateways=True, with_firewall=True)
    registry = ToolRegistry(
        mcp,
        client,
        "api-mcp-admin",
        frozenset(
            {
                Capability.SYSTEM_READ,
                Capability.INTERFACE_READ,
                Capability.GATEWAY_READ,
                Capability.FIREWALL_READ,
            }
        ),
    )
    registry.register_all()
    names = {fn.__name__ for fn in mcp.registered}
    assert names == {
        "pfsense_get_system_status",
        "pfsense_get_interfaces",
        "pfsense_get_gateways",
        "pfsense_get_gateway_status",
        "pfsense_get_firewall_rules",
        "pfsense_get_firewall_states",
        "pfsense_get_firewall_states_size",
        "pfsense_get_firewall_apply_status",
    }
