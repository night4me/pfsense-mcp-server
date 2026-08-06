import json
from pathlib import Path

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport

FIXTURE = Path(__file__).parent / "fixtures" / "system_status_response.json"
INTERFACES_FIXTURE = Path(__file__).parent / "fixtures" / "interfaces_status_response.json"
GATEWAYS_FIXTURE = Path(__file__).parent / "fixtures" / "gateways_response.json"
GATEWAY_STATUS_FIXTURE = Path(__file__).parent / "fixtures" / "gateway_status_response.json"
FIREWALL_RULES_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_rules_response.json"
FIREWALL_STATES_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_states_response.json"
FIREWALL_STATES_SIZE_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_states_size_response.json"
FIREWALL_APPLY_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_apply_response.json"

INTERFACES_IDENTIFYING_FIELDS = (
    "macaddr",
    "ipaddr",
    "subnet",
    "linklocal",
    "ipaddrv6",
    "subnetv6",
    "gateway",
    "gatewayv6",
)

GATEWAYS_IDENTIFYING_FIELDS = ("gateway", "monitor")
GATEWAY_STATUS_IDENTIFYING_FIELDS = ("srcip", "monitorip")

FIREWALL_RULES_IDENTIFYING_FIELDS = ("source", "destination", "created_by", "updated_by")
FIREWALL_STATES_IDENTIFYING_FIELDS = ("source", "destination")


def _client_with_fixture() -> PfSenseClient:
    transport = MockTransport()
    body = json.loads(FIXTURE.read_text())
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client)


def test_get_system_status_excludes_netgate_id_by_default():
    client = _client_with_fixture()
    status = client.get_system_status()
    assert status.netgate_id is None
    assert status.platform == "Netgate pfSense Plus"
    assert status.cpu_count == 4


def test_get_system_status_includes_netgate_id_when_requested():
    client = _client_with_fixture()
    status = client.get_system_status(include_identifying_metadata=True)
    assert status.netgate_id == "ANONYMIZED0000000000"


def _interfaces_body() -> dict:
    return json.loads(INTERFACES_FIXTURE.read_text())


def _interfaces_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interfaces_body()
    transport.register("GET", "/api/v2/status/interfaces", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interfaces_omits_identifying_fields_by_default():
    client, _ = _interfaces_client()
    interfaces = client.get_interfaces()
    assert len(interfaces) == 2
    for iface in interfaces:
        for field in INTERFACES_IDENTIFYING_FIELDS:
            assert getattr(iface, field) is None


def test_get_interfaces_includes_identifying_fields_when_requested():
    client, _ = _interfaces_client()
    interfaces = client.get_interfaces(include_identifying_metadata=True)
    wan = next(i for i in interfaces if i.name == "wan")
    assert wan.macaddr == "02:00:00:aa:bb:cc"
    assert wan.ipaddr == "198.51.100.10"
    assert wan.subnet == "255.255.255.0"
    assert wan.linklocal == "fe80::200:ff:feaa:bbcc%igb0"
    assert wan.gateway == "198.51.100.1"
    assert wan.ipaddrv6 is None
    assert wan.gatewayv6 is None


def test_get_interfaces_maps_non_sensitive_fields_and_counters():
    client, _ = _interfaces_client()
    interfaces = client.get_interfaces()
    wan = next(i for i in interfaces if i.name == "wan")
    lan = next(i for i in interfaces if i.name == "lan")

    assert wan.id == 0
    assert wan.descr == "WAN"
    assert wan.hwif == "igb0"
    assert wan.mtu == "1500"
    assert wan.enable is True
    assert wan.status == "up"
    assert wan.dhcplink == "up"
    assert wan.media == "1000baseT <full-duplex>"
    assert wan.inerrs == 0
    assert wan.outerrs == 0
    assert wan.collisions == 0
    assert wan.inbytes == 1000
    assert wan.inbytespass == 1000
    assert wan.outbytes == 2000
    assert wan.outbytespass == 2000
    assert wan.inpkts == 10
    assert wan.inpktspass == 10
    assert wan.outpkts == 20
    assert wan.outpktspass == 20

    assert lan.status == "no carrier"
    assert lan.dhcplink is None
    assert lan.media is None
    assert lan.inerrs == 3
    assert lan.outerrs == 1


def test_get_interfaces_only_calls_status_interfaces_endpoint():
    client, transport = _interfaces_client()
    client.get_interfaces()
    assert transport.calls == [("GET", "/api/v2/status/interfaces")]


def test_get_interfaces_missing_data_key_raises_shape_error():
    body = _interfaces_body()
    del body["data"]
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interfaces()


def test_get_interfaces_data_wrong_type_raises_shape_error():
    body = _interfaces_body()
    body["data"] = "not-a-list"
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interfaces()


def test_get_interfaces_item_wrong_type_raises_shape_error():
    body = _interfaces_body()
    body["data"] = ["not-an-object"]
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interfaces()


def test_get_interfaces_required_field_missing_raises_shape_error():
    body = _interfaces_body()
    del body["data"][0]["inbytes"]
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interfaces()


def test_get_interfaces_invalid_field_type_raises_shape_error():
    body = _interfaces_body()
    body["data"][0]["inbytes"] = "not-a-number"
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interfaces()


def test_get_interfaces_shape_error_does_not_leak_raw_field_values():
    body = _interfaces_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["inbytes"] = sentinel
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interfaces()
    assert sentinel not in str(excinfo.value)


def _gateways_body() -> dict:
    return json.loads(GATEWAYS_FIXTURE.read_text())


def _gateways_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _gateways_body()
    transport.register("GET", "/api/v2/routing/gateways", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_gateways_omits_identifying_fields_by_default():
    client, _ = _gateways_client()
    gateways = client.get_gateways()
    assert len(gateways) == 2
    for gw in gateways:
        for field in GATEWAYS_IDENTIFYING_FIELDS:
            assert getattr(gw, field) is None


def test_get_gateways_includes_identifying_fields_when_requested():
    client, _ = _gateways_client()
    gateways = client.get_gateways(include_identifying_metadata=True)
    wan = next(g for g in gateways if g.name == "WAN_DHCP")
    assert wan.gateway == "198.51.100.1"
    assert wan.monitor == "198.51.100.1"
    opt1 = next(g for g in gateways if g.name == "OPT1_GW")
    assert opt1.gateway == "203.0.113.1"
    assert opt1.monitor is None


def test_get_gateways_maps_non_sensitive_fields():
    client, _ = _gateways_client()
    gateways = client.get_gateways()
    wan = next(g for g in gateways if g.name == "WAN_DHCP")

    assert wan.id == 0
    assert wan.descr == "Interface WAN Gateway"
    assert wan.disabled is False
    assert wan.ipprotocol == "inet"
    assert wan.interface == "wan"
    assert wan.monitor_disable is False
    assert wan.action_disable is False
    assert wan.force_down is False
    assert wan.dpinger_dont_add_static_route is False
    assert wan.gw_down_kill_states == ""
    assert wan.nonlocalgateway is False
    assert wan.weight == 1
    assert wan.data_payload == 1
    assert wan.latencylow == 200
    assert wan.latencyhigh == 500
    assert wan.losslow == 10
    assert wan.losshigh == 20
    assert wan.interval == 500
    assert wan.loss_interval == 2000
    assert wan.time_period == 60000
    assert wan.alert_interval == 1000

    opt1 = next(g for g in gateways if g.name == "OPT1_GW")
    assert opt1.disabled is True
    assert opt1.gw_down_kill_states == "down"


def test_get_gateways_only_calls_routing_gateways_endpoint():
    client, transport = _gateways_client()
    client.get_gateways()
    assert transport.calls == [("GET", "/api/v2/routing/gateways")]


def test_get_gateways_missing_data_key_raises_shape_error():
    body = _gateways_body()
    del body["data"]
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateways()


def test_get_gateways_data_wrong_type_raises_shape_error():
    body = _gateways_body()
    body["data"] = "not-a-list"
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateways()


def test_get_gateways_item_wrong_type_raises_shape_error():
    body = _gateways_body()
    body["data"] = ["not-an-object"]
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateways()


def test_get_gateways_required_field_missing_raises_shape_error():
    body = _gateways_body()
    del body["data"][0]["weight"]
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateways()


def test_get_gateways_invalid_field_type_raises_shape_error():
    body = _gateways_body()
    body["data"][0]["weight"] = "not-a-number"
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateways()


def test_get_gateways_shape_error_does_not_leak_raw_field_values():
    body = _gateways_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["weight"] = sentinel
    client, _ = _gateways_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_gateways()
    assert sentinel not in str(excinfo.value)


def _gateway_status_body() -> dict:
    return json.loads(GATEWAY_STATUS_FIXTURE.read_text())


def _gateway_status_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _gateway_status_body()
    transport.register("GET", "/api/v2/status/gateways", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_gateway_status_omits_identifying_fields_by_default():
    client, _ = _gateway_status_client()
    statuses = client.get_gateway_status()
    assert len(statuses) == 2
    for status in statuses:
        for field in GATEWAY_STATUS_IDENTIFYING_FIELDS:
            assert getattr(status, field) is None


def test_get_gateway_status_includes_identifying_fields_when_requested():
    client, _ = _gateway_status_client()
    statuses = client.get_gateway_status(include_identifying_metadata=True)
    wan = next(s for s in statuses if s.name == "WAN_DHCP")
    assert wan.srcip == "198.51.100.10"
    assert wan.monitorip == "198.51.100.1"


def test_get_gateway_status_maps_non_sensitive_fields():
    client, _ = _gateway_status_client()
    statuses = client.get_gateway_status()
    wan = next(s for s in statuses if s.name == "WAN_DHCP")
    opt1 = next(s for s in statuses if s.name == "OPT1_GW")

    assert wan.id == 0
    assert wan.delay == 12.345
    assert wan.stddev == 1.2
    assert wan.loss == 0.0
    assert wan.status == "none"
    assert wan.substatus == "none"

    assert opt1.status == "down"
    assert opt1.substatus == "highdelay"
    assert opt1.loss == 100.0


def test_get_gateway_status_only_calls_status_gateways_endpoint():
    client, transport = _gateway_status_client()
    client.get_gateway_status()
    assert transport.calls == [("GET", "/api/v2/status/gateways")]


def test_get_gateway_status_missing_data_key_raises_shape_error():
    body = _gateway_status_body()
    del body["data"]
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateway_status()


def test_get_gateway_status_data_wrong_type_raises_shape_error():
    body = _gateway_status_body()
    body["data"] = "not-a-list"
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateway_status()


def test_get_gateway_status_item_wrong_type_raises_shape_error():
    body = _gateway_status_body()
    body["data"] = ["not-an-object"]
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateway_status()


def test_get_gateway_status_required_field_missing_raises_shape_error():
    body = _gateway_status_body()
    del body["data"][0]["delay"]
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateway_status()


def test_get_gateway_status_invalid_field_type_raises_shape_error():
    body = _gateway_status_body()
    body["data"][0]["delay"] = "not-a-number"
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_gateway_status()


def test_get_gateway_status_shape_error_does_not_leak_raw_field_values():
    body = _gateway_status_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["delay"] = sentinel
    client, _ = _gateway_status_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_gateway_status()
    assert sentinel not in str(excinfo.value)


def _firewall_rules_body() -> dict:
    return json.loads(FIREWALL_RULES_FIXTURE.read_text())


def _firewall_rules_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_rules_body()
    transport.register("GET", "/api/v2/firewall/rules", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_rules_omits_identifying_fields_by_default():
    client, _ = _firewall_rules_client()
    rules = client.get_firewall_rules()
    assert len(rules) == 2
    for rule in rules:
        for field in FIREWALL_RULES_IDENTIFYING_FIELDS:
            assert getattr(rule, field) is None


def test_get_firewall_rules_includes_identifying_fields_when_requested():
    client, _ = _firewall_rules_client()
    rules = client.get_firewall_rules(include_identifying_metadata=True)
    allow = next(r for r in rules if r.descr == "Allow HTTPS to web host")
    assert allow.source == "198.51.100.10"
    assert allow.destination == "203.0.113.5"
    assert allow.created_by == "admin@198.51.100.20"
    assert allow.updated_by == "admin@198.51.100.20"


def test_get_firewall_rules_maps_non_sensitive_fields():
    client, _ = _firewall_rules_client()
    rules = client.get_firewall_rules()
    allow = next(r for r in rules if r.descr == "Allow HTTPS to web host")
    block = next(r for r in rules if r.descr == "Block all")

    assert allow.id == 0
    assert allow.type == "pass"
    assert allow.interface == ["wan"]
    assert allow.ipprotocol == "inet"
    assert allow.protocol == "tcp"
    assert allow.disabled is False
    assert allow.log is True
    assert allow.statetype == "keep state"
    assert allow.floating is False
    assert allow.tracker == 1700000000
    assert allow.destination_port == "443"
    # gateway is a name reference, not identifying metadata, and is
    # always populated regardless of include_identifying_metadata.
    assert allow.gateway is None

    assert block.type == "block"
    assert block.disabled is True
    assert block.quick is True


def test_get_firewall_rules_only_calls_firewall_rules_endpoint():
    client, transport = _firewall_rules_client()
    client.get_firewall_rules()
    assert transport.calls == [("GET", "/api/v2/firewall/rules")]


def test_get_firewall_rules_missing_data_key_raises_shape_error():
    body = _firewall_rules_body()
    del body["data"]
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_rules()


def test_get_firewall_rules_data_wrong_type_raises_shape_error():
    body = _firewall_rules_body()
    body["data"] = "not-a-list"
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_rules()


def test_get_firewall_rules_item_wrong_type_raises_shape_error():
    body = _firewall_rules_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_rules()


def test_get_firewall_rules_required_field_missing_raises_shape_error():
    body = _firewall_rules_body()
    del body["data"][0]["tracker"]
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_rules()


def test_get_firewall_rules_invalid_field_type_raises_shape_error():
    body = _firewall_rules_body()
    body["data"][0]["tracker"] = "not-a-number"
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_rules()


def test_get_firewall_rules_shape_error_does_not_leak_raw_field_values():
    body = _firewall_rules_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["tracker"] = sentinel
    client, _ = _firewall_rules_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_rules()
    assert sentinel not in str(excinfo.value)


def _firewall_states_body() -> dict:
    return json.loads(FIREWALL_STATES_FIXTURE.read_text())


def _firewall_states_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_states_body()
    transport.register("GET", "/api/v2/firewall/states?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_states_omits_identifying_fields_by_default():
    client, _ = _firewall_states_client()
    states = client.get_firewall_states()
    assert len(states) == 2
    for state in states:
        for field in FIREWALL_STATES_IDENTIFYING_FIELDS:
            assert getattr(state, field) is None


def test_get_firewall_states_includes_identifying_fields_when_requested():
    client, _ = _firewall_states_client()
    states = client.get_firewall_states(include_identifying_metadata=True)
    wan_state = next(s for s in states if s.interface == "wan")
    assert wan_state.source == "198.51.100.10:51234"
    assert wan_state.destination == "203.0.113.5:443"


def test_get_firewall_states_maps_non_sensitive_fields():
    client, _ = _firewall_states_client()
    states = client.get_firewall_states()
    wan_state = next(s for s in states if s.interface == "wan")

    assert wan_state.id == 0
    assert wan_state.protocol == "tcp"
    assert wan_state.direction == "out"
    assert wan_state.state == "ESTABLISHED:ESTABLISHED"
    assert wan_state.age == "00:05:12"
    assert wan_state.packets_total == 120
    assert wan_state.bytes_total == 45000


def test_get_firewall_states_only_calls_firewall_states_endpoint_with_default_limit():
    client, transport = _firewall_states_client()
    client.get_firewall_states()
    assert transport.calls == [("GET", "/api/v2/firewall/states?limit=100")]


def test_get_firewall_states_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_states_body()
    transport.register("GET", "/api/v2/firewall/states?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_states(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/states?limit=5")]


def test_get_firewall_states_rejects_zero_limit():
    client, _ = _firewall_states_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_states(limit=0)


def test_get_firewall_states_rejects_negative_limit():
    client, _ = _firewall_states_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_states(limit=-5)


def test_get_firewall_states_rejects_limit_above_max():
    client, _ = _firewall_states_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_states(limit=501)


def test_get_firewall_states_accepts_max_limit_boundary():
    transport = MockTransport()
    body = _firewall_states_body()
    transport.register("GET", "/api/v2/firewall/states?limit=500", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    states = client.get_firewall_states(limit=500)
    assert len(states) == 2


def test_get_firewall_states_invalid_limit_never_calls_transport():
    client, transport = _firewall_states_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_states(limit=0)
    assert transport.calls == []


def test_get_firewall_states_accepts_min_limit_boundary():
    transport = MockTransport()
    body = _firewall_states_body()
    transport.register("GET", "/api/v2/firewall/states?limit=1", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    states = client.get_firewall_states(limit=1)
    assert len(states) == 2


def test_get_firewall_states_accepts_mid_range_limit():
    transport = MockTransport()
    body = _firewall_states_body()
    transport.register("GET", "/api/v2/firewall/states?limit=100", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    states = client.get_firewall_states(limit=100)
    assert len(states) == 2


def test_get_firewall_states_rejects_limit_just_above_max():
    client, transport = _firewall_states_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_states(limit=501)
    assert transport.calls == []


def test_get_firewall_states_missing_data_key_raises_shape_error():
    body = _firewall_states_body()
    del body["data"]
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states()


def test_get_firewall_states_data_wrong_type_raises_shape_error():
    body = _firewall_states_body()
    body["data"] = "not-a-list"
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states()


def test_get_firewall_states_item_wrong_type_raises_shape_error():
    body = _firewall_states_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states()


def test_get_firewall_states_required_field_missing_raises_shape_error():
    body = _firewall_states_body()
    del body["data"][0]["bytes_total"]
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states()


def test_get_firewall_states_invalid_field_type_raises_shape_error():
    body = _firewall_states_body()
    body["data"][0]["bytes_total"] = "not-a-number"
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states()


def test_get_firewall_states_shape_error_does_not_leak_raw_field_values():
    body = _firewall_states_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["bytes_total"] = sentinel
    client, _ = _firewall_states_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_states()
    assert sentinel not in str(excinfo.value)


def _firewall_states_size_body() -> dict:
    return json.loads(FIREWALL_STATES_SIZE_FIXTURE.read_text())


def _firewall_states_size_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_states_size_body()
    transport.register("GET", "/api/v2/firewall/states/size", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_states_size_maps_fields():
    client, _ = _firewall_states_size_client()
    size = client.get_firewall_states_size()
    assert size.maximumstates == 500000
    assert size.defaultmaximumstates == 500000
    assert size.currentstates == 42


def test_get_firewall_states_size_only_calls_states_size_endpoint():
    client, transport = _firewall_states_size_client()
    client.get_firewall_states_size()
    assert transport.calls == [("GET", "/api/v2/firewall/states/size")]


def test_get_firewall_states_size_missing_data_key_raises_shape_error():
    body = _firewall_states_size_body()
    del body["data"]
    client, _ = _firewall_states_size_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states_size()


def test_get_firewall_states_size_data_wrong_type_raises_shape_error():
    body = _firewall_states_size_body()
    body["data"] = "not-an-object"
    client, _ = _firewall_states_size_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states_size()


def test_get_firewall_states_size_required_field_missing_raises_shape_error():
    body = _firewall_states_size_body()
    del body["data"]["currentstates"]
    client, _ = _firewall_states_size_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states_size()


def test_get_firewall_states_size_invalid_field_type_raises_shape_error():
    body = _firewall_states_size_body()
    body["data"]["currentstates"] = "not-a-number"
    client, _ = _firewall_states_size_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_states_size()


def test_get_firewall_states_size_shape_error_does_not_leak_raw_field_values():
    body = _firewall_states_size_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["currentstates"] = sentinel
    client, _ = _firewall_states_size_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_states_size()
    assert sentinel not in str(excinfo.value)


def _firewall_apply_body() -> dict:
    return json.loads(FIREWALL_APPLY_FIXTURE.read_text())


def _firewall_apply_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_apply_body()
    transport.register("GET", "/api/v2/firewall/apply", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_apply_status_maps_fields():
    client, _ = _firewall_apply_client()
    status = client.get_firewall_apply_status()
    assert status.applied is True
    assert status.pending_subsystems == []


def test_get_firewall_apply_status_only_calls_apply_endpoint():
    client, transport = _firewall_apply_client()
    client.get_firewall_apply_status()
    assert transport.calls == [("GET", "/api/v2/firewall/apply")]


def test_get_firewall_apply_status_missing_data_key_raises_shape_error():
    body = _firewall_apply_body()
    del body["data"]
    client, _ = _firewall_apply_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_apply_status()


def test_get_firewall_apply_status_data_wrong_type_raises_shape_error():
    body = _firewall_apply_body()
    body["data"] = "not-an-object"
    client, _ = _firewall_apply_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_apply_status()


def test_get_firewall_apply_status_required_field_missing_raises_shape_error():
    body = _firewall_apply_body()
    del body["data"]["applied"]
    client, _ = _firewall_apply_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_apply_status()


def test_get_firewall_apply_status_invalid_field_type_raises_shape_error():
    body = _firewall_apply_body()
    body["data"]["pending_subsystems"] = "not-a-list"
    client, _ = _firewall_apply_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_apply_status()


def test_get_firewall_apply_status_shape_error_does_not_leak_raw_field_values():
    body = _firewall_apply_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["pending_subsystems"] = sentinel
    client, _ = _firewall_apply_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_apply_status()
    assert sentinel not in str(excinfo.value)


FIREWALL_ALIASES_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_aliases_response.json"
FIREWALL_ALIASES_IDENTIFYING_FIELDS = ("address", "detail")


def _firewall_aliases_body() -> dict:
    return json.loads(FIREWALL_ALIASES_FIXTURE.read_text())


def _firewall_aliases_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_aliases_body()
    transport.register("GET", "/api/v2/firewall/aliases?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_aliases_omits_identifying_fields_by_default():
    client, _ = _firewall_aliases_client()
    aliases = client.get_firewall_aliases()
    assert len(aliases) == 4
    for alias in aliases:
        for field in FIREWALL_ALIASES_IDENTIFYING_FIELDS:
            assert getattr(alias, field) is None


def test_get_firewall_aliases_includes_identifying_fields_when_requested():
    client, _ = _firewall_aliases_client()
    aliases = client.get_firewall_aliases(include_identifying_metadata=True)
    iptv = next(a for a in aliases if a.name == "IPTV")
    assert iptv.address == [
        "198.51.100.10/20",
        "198.51.100.11/16",
        "198.51.100.12/8",
        "198.51.100.13/8",
        "198.51.100.14/4",
    ]
    assert iptv.detail == ["REDACTED-detail"] * 5


def test_get_firewall_aliases_maps_non_sensitive_fields():
    client, _ = _firewall_aliases_client()
    aliases = client.get_firewall_aliases()
    iptv = next(a for a in aliases if a.name == "IPTV")
    assert iptv.id == 0
    assert iptv.descr == "TWE"
    assert iptv.type == "network"


def test_get_firewall_aliases_only_calls_firewall_aliases_endpoint_with_default_limit():
    client, transport = _firewall_aliases_client()
    client.get_firewall_aliases()
    assert transport.calls == [("GET", "/api/v2/firewall/aliases?limit=100")]


def test_get_firewall_aliases_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_aliases_body()
    transport.register("GET", "/api/v2/firewall/aliases?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_aliases(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/aliases?limit=5")]


def test_get_firewall_aliases_rejects_zero_limit():
    client, _ = _firewall_aliases_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_aliases(limit=0)


def test_get_firewall_aliases_rejects_limit_above_max():
    client, _ = _firewall_aliases_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_aliases(limit=501)


def test_get_firewall_aliases_invalid_limit_never_calls_transport():
    client, transport = _firewall_aliases_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_aliases(limit=0)
    assert transport.calls == []


def test_get_firewall_aliases_missing_data_key_raises_shape_error():
    body = _firewall_aliases_body()
    del body["data"]
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_aliases()


def test_get_firewall_aliases_data_wrong_type_raises_shape_error():
    body = _firewall_aliases_body()
    body["data"] = "not-a-list"
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_aliases()


def test_get_firewall_aliases_item_wrong_type_raises_shape_error():
    body = _firewall_aliases_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_aliases()


def test_get_firewall_aliases_required_field_missing_raises_shape_error():
    body = _firewall_aliases_body()
    del body["data"][0]["name"]
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_aliases()


def test_get_firewall_aliases_invalid_field_type_raises_shape_error():
    body = _firewall_aliases_body()
    body["data"][0]["id"] = "not-a-number"
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_aliases()


def test_get_firewall_aliases_shape_error_does_not_leak_raw_field_values():
    body = _firewall_aliases_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["id"] = sentinel
    client, _ = _firewall_aliases_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_aliases()
    assert sentinel not in str(excinfo.value)


STATUS_SERVICES_FIXTURE = Path(__file__).parent / "fixtures" / "status_services_response.json"


def _service_status_body() -> dict:
    return json.loads(STATUS_SERVICES_FIXTURE.read_text())


def _service_status_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _service_status_body()
    transport.register("GET", "/api/v2/status/services?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_service_status_maps_fields():
    client, _ = _service_status_client()
    services = client.get_service_status()
    assert len(services) == 10
    vnstatd = next(s for s in services if s.name == "vnstatd")
    assert vnstatd.id == 0
    assert vnstatd.description == "Status Traffic Totals data collection daemon"
    assert vnstatd.enabled is True
    assert vnstatd.status is True
    vmware_guestd = next(s for s in services if s.name == "vmware-guestd")
    assert vmware_guestd.status is False


def test_get_service_status_only_calls_status_services_endpoint_with_default_limit():
    client, transport = _service_status_client()
    client.get_service_status()
    assert transport.calls == [("GET", "/api/v2/status/services?limit=100")]


def test_get_service_status_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _service_status_body()
    transport.register("GET", "/api/v2/status/services?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_service_status(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/services?limit=5")]


def test_get_service_status_rejects_zero_limit():
    client, _ = _service_status_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_service_status(limit=0)


def test_get_service_status_rejects_limit_above_max():
    client, _ = _service_status_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_service_status(limit=101)


def test_get_service_status_invalid_limit_never_calls_transport():
    client, transport = _service_status_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_service_status(limit=0)
    assert transport.calls == []


def test_get_service_status_missing_data_key_raises_shape_error():
    body = _service_status_body()
    del body["data"]
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_service_status()


def test_get_service_status_data_wrong_type_raises_shape_error():
    body = _service_status_body()
    body["data"] = "not-a-list"
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_service_status()


def test_get_service_status_item_wrong_type_raises_shape_error():
    body = _service_status_body()
    body["data"] = ["not-an-object"]
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_service_status()


def test_get_service_status_required_field_missing_raises_shape_error():
    body = _service_status_body()
    del body["data"][0]["name"]
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_service_status()


def test_get_service_status_invalid_field_type_raises_shape_error():
    body = _service_status_body()
    body["data"][0]["id"] = "not-a-number"
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_service_status()


def test_get_service_status_shape_error_does_not_leak_raw_field_values():
    body = _service_status_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["id"] = sentinel
    client, _ = _service_status_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_service_status()
    assert sentinel not in str(excinfo.value)


SYSTEM_VERSION_FIXTURE = Path(__file__).parent / "fixtures" / "system_version_response.json"


def _system_version_body() -> dict:
    return json.loads(SYSTEM_VERSION_FIXTURE.read_text())


def _system_version_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_version_body()
    transport.register("GET", "/api/v2/system/version", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_version_maps_fields():
    client, _ = _system_version_client()
    result = client.get_system_version()
    assert result.base == "26.03.1"
    assert result.buildtime == "20260731-1801"
    assert result.patch == "0"
    assert result.version == "host.example.invalid"


def test_get_system_version_only_calls_system_version_endpoint():
    client, transport = _system_version_client()
    client.get_system_version()
    assert transport.calls == [("GET", "/api/v2/system/version")]


def test_get_system_version_missing_data_key_raises_shape_error():
    body = _system_version_body()
    del body["data"]
    client, _ = _system_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_version()


def test_get_system_version_data_wrong_type_raises_shape_error():
    body = _system_version_body()
    body["data"] = "not-an-object"
    client, _ = _system_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_version()


def test_get_system_version_required_field_missing_raises_shape_error():
    body = _system_version_body()
    del body["data"]["base"]
    client, _ = _system_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_version()


def test_get_system_version_invalid_field_type_raises_shape_error():
    body = _system_version_body()
    body["data"]["base"] = 123
    client, _ = _system_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_version()


def test_get_system_version_shape_error_does_not_leak_raw_field_values():
    body = _system_version_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["base"] = [sentinel]
    client, _ = _system_version_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_version()
    assert sentinel not in str(excinfo.value)


INTERFACE_CONFIGS_FIXTURE = Path(__file__).parent / "fixtures" / "interfaces_response.json"
INTERFACE_CONFIGS_IDENTIFYING_FIELDS = (
    "alias_address",
    "dhcphostname",
    "gateway",
    "gatewayv6",
    "ipaddr",
    "ipaddrv6",
    "spoofmac",
    "subnet",
    "subnetv6",
)


def _interface_configs_body() -> dict:
    return json.loads(INTERFACE_CONFIGS_FIXTURE.read_text())


def _interface_configs_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_configs_body()
    transport.register("GET", "/api/v2/interfaces?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_configs_omits_identifying_fields_by_default():
    client, _ = _interface_configs_client()
    configs = client.get_interface_configs()
    assert len(configs) == 5
    for config in configs:
        for field in INTERFACE_CONFIGS_IDENTIFYING_FIELDS:
            assert getattr(config, field) is None


def test_get_interface_configs_includes_identifying_fields_when_requested():
    client, _ = _interface_configs_client()
    configs = client.get_interface_configs(include_identifying_metadata=True)
    lan = next(c for c in configs if c.id == "lan")
    assert lan.ipaddr == "198.51.100.10"


def test_get_interface_configs_maps_non_sensitive_fields():
    client, _ = _interface_configs_client()
    configs = client.get_interface_configs()
    wan = next(c for c in configs if c.id == "wan")
    assert wan.if_ == "igb0"
    assert wan.descr == "WAN"
    assert wan.enable is True
    assert wan.typev4 == "dhcp"


def test_get_interface_configs_only_calls_interfaces_endpoint_with_default_limit():
    client, transport = _interface_configs_client()
    client.get_interface_configs()
    assert transport.calls == [("GET", "/api/v2/interfaces?limit=100")]


def test_get_interface_configs_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_configs_body()
    transport.register("GET", "/api/v2/interfaces?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_configs(limit=5)
    assert transport.calls == [("GET", "/api/v2/interfaces?limit=5")]


def test_get_interface_configs_rejects_zero_limit():
    client, _ = _interface_configs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_configs(limit=0)


def test_get_interface_configs_rejects_limit_above_max():
    client, _ = _interface_configs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_configs(limit=101)


def test_get_interface_configs_invalid_limit_never_calls_transport():
    client, transport = _interface_configs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_configs(limit=0)
    assert transport.calls == []


def test_get_interface_configs_missing_data_key_raises_shape_error():
    body = _interface_configs_body()
    del body["data"]
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_configs()


def test_get_interface_configs_data_wrong_type_raises_shape_error():
    body = _interface_configs_body()
    body["data"] = "not-a-list"
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_configs()


def test_get_interface_configs_item_wrong_type_raises_shape_error():
    body = _interface_configs_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_configs()


def test_get_interface_configs_required_field_missing_raises_shape_error():
    body = _interface_configs_body()
    del body["data"][0]["descr"]
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_configs()


def test_get_interface_configs_invalid_field_type_raises_shape_error():
    body = _interface_configs_body()
    body["data"][0]["descr"] = 123
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_configs()


def test_get_interface_configs_shape_error_does_not_leak_raw_field_values():
    body = _interface_configs_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _interface_configs_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_configs()
    assert sentinel not in str(excinfo.value)


FIREWALL_NAT_PORT_FORWARDS_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_nat_port_forwards_response.json"
FIREWALL_NAT_PORT_FORWARDS_IDENTIFYING_FIELDS = ("source", "destination", "target", "created_by", "updated_by")


def _firewall_nat_port_forwards_body() -> dict:
    return json.loads(FIREWALL_NAT_PORT_FORWARDS_FIXTURE.read_text())


def _firewall_nat_port_forwards_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_nat_port_forwards_body()
    transport.register("GET", "/api/v2/firewall/nat/port_forwards?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_nat_port_forwards_omits_identifying_fields_by_default():
    client, _ = _firewall_nat_port_forwards_client()
    rules = client.get_firewall_nat_port_forwards()
    assert len(rules) == 5
    for rule in rules:
        for field in FIREWALL_NAT_PORT_FORWARDS_IDENTIFYING_FIELDS:
            assert getattr(rule, field) is None


def test_get_firewall_nat_port_forwards_includes_identifying_fields_when_requested():
    client, _ = _firewall_nat_port_forwards_client()
    rules = client.get_firewall_nat_port_forwards(include_identifying_metadata=True)
    first = next(r for r in rules if r.id == 0)
    assert first.target == "198.51.100.10"


def test_get_firewall_nat_port_forwards_maps_non_sensitive_fields():
    client, _ = _firewall_nat_port_forwards_client()
    rules = client.get_firewall_nat_port_forwards()
    first = next(r for r in rules if r.id == 0)
    assert first.descr == "DelugeTorrent"
    assert first.interface == "wan"
    assert first.protocol == "tcp"
    assert first.destination_port == "58846"


def test_get_firewall_nat_port_forwards_only_calls_endpoint_with_default_limit():
    client, transport = _firewall_nat_port_forwards_client()
    client.get_firewall_nat_port_forwards()
    assert transport.calls == [("GET", "/api/v2/firewall/nat/port_forwards?limit=100")]


def test_get_firewall_nat_port_forwards_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_nat_port_forwards_body()
    transport.register("GET", "/api/v2/firewall/nat/port_forwards?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_nat_port_forwards(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/nat/port_forwards?limit=5")]


def test_get_firewall_nat_port_forwards_rejects_zero_limit():
    client, _ = _firewall_nat_port_forwards_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_port_forwards(limit=0)


def test_get_firewall_nat_port_forwards_rejects_limit_above_max():
    client, _ = _firewall_nat_port_forwards_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_port_forwards(limit=501)


def test_get_firewall_nat_port_forwards_invalid_limit_never_calls_transport():
    client, transport = _firewall_nat_port_forwards_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_port_forwards(limit=0)
    assert transport.calls == []


def test_get_firewall_nat_port_forwards_missing_data_key_raises_shape_error():
    body = _firewall_nat_port_forwards_body()
    del body["data"]
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_port_forwards()


def test_get_firewall_nat_port_forwards_data_wrong_type_raises_shape_error():
    body = _firewall_nat_port_forwards_body()
    body["data"] = "not-a-list"
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_port_forwards()


def test_get_firewall_nat_port_forwards_item_wrong_type_raises_shape_error():
    body = _firewall_nat_port_forwards_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_port_forwards()


def test_get_firewall_nat_port_forwards_required_field_missing_raises_shape_error():
    body = _firewall_nat_port_forwards_body()
    del body["data"][0]["descr"]
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_port_forwards()


def test_get_firewall_nat_port_forwards_invalid_field_type_raises_shape_error():
    body = _firewall_nat_port_forwards_body()
    body["data"][0]["descr"] = 123
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_port_forwards()


def test_get_firewall_nat_port_forwards_shape_error_does_not_leak_raw_field_values():
    body = _firewall_nat_port_forwards_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _firewall_nat_port_forwards_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_nat_port_forwards()
    assert sentinel not in str(excinfo.value)


# GENERATED PROPOSAL for get_firewall_nat_outbound_mode — review before use.
def _get_firewall_nat_outbound_mode_body() -> dict:
    # TODO(human): replace with the approved fixture's actual content
    return {"data": {}}


FIREWALL_NAT_OUTBOUND_MODE_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_nat_outbound_mode_response.json"


def _firewall_nat_outbound_mode_body() -> dict:
    return json.loads(FIREWALL_NAT_OUTBOUND_MODE_FIXTURE.read_text())


def _firewall_nat_outbound_mode_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_nat_outbound_mode_body()
    transport.register("GET", "/api/v2/firewall/nat/outbound/mode", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_nat_outbound_mode_maps_fields():
    client, _ = _firewall_nat_outbound_mode_client()
    result = client.get_firewall_nat_outbound_mode()
    assert result.mode == "hybrid"


def test_get_firewall_nat_outbound_mode_only_calls_expected_endpoint():
    client, transport = _firewall_nat_outbound_mode_client()
    client.get_firewall_nat_outbound_mode()
    assert transport.calls == [("GET", "/api/v2/firewall/nat/outbound/mode")]


def test_get_firewall_nat_outbound_mode_missing_data_key_raises_shape_error():
    body = _firewall_nat_outbound_mode_body()
    del body["data"]
    client, _ = _firewall_nat_outbound_mode_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mode()


def test_get_firewall_nat_outbound_mode_data_wrong_type_raises_shape_error():
    body = _firewall_nat_outbound_mode_body()
    body["data"] = "not-an-object"
    client, _ = _firewall_nat_outbound_mode_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mode()


def test_get_firewall_nat_outbound_mode_required_field_missing_raises_shape_error():
    body = _firewall_nat_outbound_mode_body()
    del body["data"]["mode"]
    client, _ = _firewall_nat_outbound_mode_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mode()


def test_get_firewall_nat_outbound_mode_invalid_field_type_raises_shape_error():
    body = _firewall_nat_outbound_mode_body()
    body["data"]["mode"] = 123
    client, _ = _firewall_nat_outbound_mode_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mode()


def test_get_firewall_nat_outbound_mode_shape_error_does_not_leak_raw_field_values():
    body = _firewall_nat_outbound_mode_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["mode"] = [sentinel]
    client, _ = _firewall_nat_outbound_mode_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_nat_outbound_mode()
    assert sentinel not in str(excinfo.value)


USERS_FIXTURE = Path(__file__).parent / "fixtures" / "users_response.json"
USERS_IDENTIFYING_FIELDS = ("authorizedkeys", "ipsecpsk")


def _users_body() -> dict:
    return json.loads(USERS_FIXTURE.read_text())


def _users_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _users_body()
    transport.register("GET", "/api/v2/users?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_users_omits_identifying_fields_by_default():
    client, _ = _users_client()
    users = client.get_users()
    assert len(users) == 4
    for user in users:
        for field in USERS_IDENTIFYING_FIELDS:
            assert getattr(user, field) is None


def test_get_users_object_metadata_is_visible_by_default():
    # name/descr/uid/priv/cert are ordinary object metadata (username,
    # description, reference ID, role, certificate reference), not
    # secrets: administrative-usefulness policy keeps them visible
    # without requiring include_identifying_metadata=True.
    client, _ = _users_client()
    raw = _users_body()["data"]
    users = client.get_users()
    assert [u.name for u in users] == [row["name"] for row in raw]
    assert [u.descr for u in users] == [row["descr"] for row in raw]
    assert [u.uid for u in users] == [row["uid"] for row in raw]
    assert [u.priv for u in users] == [row["priv"] for row in raw]
    assert [u.cert for u in users] == [row["cert"] for row in raw]


def test_get_users_includes_identifying_fields_when_requested():
    client, _ = _users_client()
    raw = _users_body()["data"][0]
    users = client.get_users(include_identifying_metadata=True)
    first = users[0]
    assert first.authorizedkeys == raw["authorizedkeys"]
    assert first.ipsecpsk == raw["ipsecpsk"]


def test_get_users_maps_non_sensitive_fields():
    client, _ = _users_client()
    users = client.get_users()
    first = users[0]
    assert first.id == 0
    assert first.disabled is False
    assert first.expires == ""
    assert first.scope == "system"


def test_get_users_only_calls_users_endpoint_with_default_limit():
    client, transport = _users_client()
    client.get_users()
    assert transport.calls == [("GET", "/api/v2/users?limit=100")]


def test_get_users_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _users_body()
    transport.register("GET", "/api/v2/users?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_users(limit=5)
    assert transport.calls == [("GET", "/api/v2/users?limit=5")]


def test_get_users_rejects_zero_limit():
    client, _ = _users_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_users(limit=0)


def test_get_users_rejects_limit_above_max():
    client, _ = _users_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_users(limit=101)


def test_get_users_invalid_limit_never_calls_transport():
    client, transport = _users_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_users(limit=0)
    assert transport.calls == []


def test_get_users_missing_data_key_raises_shape_error():
    body = _users_body()
    del body["data"]
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_users()


def test_get_users_data_wrong_type_raises_shape_error():
    body = _users_body()
    body["data"] = "not-a-list"
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_users()


def test_get_users_item_wrong_type_raises_shape_error():
    body = _users_body()
    body["data"] = ["not-an-object"]
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_users()


def test_get_users_required_field_missing_raises_shape_error():
    body = _users_body()
    del body["data"][0]["name"]
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_users()


def test_get_users_invalid_field_type_raises_shape_error():
    body = _users_body()
    body["data"][0]["disabled"] = "not-a-bool"
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_users()


def test_get_users_shape_error_does_not_leak_raw_field_values():
    body = _users_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["disabled"] = [sentinel]
    client, _ = _users_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_users()
    assert sentinel not in str(excinfo.value)


SYSTEM_CERTIFICATES_FIXTURE = Path(__file__).parent / "fixtures" / "system_certificates_response.json"


def _system_certificates_body() -> dict:
    return json.loads(SYSTEM_CERTIFICATES_FIXTURE.read_text())


def _system_certificates_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_certificates_body()
    transport.register("GET", "/api/v2/system/certificates?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_certificates_maps_fields():
    client, _ = _system_certificates_client()
    raw = _system_certificates_body()["data"]
    certs = client.get_system_certificates()
    assert len(certs) == 2
    assert certs[0].descr == raw[0]["descr"]
    assert certs[0].type == raw[0]["type"]
    assert certs[0].refid == raw[0]["refid"]
    assert certs[0].crt == raw[0]["crt"]
    assert certs[0].valid_days_left == raw[0]["valid_days_left"]


def test_get_system_certificates_only_calls_endpoint_with_default_limit():
    client, transport = _system_certificates_client()
    client.get_system_certificates()
    assert transport.calls == [("GET", "/api/v2/system/certificates?limit=100")]


def test_get_system_certificates_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_certificates_body()
    transport.register("GET", "/api/v2/system/certificates?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_certificates(limit=5)
    assert transport.calls == [("GET", "/api/v2/system/certificates?limit=5")]


def test_get_system_certificates_rejects_zero_limit():
    client, _ = _system_certificates_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_certificates(limit=0)


def test_get_system_certificates_rejects_limit_above_max():
    client, _ = _system_certificates_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_certificates(limit=101)


def test_get_system_certificates_missing_data_key_raises_shape_error():
    body = _system_certificates_body()
    del body["data"]
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificates()


def test_get_system_certificates_data_wrong_type_raises_shape_error():
    body = _system_certificates_body()
    body["data"] = "not-a-list"
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificates()


def test_get_system_certificates_item_wrong_type_raises_shape_error():
    body = _system_certificates_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificates()


def test_get_system_certificates_required_field_missing_raises_shape_error():
    body = _system_certificates_body()
    del body["data"][0]["descr"]
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificates()


def test_get_system_certificates_invalid_field_type_raises_shape_error():
    body = _system_certificates_body()
    body["data"][0]["descr"] = 123
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificates()


def test_get_system_certificates_shape_error_does_not_leak_raw_field_values():
    body = _system_certificates_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _system_certificates_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_certificates()
    assert sentinel not in str(excinfo.value)


USER_GROUPS_FIXTURE = Path(__file__).parent / "fixtures" / "user_groups_response.json"


def _user_groups_body() -> dict:
    return json.loads(USER_GROUPS_FIXTURE.read_text())


def _user_groups_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _user_groups_body()
    transport.register("GET", "/api/v2/user/groups?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_user_groups_maps_fields():
    client, _ = _user_groups_client()
    raw = _user_groups_body()["data"]
    groups = client.get_user_groups()
    assert len(groups) == 2
    assert groups[1].name == raw[1]["name"]
    assert groups[1].description == raw[1]["description"]
    assert groups[1].gid == raw[1]["gid"]
    assert groups[1].member == raw[1]["member"]
    assert groups[1].priv == raw[1]["priv"]
    assert groups[1].scope == raw[1]["scope"]


def test_get_user_groups_only_calls_endpoint_with_default_limit():
    client, transport = _user_groups_client()
    client.get_user_groups()
    assert transport.calls == [("GET", "/api/v2/user/groups?limit=100")]


def test_get_user_groups_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _user_groups_body()
    transport.register("GET", "/api/v2/user/groups?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_user_groups(limit=5)
    assert transport.calls == [("GET", "/api/v2/user/groups?limit=5")]


def test_get_user_groups_rejects_zero_limit():
    client, _ = _user_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_user_groups(limit=0)


def test_get_user_groups_rejects_limit_above_max():
    client, _ = _user_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_user_groups(limit=101)


def test_get_user_groups_missing_data_key_raises_shape_error():
    body = _user_groups_body()
    del body["data"]
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_user_groups()


def test_get_user_groups_data_wrong_type_raises_shape_error():
    body = _user_groups_body()
    body["data"] = "not-a-list"
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_user_groups()


def test_get_user_groups_item_wrong_type_raises_shape_error():
    body = _user_groups_body()
    body["data"] = ["not-an-object"]
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_user_groups()


def test_get_user_groups_required_field_missing_raises_shape_error():
    body = _user_groups_body()
    del body["data"][0]["name"]
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_user_groups()


def test_get_user_groups_invalid_field_type_raises_shape_error():
    body = _user_groups_body()
    body["data"][0]["name"] = 123
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_user_groups()


def test_get_user_groups_shape_error_does_not_leak_raw_field_values():
    body = _user_groups_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _user_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_user_groups()
    assert sentinel not in str(excinfo.value)


STATUS_DHCP_LEASES_FIXTURE = Path(__file__).parent / "fixtures" / "status_dhcp_server_leases_response.json"


def _dhcp_leases_body() -> dict:
    return json.loads(STATUS_DHCP_LEASES_FIXTURE.read_text())


def _dhcp_leases_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_leases_body()
    transport.register("GET", "/api/v2/status/dhcp_server/leases?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_leases_maps_fields():
    client, _ = _dhcp_leases_client()
    raw = _dhcp_leases_body()["data"]
    leases = client.get_dhcp_leases()
    assert len(leases) == 5
    assert leases[0].ip == raw[0]["ip"]
    assert leases[0].mac == raw[0]["mac"]
    assert leases[0].hostname == raw[0]["hostname"]
    assert leases[0].descr == raw[0]["descr"]
    assert leases[0].if_ == raw[0]["if"]
    assert leases[0].active_status == raw[0]["active_status"]
    assert leases[0].online_status == raw[0]["online_status"]


def test_get_dhcp_leases_only_calls_endpoint_with_default_limit():
    client, transport = _dhcp_leases_client()
    client.get_dhcp_leases()
    assert transport.calls == [("GET", "/api/v2/status/dhcp_server/leases?limit=100")]


def test_get_dhcp_leases_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dhcp_leases_body()
    transport.register("GET", "/api/v2/status/dhcp_server/leases?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dhcp_leases(limit=2)
    assert transport.calls == [("GET", "/api/v2/status/dhcp_server/leases?limit=2")]


def test_get_dhcp_leases_rejects_zero_limit():
    client, _ = _dhcp_leases_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_leases(limit=0)


def test_get_dhcp_leases_rejects_limit_above_max():
    client, _ = _dhcp_leases_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_leases(limit=101)


def test_get_dhcp_leases_missing_data_key_raises_shape_error():
    body = _dhcp_leases_body()
    del body["data"]
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_leases()


def test_get_dhcp_leases_data_wrong_type_raises_shape_error():
    body = _dhcp_leases_body()
    body["data"] = "not-a-list"
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_leases()


def test_get_dhcp_leases_item_wrong_type_raises_shape_error():
    body = _dhcp_leases_body()
    body["data"] = ["not-an-object"]
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_leases()


def test_get_dhcp_leases_required_field_missing_raises_shape_error():
    body = _dhcp_leases_body()
    del body["data"][0]["id"]
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_leases()


def test_get_dhcp_leases_invalid_field_type_raises_shape_error():
    body = _dhcp_leases_body()
    body["data"][0]["id"] = "not-a-number"
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_leases()


def test_get_dhcp_leases_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_leases_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["id"] = [sentinel]
    client, _ = _dhcp_leases_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_leases()
    assert sentinel not in str(excinfo.value)


DHCP_STATIC_MAPPINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_dhcp_server_static_mappings_response.json"


def _dhcp_static_mappings_body() -> dict:
    return json.loads(DHCP_STATIC_MAPPINGS_FIXTURE.read_text())


def _dhcp_static_mappings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_static_mappings_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/static_mappings?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_static_mappings_maps_fields():
    client, _ = _dhcp_static_mappings_client()
    raw = _dhcp_static_mappings_body()["data"]
    mappings = client.get_dhcp_static_mappings()
    assert len(mappings) == 5
    assert mappings[0].mac == raw[0]["mac"]
    assert mappings[0].ipaddr == raw[0]["ipaddr"]
    assert mappings[0].hostname == raw[0]["hostname"]
    assert mappings[0].descr == raw[0]["descr"]
    assert mappings[0].parent_id == raw[0]["parent_id"]
    assert mappings[0].arp_table_static_entry == raw[0]["arp_table_static_entry"]


def test_get_dhcp_static_mappings_only_calls_endpoint_with_default_limit():
    client, transport = _dhcp_static_mappings_client()
    client.get_dhcp_static_mappings()
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/static_mappings?limit=100")]


def test_get_dhcp_static_mappings_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dhcp_static_mappings_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/static_mappings?limit=2", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dhcp_static_mappings(limit=2)
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/static_mappings?limit=2")]


def test_get_dhcp_static_mappings_rejects_zero_limit():
    client, _ = _dhcp_static_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_static_mappings(limit=0)


def test_get_dhcp_static_mappings_rejects_limit_above_max():
    client, _ = _dhcp_static_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_static_mappings(limit=101)


def test_get_dhcp_static_mappings_missing_data_key_raises_shape_error():
    body = _dhcp_static_mappings_body()
    del body["data"]
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_static_mappings()


def test_get_dhcp_static_mappings_data_wrong_type_raises_shape_error():
    body = _dhcp_static_mappings_body()
    body["data"] = "not-a-list"
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_static_mappings()


def test_get_dhcp_static_mappings_item_wrong_type_raises_shape_error():
    body = _dhcp_static_mappings_body()
    body["data"] = ["not-an-object"]
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_static_mappings()


def test_get_dhcp_static_mappings_required_field_missing_raises_shape_error():
    body = _dhcp_static_mappings_body()
    del body["data"][0]["mac"]
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_static_mappings()


def test_get_dhcp_static_mappings_invalid_field_type_raises_shape_error():
    body = _dhcp_static_mappings_body()
    body["data"][0]["mac"] = 123
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_static_mappings()


def test_get_dhcp_static_mappings_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_static_mappings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["mac"] = [sentinel]
    client, _ = _dhcp_static_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_static_mappings()
    assert sentinel not in str(excinfo.value)


DHCP_SERVERS_FIXTURE = Path(__file__).parent / "fixtures" / "services_dhcp_servers_response.json"


def _dhcp_servers_body() -> dict:
    return json.loads(DHCP_SERVERS_FIXTURE.read_text())


def _dhcp_servers_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_servers_body()
    transport.register("GET", "/api/v2/services/dhcp_servers?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_servers_maps_fields():
    client, _ = _dhcp_servers_client()
    raw = _dhcp_servers_body()["data"]
    servers = client.get_dhcp_servers()
    assert len(servers) == 2
    assert servers[0].id == raw[0]["id"]
    assert servers[0].interface == raw[0]["interface"]
    assert servers[0].range_from == raw[0]["range_from"]
    assert servers[0].range_to == raw[0]["range_to"]
    assert servers[0].enable == raw[0]["enable"]
    assert servers[0].staticmap == raw[0]["staticmap"]
    assert servers[1].dnsserver == raw[1]["dnsserver"]
    assert servers[1].mac_deny == raw[1]["mac_deny"]


def test_get_dhcp_servers_only_calls_endpoint_with_default_limit():
    client, transport = _dhcp_servers_client()
    client.get_dhcp_servers()
    assert transport.calls == [("GET", "/api/v2/services/dhcp_servers?limit=100")]


def test_get_dhcp_servers_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dhcp_servers_body()
    transport.register("GET", "/api/v2/services/dhcp_servers?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dhcp_servers(limit=2)
    assert transport.calls == [("GET", "/api/v2/services/dhcp_servers?limit=2")]


def test_get_dhcp_servers_rejects_zero_limit():
    client, _ = _dhcp_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_servers(limit=0)


def test_get_dhcp_servers_rejects_limit_above_max():
    client, _ = _dhcp_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_servers(limit=101)


def test_get_dhcp_servers_missing_data_key_raises_shape_error():
    body = _dhcp_servers_body()
    del body["data"]
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_servers()


def test_get_dhcp_servers_data_wrong_type_raises_shape_error():
    body = _dhcp_servers_body()
    body["data"] = "not-a-list"
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_servers()


def test_get_dhcp_servers_item_wrong_type_raises_shape_error():
    body = _dhcp_servers_body()
    body["data"] = ["not-an-object"]
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_servers()


def test_get_dhcp_servers_required_field_missing_raises_shape_error():
    body = _dhcp_servers_body()
    del body["data"][0]["id"]
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_servers()


def test_get_dhcp_servers_invalid_field_type_raises_shape_error():
    body = _dhcp_servers_body()
    body["data"][0]["id"] = 123
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_servers()


def test_get_dhcp_servers_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_servers_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["id"] = [sentinel]
    client, _ = _dhcp_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_servers()
    assert sentinel not in str(excinfo.value)


INTERFACE_BRIDGES_FIXTURE = Path(__file__).parent / "fixtures" / "interface_bridges_response.json"


def _interface_bridges_body() -> dict:
    return json.loads(INTERFACE_BRIDGES_FIXTURE.read_text())


def _interface_bridges_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_bridges_body()
    transport.register("GET", "/api/v2/interface/bridges?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_bridges_maps_fields():
    client, _ = _interface_bridges_client()
    raw = _interface_bridges_body()["data"]
    bridges = client.get_interface_bridges()
    assert len(bridges) == 1
    assert bridges[0].bridgeif == raw[0]["bridgeif"]
    assert bridges[0].members == raw[0]["members"]
    assert bridges[0].descr == raw[0]["descr"]


def test_get_interface_bridges_only_calls_endpoint_with_default_limit():
    client, transport = _interface_bridges_client()
    client.get_interface_bridges()
    assert transport.calls == [("GET", "/api/v2/interface/bridges?limit=100")]


def test_get_interface_bridges_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_bridges_body()
    transport.register("GET", "/api/v2/interface/bridges?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_bridges(limit=2)
    assert transport.calls == [("GET", "/api/v2/interface/bridges?limit=2")]


def test_get_interface_bridges_rejects_zero_limit():
    client, _ = _interface_bridges_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_bridges(limit=0)


def test_get_interface_bridges_rejects_limit_above_max():
    client, _ = _interface_bridges_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_bridges(limit=101)


def test_get_interface_bridges_missing_data_key_raises_shape_error():
    body = _interface_bridges_body()
    del body["data"]
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_bridges()


def test_get_interface_bridges_data_wrong_type_raises_shape_error():
    body = _interface_bridges_body()
    body["data"] = "not-a-list"
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_bridges()


def test_get_interface_bridges_item_wrong_type_raises_shape_error():
    body = _interface_bridges_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_bridges()


def test_get_interface_bridges_required_field_missing_raises_shape_error():
    body = _interface_bridges_body()
    del body["data"][0]["members"]
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_bridges()


def test_get_interface_bridges_invalid_field_type_raises_shape_error():
    body = _interface_bridges_body()
    body["data"][0]["members"] = 123
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_bridges()


def test_get_interface_bridges_shape_error_does_not_leak_raw_field_values():
    body = _interface_bridges_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["bridgeif"] = [sentinel]
    client, _ = _interface_bridges_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_bridges()
    assert sentinel not in str(excinfo.value)


STATUS_CARP_FIXTURE = Path(__file__).parent / "fixtures" / "status_carp_response.json"


def _status_carp_body() -> dict:
    return json.loads(STATUS_CARP_FIXTURE.read_text())


def _status_carp_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_carp_body()
    transport.register("GET", "/api/v2/status/carp", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_carp_status_maps_fields():
    client, _ = _status_carp_client()
    raw = _status_carp_body()["data"]
    status = client.get_carp_status()
    assert status.enable == raw["enable"]
    assert status.maintenance_mode == raw["maintenance_mode"]


def test_get_carp_status_only_calls_carp_endpoint():
    client, transport = _status_carp_client()
    client.get_carp_status()
    assert transport.calls == [("GET", "/api/v2/status/carp")]


def test_get_carp_status_missing_data_key_raises_shape_error():
    body = _status_carp_body()
    del body["data"]
    client, _ = _status_carp_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_carp_status()


def test_get_carp_status_data_wrong_type_raises_shape_error():
    body = _status_carp_body()
    body["data"] = "not-an-object"
    client, _ = _status_carp_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_carp_status()


def test_get_carp_status_required_field_missing_raises_shape_error():
    body = _status_carp_body()
    del body["data"]["enable"]
    client, _ = _status_carp_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_carp_status()


def test_get_carp_status_invalid_field_type_raises_shape_error():
    body = _status_carp_body()
    body["data"]["maintenance_mode"] = "not-a-bool"
    client, _ = _status_carp_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_carp_status()


def test_get_carp_status_shape_error_does_not_leak_raw_field_values():
    body = _status_carp_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["maintenance_mode"] = sentinel
    client, _ = _status_carp_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_carp_status()
    assert sentinel not in str(excinfo.value)


SYSTEM_RESTAPI_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "system_restapi_settings_response.json"
SYSTEM_RESTAPI_SETTINGS_IDENTIFYING_FIELDS = ("ha_sync_username",)


def _system_restapi_settings_body() -> dict:
    return json.loads(SYSTEM_RESTAPI_SETTINGS_FIXTURE.read_text())


def _system_restapi_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_restapi_settings_body()
    transport.register("GET", "/api/v2/system/restapi/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_restapi_settings_omits_identifying_fields_by_default():
    client, _ = _system_restapi_settings_client()
    settings = client.get_system_restapi_settings()
    for field in SYSTEM_RESTAPI_SETTINGS_IDENTIFYING_FIELDS:
        assert getattr(settings, field) is None


def test_get_system_restapi_settings_object_metadata_is_visible_by_default():
    client, _ = _system_restapi_settings_client()
    raw = _system_restapi_settings_body()["data"]
    settings = client.get_system_restapi_settings()
    assert settings.enabled == raw["enabled"]
    assert settings.auth_methods == raw["auth_methods"]
    assert settings.allowed_interfaces == raw["allowed_interfaces"]
    assert settings.jwt_exp == raw["jwt_exp"]
    assert settings.log_level == raw["log_level"]


def test_get_system_restapi_settings_includes_identifying_fields_when_requested():
    client, _ = _system_restapi_settings_client()
    raw = _system_restapi_settings_body()["data"]
    settings = client.get_system_restapi_settings(include_identifying_metadata=True)
    assert settings.ha_sync_username == raw["ha_sync_username"]


def test_get_system_restapi_settings_only_calls_settings_endpoint():
    client, transport = _system_restapi_settings_client()
    client.get_system_restapi_settings()
    assert transport.calls == [("GET", "/api/v2/system/restapi/settings")]


def test_get_system_restapi_settings_missing_data_key_raises_shape_error():
    body = _system_restapi_settings_body()
    del body["data"]
    client, _ = _system_restapi_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_settings()


def test_get_system_restapi_settings_data_wrong_type_raises_shape_error():
    body = _system_restapi_settings_body()
    body["data"] = "not-an-object"
    client, _ = _system_restapi_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_settings()


def test_get_system_restapi_settings_required_field_missing_raises_shape_error():
    body = _system_restapi_settings_body()
    del body["data"]["enabled"]
    client, _ = _system_restapi_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_settings()


def test_get_system_restapi_settings_invalid_field_type_raises_shape_error():
    body = _system_restapi_settings_body()
    body["data"]["jwt_exp"] = "not-an-int"
    client, _ = _system_restapi_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_settings()


def test_get_system_restapi_settings_shape_error_does_not_leak_raw_field_values():
    body = _system_restapi_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["jwt_exp"] = sentinel
    client, _ = _system_restapi_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_restapi_settings()
    assert sentinel not in str(excinfo.value)


SYSTEM_HASYNC_FIXTURE = Path(__file__).parent / "fixtures" / "system_hasync_response.json"
SYSTEM_HASYNC_IDENTIFYING_FIELDS = ("username", "pfhostid")


def _system_hasync_body() -> dict:
    return json.loads(SYSTEM_HASYNC_FIXTURE.read_text())


def _system_hasync_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_hasync_body()
    transport.register("GET", "/api/v2/system/hasync", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_hasync_omits_identifying_fields_by_default():
    client, _ = _system_hasync_client()
    hasync = client.get_system_hasync()
    for field in SYSTEM_HASYNC_IDENTIFYING_FIELDS:
        assert getattr(hasync, field) is None


def test_get_system_hasync_object_metadata_is_visible_by_default():
    client, _ = _system_hasync_client()
    raw = _system_hasync_body()["data"]
    hasync = client.get_system_hasync()
    assert hasync.pfsyncenabled == raw["pfsyncenabled"]
    assert hasync.pfsyncinterface == raw["pfsyncinterface"]
    assert hasync.pfsyncpeerip == raw["pfsyncpeerip"]
    assert hasync.synchronizerules == raw["synchronizerules"]


def test_get_system_hasync_includes_identifying_fields_when_requested():
    client, _ = _system_hasync_client()
    raw = _system_hasync_body()["data"]
    hasync = client.get_system_hasync(include_identifying_metadata=True)
    assert hasync.username == raw["username"]
    assert hasync.pfhostid == raw["pfhostid"]


def test_get_system_hasync_only_calls_hasync_endpoint():
    client, transport = _system_hasync_client()
    client.get_system_hasync()
    assert transport.calls == [("GET", "/api/v2/system/hasync")]


def test_get_system_hasync_missing_data_key_raises_shape_error():
    body = _system_hasync_body()
    del body["data"]
    client, _ = _system_hasync_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hasync()


def test_get_system_hasync_data_wrong_type_raises_shape_error():
    body = _system_hasync_body()
    body["data"] = "not-an-object"
    client, _ = _system_hasync_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hasync()


def test_get_system_hasync_required_field_missing_raises_shape_error():
    body = _system_hasync_body()
    del body["data"]["pfsyncenabled"]
    client, _ = _system_hasync_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hasync()


def test_get_system_hasync_invalid_field_type_raises_shape_error():
    body = _system_hasync_body()
    body["data"]["pfsyncenabled"] = "not-a-bool"
    client, _ = _system_hasync_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hasync()


def test_get_system_hasync_shape_error_does_not_leak_raw_field_values():
    body = _system_hasync_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["pfsyncenabled"] = sentinel
    client, _ = _system_hasync_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_hasync()
    assert sentinel not in str(excinfo.value)


DNS_RESOLVER_HOST_OVERRIDES_FIXTURE = (
    Path(__file__).parent / "fixtures" / "services_dns_resolver_host_overrides_response.json"
)


def _dns_resolver_host_overrides_body() -> dict:
    return json.loads(DNS_RESOLVER_HOST_OVERRIDES_FIXTURE.read_text())


def _dns_resolver_host_overrides_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dns_resolver_host_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/host_overrides?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dns_resolver_host_overrides_maps_fields():
    client, _ = _dns_resolver_host_overrides_client()
    raw = _dns_resolver_host_overrides_body()["data"]
    overrides = client.get_dns_resolver_host_overrides()
    assert len(overrides) == 1
    assert overrides[0].host == raw[0]["host"]
    assert overrides[0].domain == raw[0]["domain"]
    assert overrides[0].descr == raw[0]["descr"]
    assert overrides[0].ip == raw[0]["ip"]
    assert overrides[0].aliases == raw[0]["aliases"]


def test_get_dns_resolver_host_overrides_only_calls_endpoint_with_default_limit():
    client, transport = _dns_resolver_host_overrides_client()
    client.get_dns_resolver_host_overrides()
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/host_overrides?limit=100")]


def test_get_dns_resolver_host_overrides_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dns_resolver_host_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/host_overrides?limit=2", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dns_resolver_host_overrides(limit=2)
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/host_overrides?limit=2")]


def test_get_dns_resolver_host_overrides_rejects_zero_limit():
    client, _ = _dns_resolver_host_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_host_overrides(limit=0)


def test_get_dns_resolver_host_overrides_rejects_limit_above_max():
    client, _ = _dns_resolver_host_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_host_overrides(limit=101)


def test_get_dns_resolver_host_overrides_missing_data_key_raises_shape_error():
    body = _dns_resolver_host_overrides_body()
    del body["data"]
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_host_overrides()


def test_get_dns_resolver_host_overrides_data_wrong_type_raises_shape_error():
    body = _dns_resolver_host_overrides_body()
    body["data"] = "not-a-list"
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_host_overrides()


def test_get_dns_resolver_host_overrides_item_wrong_type_raises_shape_error():
    body = _dns_resolver_host_overrides_body()
    body["data"] = ["not-an-object"]
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_host_overrides()


def test_get_dns_resolver_host_overrides_required_field_missing_raises_shape_error():
    body = _dns_resolver_host_overrides_body()
    del body["data"][0]["host"]
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_host_overrides()


def test_get_dns_resolver_host_overrides_invalid_field_type_raises_shape_error():
    body = _dns_resolver_host_overrides_body()
    body["data"][0]["ip"] = 123
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_host_overrides()


def test_get_dns_resolver_host_overrides_shape_error_does_not_leak_raw_field_values():
    body = _dns_resolver_host_overrides_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["host"] = [sentinel]
    client, _ = _dns_resolver_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dns_resolver_host_overrides()
    assert sentinel not in str(excinfo.value)


DNS_RESOLVER_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_dns_resolver_settings_response.json"


def _dns_resolver_settings_body() -> dict:
    return json.loads(DNS_RESOLVER_SETTINGS_FIXTURE.read_text())


def _dns_resolver_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dns_resolver_settings_body()
    transport.register("GET", "/api/v2/services/dns_resolver/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dns_resolver_settings_maps_fields():
    client, _ = _dns_resolver_settings_client()
    raw = _dns_resolver_settings_body()["data"]
    settings = client.get_dns_resolver_settings()
    assert settings.enable == raw["enable"]
    assert settings.dnssec == raw["dnssec"]
    assert settings.active_interface == raw["active_interface"]
    assert settings.outgoing_interface == raw["outgoing_interface"]
    assert settings.sslcertref == raw["sslcertref"]


def test_get_dns_resolver_settings_only_calls_settings_endpoint():
    client, transport = _dns_resolver_settings_client()
    client.get_dns_resolver_settings()
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/settings")]


def test_get_dns_resolver_settings_missing_data_key_raises_shape_error():
    body = _dns_resolver_settings_body()
    del body["data"]
    client, _ = _dns_resolver_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_settings()


def test_get_dns_resolver_settings_data_wrong_type_raises_shape_error():
    body = _dns_resolver_settings_body()
    body["data"] = "not-an-object"
    client, _ = _dns_resolver_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_settings()


def test_get_dns_resolver_settings_required_field_missing_raises_shape_error():
    body = _dns_resolver_settings_body()
    del body["data"]["enable"]
    client, _ = _dns_resolver_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_settings()


def test_get_dns_resolver_settings_invalid_field_type_raises_shape_error():
    body = _dns_resolver_settings_body()
    body["data"]["active_interface"] = 123
    client, _ = _dns_resolver_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_settings()


def test_get_dns_resolver_settings_shape_error_does_not_leak_raw_field_values():
    body = _dns_resolver_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["sslcertref"] = [sentinel]
    client, _ = _dns_resolver_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dns_resolver_settings()
    assert sentinel not in str(excinfo.value)


ARP_TABLE_FIXTURE = Path(__file__).parent / "fixtures" / "diagnostics_arp_table_response.json"


def _arp_table_body() -> dict:
    return json.loads(ARP_TABLE_FIXTURE.read_text())


def _arp_table_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _arp_table_body()
    transport.register("GET", "/api/v2/diagnostics/arp_table?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_arp_table_maps_fields():
    client, _ = _arp_table_client()
    raw = _arp_table_body()["data"]
    entries = client.get_arp_table()
    assert len(entries) == 5
    assert entries[0].hostname == raw[0]["hostname"]
    assert entries[0].ip_address == raw[0]["ip_address"]
    assert entries[0].mac_address == raw[0]["mac_address"]
    assert entries[0].interface == raw[0]["interface"]


def test_get_arp_table_only_calls_endpoint_with_default_limit():
    client, transport = _arp_table_client()
    client.get_arp_table()
    assert transport.calls == [("GET", "/api/v2/diagnostics/arp_table?limit=100")]


def test_get_arp_table_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _arp_table_body()
    transport.register("GET", "/api/v2/diagnostics/arp_table?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_arp_table(limit=2)
    assert transport.calls == [("GET", "/api/v2/diagnostics/arp_table?limit=2")]


def test_get_arp_table_rejects_zero_limit():
    client, _ = _arp_table_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_arp_table(limit=0)


def test_get_arp_table_rejects_limit_above_max():
    client, _ = _arp_table_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_arp_table(limit=101)


def test_get_arp_table_missing_data_key_raises_shape_error():
    body = _arp_table_body()
    del body["data"]
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_arp_table()


def test_get_arp_table_data_wrong_type_raises_shape_error():
    body = _arp_table_body()
    body["data"] = "not-a-list"
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_arp_table()


def test_get_arp_table_item_wrong_type_raises_shape_error():
    body = _arp_table_body()
    body["data"] = ["not-an-object"]
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_arp_table()


def test_get_arp_table_required_field_missing_raises_shape_error():
    body = _arp_table_body()
    del body["data"][0]["ip_address"]
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_arp_table()


def test_get_arp_table_invalid_field_type_raises_shape_error():
    body = _arp_table_body()
    body["data"][0]["permanent"] = "not-a-bool"
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_arp_table()


def test_get_arp_table_shape_error_does_not_leak_raw_field_values():
    body = _arp_table_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["ip_address"] = [sentinel]
    client, _ = _arp_table_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_arp_table()
    assert sentinel not in str(excinfo.value)


TRAFFIC_SHAPER_LIMITERS_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_traffic_shaper_limiters_response.json"


def _traffic_shaper_limiters_body() -> dict:
    return json.loads(TRAFFIC_SHAPER_LIMITERS_FIXTURE.read_text())


def _traffic_shaper_limiters_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _traffic_shaper_limiters_body()
    transport.register(
        "GET", "/api/v2/firewall/traffic_shaper/limiters?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_traffic_shaper_limiters_maps_fields():
    client, _ = _traffic_shaper_limiters_client()
    raw = _traffic_shaper_limiters_body()["data"]
    limiters = client.get_firewall_traffic_shaper_limiters()
    assert len(limiters) == 2
    assert limiters[0].name == raw[0]["name"]
    assert limiters[0].aqm == raw[0]["aqm"]
    assert limiters[0].sched == raw[0]["sched"]
    assert limiters[0].bandwidth == raw[0]["bandwidth"]


def test_get_firewall_traffic_shaper_limiters_only_calls_endpoint_with_default_limit():
    client, transport = _traffic_shaper_limiters_client()
    client.get_firewall_traffic_shaper_limiters()
    assert transport.calls == [("GET", "/api/v2/firewall/traffic_shaper/limiters?limit=100")]


def test_get_firewall_traffic_shaper_limiters_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _traffic_shaper_limiters_body()
    transport.register(
        "GET", "/api/v2/firewall/traffic_shaper/limiters?limit=2", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_traffic_shaper_limiters(limit=2)
    assert transport.calls == [("GET", "/api/v2/firewall/traffic_shaper/limiters?limit=2")]


def test_get_firewall_traffic_shaper_limiters_rejects_zero_limit():
    client, _ = _traffic_shaper_limiters_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_traffic_shaper_limiters(limit=0)


def test_get_firewall_traffic_shaper_limiters_rejects_limit_above_max():
    client, _ = _traffic_shaper_limiters_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_traffic_shaper_limiters(limit=101)


def test_get_firewall_traffic_shaper_limiters_missing_data_key_raises_shape_error():
    body = _traffic_shaper_limiters_body()
    del body["data"]
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_traffic_shaper_limiters()


def test_get_firewall_traffic_shaper_limiters_data_wrong_type_raises_shape_error():
    body = _traffic_shaper_limiters_body()
    body["data"] = "not-a-list"
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_traffic_shaper_limiters()


def test_get_firewall_traffic_shaper_limiters_item_wrong_type_raises_shape_error():
    body = _traffic_shaper_limiters_body()
    body["data"] = ["not-an-object"]
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_traffic_shaper_limiters()


def test_get_firewall_traffic_shaper_limiters_required_field_missing_raises_shape_error():
    body = _traffic_shaper_limiters_body()
    del body["data"][0]["sched"]
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_traffic_shaper_limiters()


def test_get_firewall_traffic_shaper_limiters_invalid_field_type_raises_shape_error():
    body = _traffic_shaper_limiters_body()
    body["data"][0]["enabled"] = "not-a-bool"
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_traffic_shaper_limiters()


def test_get_firewall_traffic_shaper_limiters_shape_error_does_not_leak_raw_field_values():
    body = _traffic_shaper_limiters_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _traffic_shaper_limiters_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_traffic_shaper_limiters()
    assert sentinel not in str(excinfo.value)


FIREWALL_ADVANCED_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_advanced_settings_response.json"


def _firewall_advanced_settings_body() -> dict:
    return json.loads(FIREWALL_ADVANCED_SETTINGS_FIXTURE.read_text())


def _firewall_advanced_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_advanced_settings_body()
    transport.register("GET", "/api/v2/firewall/advanced_settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_advanced_settings_maps_fields():
    client, _ = _firewall_advanced_settings_client()
    settings = client.get_firewall_advanced_settings()
    assert settings.aliasesresolveinterval is None
    assert settings.checkaliasesurlcert is False


def test_get_firewall_advanced_settings_only_calls_settings_endpoint():
    client, transport = _firewall_advanced_settings_client()
    client.get_firewall_advanced_settings()
    assert transport.calls == [("GET", "/api/v2/firewall/advanced_settings")]


def test_get_firewall_advanced_settings_missing_data_key_raises_shape_error():
    body = _firewall_advanced_settings_body()
    del body["data"]
    client, _ = _firewall_advanced_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_advanced_settings()


def test_get_firewall_advanced_settings_data_wrong_type_raises_shape_error():
    body = _firewall_advanced_settings_body()
    body["data"] = "not-an-object"
    client, _ = _firewall_advanced_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_advanced_settings()


def test_get_firewall_advanced_settings_required_field_missing_raises_shape_error():
    body = _firewall_advanced_settings_body()
    del body["data"]["checkaliasesurlcert"]
    client, _ = _firewall_advanced_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_advanced_settings()


def test_get_firewall_advanced_settings_invalid_field_type_raises_shape_error():
    body = _firewall_advanced_settings_body()
    body["data"]["checkaliasesurlcert"] = "not-a-bool"
    client, _ = _firewall_advanced_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_advanced_settings()


def test_get_firewall_advanced_settings_shape_error_does_not_leak_raw_field_values():
    body = _firewall_advanced_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["checkaliasesurlcert"] = [sentinel]
    client, _ = _firewall_advanced_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_advanced_settings()
    assert sentinel not in str(excinfo.value)


SYSTEM_PACKAGES_FIXTURE = Path(__file__).parent / "fixtures" / "system_packages_response.json"


def _system_packages_body() -> dict:
    return json.loads(SYSTEM_PACKAGES_FIXTURE.read_text())


def _system_packages_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_packages_body()
    transport.register("GET", "/api/v2/system/packages?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_packages_maps_fields():
    client, _ = _system_packages_client()
    raw = _system_packages_body()["data"]
    packages = client.get_system_packages()
    assert len(packages) == len(raw)
    assert packages[0].name == raw[0]["name"]
    assert packages[0].descr == raw[0]["descr"]
    assert packages[0].installed_version == raw[0]["installed_version"]


def test_get_system_packages_only_calls_endpoint_with_default_limit():
    client, transport = _system_packages_client()
    client.get_system_packages()
    assert transport.calls == [("GET", "/api/v2/system/packages?limit=100")]


def test_get_system_packages_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_packages_body()
    transport.register("GET", "/api/v2/system/packages?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_packages(limit=2)
    assert transport.calls == [("GET", "/api/v2/system/packages?limit=2")]


def test_get_system_packages_rejects_zero_limit():
    client, _ = _system_packages_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_packages(limit=0)


def test_get_system_packages_rejects_limit_above_max():
    client, _ = _system_packages_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_packages(limit=101)


def test_get_system_packages_missing_data_key_raises_shape_error():
    body = _system_packages_body()
    del body["data"]
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_packages()


def test_get_system_packages_data_wrong_type_raises_shape_error():
    body = _system_packages_body()
    body["data"] = "not-a-list"
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_packages()


def test_get_system_packages_item_wrong_type_raises_shape_error():
    body = _system_packages_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_packages()


def test_get_system_packages_required_field_missing_raises_shape_error():
    body = _system_packages_body()
    del body["data"][0]["name"]
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_packages()


def test_get_system_packages_invalid_field_type_raises_shape_error():
    body = _system_packages_body()
    body["data"][0]["update_available"] = "not-a-bool"
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_packages()


def test_get_system_packages_shape_error_does_not_leak_raw_field_values():
    body = _system_packages_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _system_packages_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_packages()
    assert sentinel not in str(excinfo.value)


SYSTEM_TUNABLES_FIXTURE = Path(__file__).parent / "fixtures" / "system_tunables_response.json"


def _system_tunables_body() -> dict:
    return json.loads(SYSTEM_TUNABLES_FIXTURE.read_text())


def _system_tunables_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_tunables_body()
    transport.register("GET", "/api/v2/system/tunables?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_tunables_maps_fields():
    client, _ = _system_tunables_client()
    raw = _system_tunables_body()["data"]
    tunables = client.get_system_tunables()
    assert len(tunables) == len(raw)
    assert tunables[0].tunable == raw[0]["tunable"]
    assert tunables[0].descr == raw[0]["descr"]
    assert tunables[0].value == raw[0]["value"]


def test_get_system_tunables_only_calls_endpoint_with_default_limit():
    client, transport = _system_tunables_client()
    client.get_system_tunables()
    assert transport.calls == [("GET", "/api/v2/system/tunables?limit=100")]


def test_get_system_tunables_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_tunables_body()
    transport.register("GET", "/api/v2/system/tunables?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_tunables(limit=2)
    assert transport.calls == [("GET", "/api/v2/system/tunables?limit=2")]


def test_get_system_tunables_rejects_zero_limit():
    client, _ = _system_tunables_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_tunables(limit=0)


def test_get_system_tunables_rejects_limit_above_max():
    client, _ = _system_tunables_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_tunables(limit=101)


def test_get_system_tunables_missing_data_key_raises_shape_error():
    body = _system_tunables_body()
    del body["data"]
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_tunables()


def test_get_system_tunables_data_wrong_type_raises_shape_error():
    body = _system_tunables_body()
    body["data"] = "not-a-list"
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_tunables()


def test_get_system_tunables_item_wrong_type_raises_shape_error():
    body = _system_tunables_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_tunables()


def test_get_system_tunables_required_field_missing_raises_shape_error():
    body = _system_tunables_body()
    del body["data"][0]["tunable"]
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_tunables()


def test_get_system_tunables_invalid_field_type_raises_shape_error():
    body = _system_tunables_body()
    body["data"][0]["value"] = 123
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_tunables()


def test_get_system_tunables_shape_error_does_not_leak_raw_field_values():
    body = _system_tunables_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["tunable"] = [sentinel]
    client, _ = _system_tunables_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_tunables()
    assert sentinel not in str(excinfo.value)


EMAIL_NOTIFICATION_SETTINGS_FIXTURE = (
    Path(__file__).parent / "fixtures" / "system_notifications_email_settings_response.json"
)
EMAIL_NOTIFICATION_SETTINGS_IDENTIFYING_FIELDS = (
    "username",
    "password",
    "fromaddress",
    "notifyemailaddress",
    "ipaddress",
)


def _email_notification_settings_body() -> dict:
    return json.loads(EMAIL_NOTIFICATION_SETTINGS_FIXTURE.read_text())


def _email_notification_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _email_notification_settings_body()
    transport.register("GET", "/api/v2/system/notifications/email_settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_email_notification_settings_omits_identifying_fields_by_default():
    client, _ = _email_notification_settings_client()
    settings = client.get_email_notification_settings()
    for field in EMAIL_NOTIFICATION_SETTINGS_IDENTIFYING_FIELDS:
        assert getattr(settings, field) is None


def test_get_email_notification_settings_object_metadata_is_visible_by_default():
    client, _ = _email_notification_settings_client()
    raw = _email_notification_settings_body()["data"]
    settings = client.get_email_notification_settings()
    assert settings.authentication_mechanism == raw["authentication_mechanism"]
    assert settings.disable == raw["disable"]
    assert settings.port == raw["port"]
    assert settings.ssl == raw["ssl"]
    assert settings.sslvalidate == raw["sslvalidate"]
    assert settings.timeout == raw["timeout"]


def test_get_email_notification_settings_includes_identifying_fields_when_requested():
    client, _ = _email_notification_settings_client()
    raw = _email_notification_settings_body()["data"]
    settings = client.get_email_notification_settings(include_identifying_metadata=True)
    for field in EMAIL_NOTIFICATION_SETTINGS_IDENTIFYING_FIELDS:
        assert getattr(settings, field) == raw[field]


def test_get_email_notification_settings_only_calls_settings_endpoint():
    client, transport = _email_notification_settings_client()
    client.get_email_notification_settings()
    assert transport.calls == [("GET", "/api/v2/system/notifications/email_settings")]


def test_get_email_notification_settings_missing_data_key_raises_shape_error():
    body = _email_notification_settings_body()
    del body["data"]
    client, _ = _email_notification_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_email_notification_settings()


def test_get_email_notification_settings_data_wrong_type_raises_shape_error():
    body = _email_notification_settings_body()
    body["data"] = "not-an-object"
    client, _ = _email_notification_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_email_notification_settings()


def test_get_email_notification_settings_required_field_missing_raises_shape_error():
    body = _email_notification_settings_body()
    del body["data"]["port"]
    client, _ = _email_notification_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_email_notification_settings()


def test_get_email_notification_settings_invalid_field_type_raises_shape_error():
    body = _email_notification_settings_body()
    body["data"]["disable"] = "not-a-bool"
    client, _ = _email_notification_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_email_notification_settings()


def test_get_email_notification_settings_shape_error_does_not_leak_raw_field_values():
    body = _email_notification_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["disable"] = sentinel
    client, _ = _email_notification_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_email_notification_settings()
    assert sentinel not in str(excinfo.value)


BIND_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_bind_settings_response.json"


def _bind_settings_body() -> dict:
    return json.loads(BIND_SETTINGS_FIXTURE.read_text())


def _bind_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _bind_settings_body()
    transport.register("GET", "/api/v2/services/bind/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_bind_settings_maps_fields():
    client, _ = _bind_settings_client()
    raw = _bind_settings_body()["data"]
    settings = client.get_bind_settings()
    assert settings.enable_bind == raw["enable_bind"]
    assert settings.listenport == raw["listenport"]
    assert settings.bind_ram_limit == raw["bind_ram_limit"]
    assert settings.listenon == raw["listenon"]


def test_get_bind_settings_only_calls_settings_endpoint():
    client, transport = _bind_settings_client()
    client.get_bind_settings()
    assert transport.calls == [("GET", "/api/v2/services/bind/settings")]


def test_get_bind_settings_missing_data_key_raises_shape_error():
    body = _bind_settings_body()
    del body["data"]
    client, _ = _bind_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_bind_settings()


def test_get_bind_settings_data_wrong_type_raises_shape_error():
    body = _bind_settings_body()
    body["data"] = "not-an-object"
    client, _ = _bind_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_bind_settings()


def test_get_bind_settings_required_field_missing_raises_shape_error():
    body = _bind_settings_body()
    del body["data"]["enable_bind"]
    client, _ = _bind_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_bind_settings()


def test_get_bind_settings_invalid_field_type_raises_shape_error():
    body = _bind_settings_body()
    body["data"]["enable_bind"] = "not-a-bool"
    client, _ = _bind_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_bind_settings()


def test_get_bind_settings_shape_error_does_not_leak_raw_field_values():
    body = _bind_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["enable_bind"] = sentinel
    client, _ = _bind_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_bind_settings()
    assert sentinel not in str(excinfo.value)
