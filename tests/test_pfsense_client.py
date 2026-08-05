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
