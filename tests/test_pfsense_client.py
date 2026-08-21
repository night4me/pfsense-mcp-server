import json
from pathlib import Path

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import PfSenseRequestValidationError, PfSenseResponseShapeError
from pfsense_mcp.models.system import SystemStatus
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


def test_get_system_status_missing_data_key_raises_shape_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps({"status": "ok"}))
    client = PfSenseClient(RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2))
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_status()
    assert str(excinfo.value) == "pfSense status/system response did not contain 'data'."


def test_get_system_status_data_wrong_type_raises_shape_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps({"data": []}))
    client = PfSenseClient(RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2))
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_status()
    assert str(excinfo.value) == "pfSense status/system response 'data' was not an object."


def test_get_system_status_schema_error_is_sanitized():
    sentinel = "SENTINEL-SYSTEM-STATUS-SECRET"
    body = {"data": {"platform": [sentinel]}}
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    client = PfSenseClient(RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2))
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_status()
    assert str(excinfo.value) == "pfSense status/system response failed schema validation."
    assert sentinel not in str(excinfo.value)


def test_get_system_status_does_not_swallow_unrelated_factory_exception(monkeypatch):
    def raise_unrelated(*args, **kwargs):
        raise RuntimeError("unrelated factory failure")

    monkeypatch.setattr(SystemStatus, "from_api", raise_unrelated)
    with pytest.raises(RuntimeError, match="unrelated factory failure"):
        _client_with_fixture().get_system_status()


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
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interfaces()
    assert str(excinfo.value) == "pfSense status/interfaces response did not contain 'data'."


def test_get_interfaces_data_wrong_type_raises_shape_error():
    body = _interfaces_body()
    body["data"] = "not-a-list"
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interfaces()
    assert str(excinfo.value) == "pfSense status/interfaces response 'data' was not a list."


def test_get_interfaces_item_wrong_type_raises_shape_error():
    body = _interfaces_body()
    body["data"] = ["not-an-object"]
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interfaces()
    assert str(excinfo.value) == "pfSense status/interfaces response contained a non-object entry in 'data'."


def test_get_interfaces_required_field_missing_raises_shape_error():
    body = _interfaces_body()
    del body["data"][0]["inbytes"]
    client, _ = _interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interfaces()
    assert str(excinfo.value) == "pfSense status/interfaces response contained an entry that failed schema validation."


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


FIREWALL_NAT_OUTBOUND_MAPPINGS_FIXTURE = (
    Path(__file__).parent / "fixtures" / "firewall_nat_outbound_mappings_response.json"
)
FIREWALL_NAT_OUTBOUND_MAPPINGS_IDENTIFYING_FIELDS = ("destination", "source", "target")


def _firewall_nat_outbound_mappings_body() -> dict:
    return json.loads(FIREWALL_NAT_OUTBOUND_MAPPINGS_FIXTURE.read_text())


def _firewall_nat_outbound_mappings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_nat_outbound_mappings_body()
    transport.register(
        "GET", "/api/v2/firewall/nat/outbound/mappings?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_nat_outbound_mappings_parses_empty_list():
    """2026-08-20 live production verification observed exactly this
    shape: HTTP 200, `{"data": []}` -- zero outbound NAT mappings
    configured at verification time. Confirms the empty-list case
    (not just populated lists) parses without error."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _firewall_nat_outbound_mappings_client(body)
    assert client.get_firewall_nat_outbound_mappings() == []


def test_get_firewall_nat_outbound_mappings_omits_identifying_fields_by_default():
    client, _ = _firewall_nat_outbound_mappings_client()
    mappings = client.get_firewall_nat_outbound_mappings()
    assert len(mappings) == 2
    for mapping in mappings:
        for field in FIREWALL_NAT_OUTBOUND_MAPPINGS_IDENTIFYING_FIELDS:
            assert getattr(mapping, field) is None


def test_get_firewall_nat_outbound_mappings_includes_identifying_fields_when_requested():
    client, _ = _firewall_nat_outbound_mappings_client()
    mappings = client.get_firewall_nat_outbound_mappings(include_identifying_metadata=True)
    first = next(m for m in mappings if m.id == 0)
    assert first.target == "203.0.113.10"
    assert first.source == "198.51.100.0/24"


def test_get_firewall_nat_outbound_mappings_maps_non_sensitive_fields():
    client, _ = _firewall_nat_outbound_mappings_client()
    mappings = client.get_firewall_nat_outbound_mappings()
    first = next(m for m in mappings if m.id == 0)
    assert first.interface == "wan"
    assert first.protocol == "tcp/udp"
    assert first.disabled is False
    assert first.nonat is False
    assert first.static_nat_port is False
    assert first.target_subnet == 32
    assert first.source_hash_key == "0x15758006d87dc3affc7973c95e378b65"


def test_get_firewall_nat_outbound_mappings_only_calls_endpoint_with_default_limit():
    client, transport = _firewall_nat_outbound_mappings_client()
    client.get_firewall_nat_outbound_mappings()
    assert transport.calls == [("GET", "/api/v2/firewall/nat/outbound/mappings?limit=100")]


def test_get_firewall_nat_outbound_mappings_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_nat_outbound_mappings_body()
    transport.register("GET", "/api/v2/firewall/nat/outbound/mappings?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_nat_outbound_mappings(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/nat/outbound/mappings?limit=5")]


def test_get_firewall_nat_outbound_mappings_rejects_zero_limit():
    client, _ = _firewall_nat_outbound_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_outbound_mappings(limit=0)


def test_get_firewall_nat_outbound_mappings_rejects_limit_above_max():
    client, _ = _firewall_nat_outbound_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_outbound_mappings(limit=501)


def test_get_firewall_nat_outbound_mappings_invalid_limit_never_calls_transport():
    client, transport = _firewall_nat_outbound_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_outbound_mappings(limit=0)
    assert transport.calls == []


def test_get_firewall_nat_outbound_mappings_missing_data_key_raises_shape_error():
    body = _firewall_nat_outbound_mappings_body()
    del body["data"]
    client, _ = _firewall_nat_outbound_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mappings()


def test_get_firewall_nat_outbound_mappings_item_wrong_type_raises_shape_error():
    body = _firewall_nat_outbound_mappings_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_nat_outbound_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mappings()


def test_get_firewall_nat_outbound_mappings_required_field_missing_raises_shape_error():
    body = _firewall_nat_outbound_mappings_body()
    del body["data"][0]["descr"]
    client, _ = _firewall_nat_outbound_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_outbound_mappings()


def test_get_firewall_nat_outbound_mappings_shape_error_does_not_leak_raw_field_values():
    body = _firewall_nat_outbound_mappings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _firewall_nat_outbound_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_nat_outbound_mappings()
    assert sentinel not in str(excinfo.value)


FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_FIXTURE = (
    Path(__file__).parent / "fixtures" / "firewall_nat_one_to_one_mappings_response.json"
)
FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_IDENTIFYING_FIELDS = ("destination", "external", "source")


def _firewall_nat_one_to_one_mappings_body() -> dict:
    return json.loads(FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_FIXTURE.read_text())


def _firewall_nat_one_to_one_mappings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_nat_one_to_one_mappings_body()
    transport.register(
        "GET", "/api/v2/firewall/nat/one_to_one/mappings?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_nat_one_to_one_mappings_parses_empty_list():
    """2026-08-20 live production verification observed exactly this
    shape: HTTP 200, `{"data": []}` -- zero 1:1 NAT mappings configured
    at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _firewall_nat_one_to_one_mappings_client(body)
    assert client.get_firewall_nat_one_to_one_mappings() == []


def test_get_firewall_nat_one_to_one_mappings_omits_identifying_fields_by_default():
    client, _ = _firewall_nat_one_to_one_mappings_client()
    mappings = client.get_firewall_nat_one_to_one_mappings()
    assert len(mappings) == 2
    for mapping in mappings:
        for field in FIREWALL_NAT_ONE_TO_ONE_MAPPINGS_IDENTIFYING_FIELDS:
            assert getattr(mapping, field) is None


def test_get_firewall_nat_one_to_one_mappings_includes_identifying_fields_when_requested():
    client, _ = _firewall_nat_one_to_one_mappings_client()
    mappings = client.get_firewall_nat_one_to_one_mappings(include_identifying_metadata=True)
    first = next(m for m in mappings if m.id == 0)
    assert first.external == "203.0.113.30"
    assert first.source == "198.51.100.10"


def test_get_firewall_nat_one_to_one_mappings_maps_non_sensitive_fields():
    client, _ = _firewall_nat_one_to_one_mappings_client()
    mappings = client.get_firewall_nat_one_to_one_mappings()
    first = next(m for m in mappings if m.id == 0)
    assert first.interface == "wan"
    assert first.disabled is False
    assert first.nobinat is False
    assert first.natreflection == "purenat"
    assert first.ipprotocol == "inet"


def test_get_firewall_nat_one_to_one_mappings_only_calls_endpoint_with_default_limit():
    client, transport = _firewall_nat_one_to_one_mappings_client()
    client.get_firewall_nat_one_to_one_mappings()
    assert transport.calls == [("GET", "/api/v2/firewall/nat/one_to_one/mappings?limit=100")]


def test_get_firewall_nat_one_to_one_mappings_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_nat_one_to_one_mappings_body()
    transport.register(
        "GET", "/api/v2/firewall/nat/one_to_one/mappings?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_nat_one_to_one_mappings(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/nat/one_to_one/mappings?limit=5")]


def test_get_firewall_nat_one_to_one_mappings_rejects_zero_limit():
    client, _ = _firewall_nat_one_to_one_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_one_to_one_mappings(limit=0)


def test_get_firewall_nat_one_to_one_mappings_rejects_limit_above_max():
    client, _ = _firewall_nat_one_to_one_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_one_to_one_mappings(limit=501)


def test_get_firewall_nat_one_to_one_mappings_invalid_limit_never_calls_transport():
    client, transport = _firewall_nat_one_to_one_mappings_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_nat_one_to_one_mappings(limit=0)
    assert transport.calls == []


def test_get_firewall_nat_one_to_one_mappings_missing_data_key_raises_shape_error():
    body = _firewall_nat_one_to_one_mappings_body()
    del body["data"]
    client, _ = _firewall_nat_one_to_one_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_one_to_one_mappings()


def test_get_firewall_nat_one_to_one_mappings_item_wrong_type_raises_shape_error():
    body = _firewall_nat_one_to_one_mappings_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_nat_one_to_one_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_one_to_one_mappings()


def test_get_firewall_nat_one_to_one_mappings_required_field_missing_raises_shape_error():
    body = _firewall_nat_one_to_one_mappings_body()
    del body["data"][0]["descr"]
    client, _ = _firewall_nat_one_to_one_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_nat_one_to_one_mappings()


def test_get_firewall_nat_one_to_one_mappings_shape_error_does_not_leak_raw_field_values():
    body = _firewall_nat_one_to_one_mappings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _firewall_nat_one_to_one_mappings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_nat_one_to_one_mappings()
    assert sentinel not in str(excinfo.value)


USERS_FIXTURE = Path(__file__).parent / "fixtures" / "users_response.json"
USERS_IDENTIFYING_FIELDS = ("authorizedkeys",)


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


def test_get_users_maps_non_sensitive_fields():
    client, _ = _users_client()
    users = client.get_users()
    first = users[0]
    assert first.id == 0
    assert first.disabled is False
    assert first.expires == ""
    assert first.scope == "system"


def test_get_users_accepts_null_expires():
    """Regression: a real pfSense v2 LAB appliance returned `expires: null`
    for the built-in admin account (2026-08-16 live evidence) -- the
    original fixture only ever exercised `""`, and the model's original
    non-nullable `str` typing raised PfSenseResponseShapeError for this
    genuine, valid API response shape."""
    body = _users_body()
    body["data"][0]["expires"] = None
    client, _ = _users_client(body)
    users = client.get_users()
    assert users[0].expires is None


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


CONFIG_HISTORY_REVISIONS_FIXTURE = Path(__file__).parent / "fixtures" / "config_history_revisions_response.json"


def _config_history_revisions_body() -> dict:
    return json.loads(CONFIG_HISTORY_REVISIONS_FIXTURE.read_text())


def _config_history_revisions_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _config_history_revisions_body()
    transport.register(
        "GET", "/api/v2/diagnostics/config_history/revisions?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_config_history_revisions_maps_fields():
    client, _ = _config_history_revisions_client()
    raw = _config_history_revisions_body()["data"]
    revisions = client.get_config_history_revisions()
    assert len(revisions) == 2
    assert revisions[0].id == raw[0]["id"]
    assert revisions[0].time == raw[0]["time"]
    assert revisions[0].description == raw[0]["description"]
    assert revisions[0].version == raw[0]["version"]
    assert revisions[0].filesize == raw[0]["filesize"]


def test_get_config_history_revisions_only_calls_endpoint_with_default_limit():
    client, transport = _config_history_revisions_client()
    client.get_config_history_revisions()
    assert transport.calls == [("GET", "/api/v2/diagnostics/config_history/revisions?limit=100")]


def test_get_config_history_revisions_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _config_history_revisions_body()
    transport.register(
        "GET", "/api/v2/diagnostics/config_history/revisions?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_config_history_revisions(limit=5)
    assert transport.calls == [("GET", "/api/v2/diagnostics/config_history/revisions?limit=5")]


def test_get_config_history_revisions_rejects_zero_limit():
    client, _ = _config_history_revisions_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_config_history_revisions(limit=0)


def test_get_config_history_revisions_rejects_limit_above_max():
    client, _ = _config_history_revisions_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_config_history_revisions(limit=101)


def test_get_config_history_revisions_missing_data_key_raises_shape_error():
    body = _config_history_revisions_body()
    del body["data"]
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_config_history_revisions()


def test_get_config_history_revisions_data_wrong_type_raises_shape_error():
    body = _config_history_revisions_body()
    body["data"] = "not-a-list"
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_config_history_revisions()


def test_get_config_history_revisions_item_wrong_type_raises_shape_error():
    body = _config_history_revisions_body()
    body["data"] = ["not-an-object"]
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_config_history_revisions()


def test_get_config_history_revisions_required_field_missing_raises_shape_error():
    body = _config_history_revisions_body()
    del body["data"][0]["description"]
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_config_history_revisions()


def test_get_config_history_revisions_invalid_field_type_raises_shape_error():
    body = _config_history_revisions_body()
    body["data"][0]["filesize"] = "not-an-int"
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_config_history_revisions()


def test_get_config_history_revisions_shape_error_does_not_leak_raw_field_values():
    body = _config_history_revisions_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["description"] = [sentinel]
    client, _ = _config_history_revisions_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_config_history_revisions()
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


def test_get_dhcp_servers_parses_null_optional_fields():
    """2026-08-21 LAB CE 2.8.1 -> 2.9.0 platform-upgrade regression
    check observed exactly this shape for an unconfigured scope: HTTP
    200 with domain/domainsearchlist/failover_peerip/gateway/mac_allow/
    mac_deny all `null`, where the original 2.8.1 capture had returned
    empty string/list for the same fields. Confirms the widened types
    accept both shapes."""

    body = _dhcp_servers_body()
    unconfigured = dict(body["data"][0])
    for field in ("domain", "domainsearchlist", "failover_peerip", "gateway", "mac_allow", "mac_deny"):
        unconfigured[field] = None
    body["data"] = [unconfigured]
    client, _ = _dhcp_servers_client(body)
    servers = client.get_dhcp_servers()
    assert len(servers) == 1
    for field in ("domain", "domainsearchlist", "failover_peerip", "gateway", "mac_allow", "mac_deny"):
        assert getattr(servers[0], field) is None


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


def test_get_dns_resolver_settings_parses_null_sslcertref_and_tlsport():
    """2026-08-21 LAB CE 2.8.1 -> 2.9.0 platform-upgrade regression
    check observed exactly this shape when DNS-over-TLS/SSL is not
    configured: HTTP 200 with sslcertref/tlsport both `null`, where the
    original 2.8.1 capture had returned a populated/empty string for
    the same fields. Confirms the widened types accept both shapes."""

    body = _dns_resolver_settings_body()
    body["data"]["sslcertref"] = None
    body["data"]["tlsport"] = None
    client, _ = _dns_resolver_settings_client(body)
    settings = client.get_dns_resolver_settings()
    assert settings.sslcertref is None
    assert settings.tlsport is None


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


NTP_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_ntp_settings_response.json"


def _ntp_settings_body() -> dict:
    return json.loads(NTP_SETTINGS_FIXTURE.read_text())


def _ntp_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _ntp_settings_body()
    transport.register("GET", "/api/v2/services/ntp/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_ntp_settings_maps_fields():
    client, _ = _ntp_settings_client()
    raw = _ntp_settings_body()["data"]
    settings = client.get_ntp_settings()
    assert settings.enable == raw["enable"]
    assert settings.ntpmaxpeers == raw["ntpmaxpeers"]
    assert settings.serverauthalgo == raw["serverauthalgo"]


def test_get_ntp_settings_only_calls_settings_endpoint():
    client, transport = _ntp_settings_client()
    client.get_ntp_settings()
    assert transport.calls == [("GET", "/api/v2/services/ntp/settings")]


def test_get_ntp_settings_missing_data_key_raises_shape_error():
    body = _ntp_settings_body()
    del body["data"]
    client, _ = _ntp_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_settings()


def test_get_ntp_settings_data_wrong_type_raises_shape_error():
    body = _ntp_settings_body()
    body["data"] = "not-an-object"
    client, _ = _ntp_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_settings()


def test_get_ntp_settings_required_field_missing_raises_shape_error():
    body = _ntp_settings_body()
    del body["data"]["enable"]
    client, _ = _ntp_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_settings()


def test_get_ntp_settings_invalid_field_type_raises_shape_error():
    body = _ntp_settings_body()
    body["data"]["enable"] = "not-a-bool"
    client, _ = _ntp_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_settings()


def test_get_ntp_settings_shape_error_does_not_leak_raw_field_values():
    body = _ntp_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["enable"] = sentinel
    client, _ = _ntp_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_ntp_settings()
    assert sentinel not in str(excinfo.value)


NTP_TIME_SERVERS_FIXTURE = Path(__file__).parent / "fixtures" / "services_ntp_time_servers_response.json"


def _ntp_time_servers_body() -> dict:
    return json.loads(NTP_TIME_SERVERS_FIXTURE.read_text())


def _ntp_time_servers_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _ntp_time_servers_body()
    transport.register("GET", "/api/v2/services/ntp/time_servers?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_ntp_time_servers_maps_fields():
    client, _ = _ntp_time_servers_client()
    raw = _ntp_time_servers_body()["data"]
    servers = client.get_ntp_time_servers()
    assert len(servers) == len(raw)
    assert servers[0].timeserver == raw[0]["timeserver"]
    assert servers[0].type == raw[0]["type"]


def test_get_ntp_time_servers_only_calls_endpoint_with_default_limit():
    client, transport = _ntp_time_servers_client()
    client.get_ntp_time_servers()
    assert transport.calls == [("GET", "/api/v2/services/ntp/time_servers?limit=100")]


def test_get_ntp_time_servers_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _ntp_time_servers_body()
    transport.register("GET", "/api/v2/services/ntp/time_servers?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_ntp_time_servers(limit=2)
    assert transport.calls == [("GET", "/api/v2/services/ntp/time_servers?limit=2")]


def test_get_ntp_time_servers_rejects_zero_limit():
    client, _ = _ntp_time_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_ntp_time_servers(limit=0)


def test_get_ntp_time_servers_rejects_limit_above_max():
    client, _ = _ntp_time_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_ntp_time_servers(limit=101)


def test_get_ntp_time_servers_missing_data_key_raises_shape_error():
    body = _ntp_time_servers_body()
    del body["data"]
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_time_servers()


def test_get_ntp_time_servers_data_wrong_type_raises_shape_error():
    body = _ntp_time_servers_body()
    body["data"] = "not-a-list"
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_time_servers()


def test_get_ntp_time_servers_item_wrong_type_raises_shape_error():
    body = _ntp_time_servers_body()
    body["data"] = ["not-an-object"]
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_time_servers()


def test_get_ntp_time_servers_required_field_missing_raises_shape_error():
    body = _ntp_time_servers_body()
    del body["data"][0]["timeserver"]
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_time_servers()


def test_get_ntp_time_servers_invalid_field_type_raises_shape_error():
    body = _ntp_time_servers_body()
    body["data"][0]["noselect"] = "not-a-bool"
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ntp_time_servers()


def test_get_ntp_time_servers_shape_error_does_not_leak_raw_field_values():
    body = _ntp_time_servers_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["timeserver"] = [sentinel]
    client, _ = _ntp_time_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_ntp_time_servers()
    assert sentinel not in str(excinfo.value)


SSH_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_ssh_response.json"


def _ssh_settings_body() -> dict:
    return json.loads(SSH_SETTINGS_FIXTURE.read_text())


def _ssh_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _ssh_settings_body()
    transport.register("GET", "/api/v2/services/ssh", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_ssh_settings_maps_fields():
    client, _ = _ssh_settings_client()
    raw = _ssh_settings_body()["data"]
    settings = client.get_ssh_settings()
    assert settings.enable == raw["enable"]
    assert settings.port == raw["port"]
    assert settings.sshdagentforwarding == raw["sshdagentforwarding"]


def test_get_ssh_settings_only_calls_settings_endpoint():
    client, transport = _ssh_settings_client()
    client.get_ssh_settings()
    assert transport.calls == [("GET", "/api/v2/services/ssh")]


def test_get_ssh_settings_missing_data_key_raises_shape_error():
    body = _ssh_settings_body()
    del body["data"]
    client, _ = _ssh_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ssh_settings()


def test_get_ssh_settings_data_wrong_type_raises_shape_error():
    body = _ssh_settings_body()
    body["data"] = "not-an-object"
    client, _ = _ssh_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ssh_settings()


def test_get_ssh_settings_required_field_missing_raises_shape_error():
    body = _ssh_settings_body()
    del body["data"]["enable"]
    client, _ = _ssh_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ssh_settings()


def test_get_ssh_settings_invalid_field_type_raises_shape_error():
    body = _ssh_settings_body()
    body["data"]["enable"] = "not-a-bool"
    client, _ = _ssh_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_ssh_settings()


def test_get_ssh_settings_shape_error_does_not_leak_raw_field_values():
    body = _ssh_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["enable"] = sentinel
    client, _ = _ssh_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_ssh_settings()
    assert sentinel not in str(excinfo.value)


CRON_JOBS_FIXTURE = Path(__file__).parent / "fixtures" / "services_cron_jobs_response.json"


def _cron_jobs_body() -> dict:
    return json.loads(CRON_JOBS_FIXTURE.read_text())


def _cron_jobs_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _cron_jobs_body()
    transport.register("GET", "/api/v2/services/cron/jobs?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_cron_jobs_maps_fields():
    client, _ = _cron_jobs_client()
    raw = _cron_jobs_body()["data"]
    jobs = client.get_cron_jobs()
    assert len(jobs) == len(raw)
    assert jobs[0].command == raw[0]["command"]
    assert jobs[0].who == raw[0]["who"]


def test_get_cron_jobs_only_calls_endpoint_with_default_limit():
    client, transport = _cron_jobs_client()
    client.get_cron_jobs()
    assert transport.calls == [("GET", "/api/v2/services/cron/jobs?limit=100")]


def test_get_cron_jobs_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _cron_jobs_body()
    transport.register("GET", "/api/v2/services/cron/jobs?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_cron_jobs(limit=2)
    assert transport.calls == [("GET", "/api/v2/services/cron/jobs?limit=2")]


def test_get_cron_jobs_rejects_zero_limit():
    client, _ = _cron_jobs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_cron_jobs(limit=0)


def test_get_cron_jobs_rejects_limit_above_max():
    client, _ = _cron_jobs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_cron_jobs(limit=101)


def test_get_cron_jobs_missing_data_key_raises_shape_error():
    body = _cron_jobs_body()
    del body["data"]
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_cron_jobs()


def test_get_cron_jobs_data_wrong_type_raises_shape_error():
    body = _cron_jobs_body()
    body["data"] = "not-a-list"
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_cron_jobs()


def test_get_cron_jobs_item_wrong_type_raises_shape_error():
    body = _cron_jobs_body()
    body["data"] = ["not-an-object"]
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_cron_jobs()


def test_get_cron_jobs_required_field_missing_raises_shape_error():
    body = _cron_jobs_body()
    del body["data"][0]["command"]
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_cron_jobs()


def test_get_cron_jobs_invalid_field_type_raises_shape_error():
    body = _cron_jobs_body()
    body["data"][0]["id"] = "not-an-int"
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_cron_jobs()


def test_get_cron_jobs_shape_error_does_not_leak_raw_field_values():
    body = _cron_jobs_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["command"] = [sentinel]
    client, _ = _cron_jobs_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_cron_jobs()
    assert sentinel not in str(excinfo.value)


ACME_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "services_acme_settings_response.json"


def _acme_settings_body() -> dict:
    return json.loads(ACME_SETTINGS_FIXTURE.read_text())


def _acme_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _acme_settings_body()
    transport.register("GET", "/api/v2/services/acme/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_acme_settings_maps_fields():
    client, _ = _acme_settings_client()
    raw = _acme_settings_body()["data"]
    settings = client.get_acme_settings()
    assert settings.enable == raw["enable"]
    assert settings.writecerts == raw["writecerts"]


def test_get_acme_settings_only_calls_settings_endpoint():
    client, transport = _acme_settings_client()
    client.get_acme_settings()
    assert transport.calls == [("GET", "/api/v2/services/acme/settings")]


def test_get_acme_settings_missing_data_key_raises_shape_error():
    body = _acme_settings_body()
    del body["data"]
    client, _ = _acme_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_acme_settings()


def test_get_acme_settings_data_wrong_type_raises_shape_error():
    body = _acme_settings_body()
    body["data"] = "not-an-object"
    client, _ = _acme_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_acme_settings()


def test_get_acme_settings_required_field_missing_raises_shape_error():
    body = _acme_settings_body()
    del body["data"]["enable"]
    client, _ = _acme_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_acme_settings()


def test_get_acme_settings_invalid_field_type_raises_shape_error():
    body = _acme_settings_body()
    body["data"]["enable"] = "not-a-bool"
    client, _ = _acme_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_acme_settings()


def test_get_acme_settings_shape_error_does_not_leak_raw_field_values():
    body = _acme_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["enable"] = sentinel
    client, _ = _acme_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_acme_settings()
    assert sentinel not in str(excinfo.value)


FREERADIUS_EAP_FIXTURE = Path(__file__).parent / "fixtures" / "services_freeradius_eap_response.json"


def _freeradius_eap_body() -> dict:
    return json.loads(FREERADIUS_EAP_FIXTURE.read_text())


def _freeradius_eap_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _freeradius_eap_body()
    transport.register("GET", "/api/v2/services/freeradius/eap", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_freeradius_eap_maps_fields():
    client, _ = _freeradius_eap_client()
    raw = _freeradius_eap_body()["data"]
    eap = client.get_freeradius_eap()
    assert eap.default_eap_type == raw["default_eap_type"]
    assert eap.max_sessions == raw["max_sessions"]
    assert eap.ssl_ca_cert == raw["ssl_ca_cert"]


def test_get_freeradius_eap_only_calls_eap_endpoint():
    client, transport = _freeradius_eap_client()
    client.get_freeradius_eap()
    assert transport.calls == [("GET", "/api/v2/services/freeradius/eap")]


def test_get_freeradius_eap_missing_data_key_raises_shape_error():
    body = _freeradius_eap_body()
    del body["data"]
    client, _ = _freeradius_eap_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_freeradius_eap()


def test_get_freeradius_eap_data_wrong_type_raises_shape_error():
    body = _freeradius_eap_body()
    body["data"] = "not-an-object"
    client, _ = _freeradius_eap_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_freeradius_eap()


def test_get_freeradius_eap_required_field_missing_raises_shape_error():
    body = _freeradius_eap_body()
    del body["data"]["default_eap_type"]
    client, _ = _freeradius_eap_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_freeradius_eap()


def test_get_freeradius_eap_invalid_field_type_raises_shape_error():
    body = _freeradius_eap_body()
    body["data"]["cache_enable"] = "not-a-bool"
    client, _ = _freeradius_eap_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_freeradius_eap()


def test_get_freeradius_eap_shape_error_does_not_leak_raw_field_values():
    body = _freeradius_eap_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["cache_enable"] = sentinel
    client, _ = _freeradius_eap_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_freeradius_eap()
    assert sentinel not in str(excinfo.value)


DIAGNOSTICS_TABLES_FIXTURE = Path(__file__).parent / "fixtures" / "diagnostics_tables_response.json"


def _diagnostics_tables_body() -> dict:
    return json.loads(DIAGNOSTICS_TABLES_FIXTURE.read_text())


def _diagnostics_tables_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _diagnostics_tables_body()
    transport.register("GET", "/api/v2/diagnostics/tables?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_diagnostics_tables_maps_fields():
    client, _ = _diagnostics_tables_client()
    raw = _diagnostics_tables_body()["data"]
    tables = client.get_diagnostics_tables()
    assert len(tables) == len(raw)
    assert tables[0].name == raw[0]["name"]
    assert tables[0].entries == raw[0]["entries"]


def test_get_diagnostics_tables_only_calls_endpoint_with_default_limit():
    client, transport = _diagnostics_tables_client()
    client.get_diagnostics_tables()
    assert transport.calls == [("GET", "/api/v2/diagnostics/tables?limit=100")]


def test_get_diagnostics_tables_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _diagnostics_tables_body()
    transport.register("GET", "/api/v2/diagnostics/tables?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_diagnostics_tables(limit=2)
    assert transport.calls == [("GET", "/api/v2/diagnostics/tables?limit=2")]


def test_get_diagnostics_tables_rejects_zero_limit():
    client, _ = _diagnostics_tables_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_diagnostics_tables(limit=0)


def test_get_diagnostics_tables_rejects_limit_above_max():
    client, _ = _diagnostics_tables_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_diagnostics_tables(limit=101)


def test_get_diagnostics_tables_missing_data_key_raises_shape_error():
    body = _diagnostics_tables_body()
    del body["data"]
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_diagnostics_tables()


def test_get_diagnostics_tables_data_wrong_type_raises_shape_error():
    body = _diagnostics_tables_body()
    body["data"] = "not-a-list"
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_diagnostics_tables()


def test_get_diagnostics_tables_item_wrong_type_raises_shape_error():
    body = _diagnostics_tables_body()
    body["data"] = ["not-an-object"]
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_diagnostics_tables()


def test_get_diagnostics_tables_required_field_missing_raises_shape_error():
    body = _diagnostics_tables_body()
    del body["data"][0]["name"]
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_diagnostics_tables()


def test_get_diagnostics_tables_invalid_field_type_raises_shape_error():
    body = _diagnostics_tables_body()
    body["data"][0]["entries"] = "not-a-list"
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_diagnostics_tables()


def test_get_diagnostics_tables_shape_error_does_not_leak_raw_field_values():
    body = _diagnostics_tables_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _diagnostics_tables_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_diagnostics_tables()
    assert sentinel not in str(excinfo.value)


AUTH_KEYS_FIXTURE = Path(__file__).parent / "fixtures" / "auth_keys_response.json"


def _auth_keys_body() -> dict:
    return json.loads(AUTH_KEYS_FIXTURE.read_text())


def _auth_keys_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _auth_keys_body()
    transport.register("GET", "/api/v2/auth/keys?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_auth_keys_ignores_upstream_plaintext_key():
    body = _auth_keys_body()
    body["data"][0]["key"] = "test-plaintext-key-value"
    client, _ = _auth_keys_client(body)
    keys = client.get_auth_keys()
    assert "key" not in type(keys[0]).model_fields
    assert "test-plaintext-key-value" not in keys[0].model_dump_json()


def test_get_auth_keys_maps_non_identifying_fields():
    client, _ = _auth_keys_client()
    raw = _auth_keys_body()["data"]
    keys = client.get_auth_keys()
    assert keys[0].descr == raw[0]["descr"]
    assert keys[0].username == raw[0]["username"]
    assert keys[0].hash_algo == raw[0]["hash_algo"]
    assert keys[0].length_bytes == raw[0]["length_bytes"]


def test_get_auth_keys_only_calls_endpoint_with_default_limit():
    client, transport = _auth_keys_client()
    client.get_auth_keys()
    assert transport.calls == [("GET", "/api/v2/auth/keys?limit=100")]


def test_get_auth_keys_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _auth_keys_body()
    transport.register("GET", "/api/v2/auth/keys?limit=2", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_auth_keys(limit=2)
    assert transport.calls == [("GET", "/api/v2/auth/keys?limit=2")]


def test_get_auth_keys_rejects_zero_limit():
    client, _ = _auth_keys_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_auth_keys(limit=0)


def test_get_auth_keys_rejects_limit_above_max():
    client, _ = _auth_keys_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_auth_keys(limit=101)


def test_get_auth_keys_missing_data_key_raises_shape_error():
    body = _auth_keys_body()
    del body["data"]
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_auth_keys()


def test_get_auth_keys_data_wrong_type_raises_shape_error():
    body = _auth_keys_body()
    body["data"] = "not-a-list"
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_auth_keys()


def test_get_auth_keys_item_wrong_type_raises_shape_error():
    body = _auth_keys_body()
    body["data"] = ["not-an-object"]
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_auth_keys()


def test_get_auth_keys_required_field_missing_raises_shape_error():
    body = _auth_keys_body()
    del body["data"][0]["descr"]
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_auth_keys()


def test_get_auth_keys_invalid_field_type_raises_shape_error():
    body = _auth_keys_body()
    body["data"][0]["length_bytes"] = "not-an-int"
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_auth_keys()


def test_get_auth_keys_shape_error_does_not_leak_raw_field_values():
    body = _auth_keys_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _auth_keys_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_auth_keys()
    assert sentinel not in str(excinfo.value)


INTERFACE_VLANS_FIXTURE = Path(__file__).parent / "fixtures" / "interface_vlans_response.json"


def _interface_vlans_body() -> dict:
    return json.loads(INTERFACE_VLANS_FIXTURE.read_text())


def _interface_vlans_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_vlans_body()
    transport.register("GET", "/api/v2/interface/vlans?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_vlans_parses_empty_list():
    """2026-08-20 LAB verification observed exactly this shape: HTTP
    200, `{"data": []}` -- zero VLANs configured on the LAB appliance
    at verification time. Confirms the empty-list case (not just
    populated lists) parses without error."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _interface_vlans_client(body)
    assert client.get_interface_vlans() == []


def test_get_interface_vlans_maps_all_fields():
    client, _ = _interface_vlans_client()
    vlans = client.get_interface_vlans()
    assert len(vlans) == 2
    first = next(v for v in vlans if v.tag == 10)
    assert first.if_ == "igb1"
    assert first.vlanif == "igb1.10"
    assert first.pcp == "0"
    assert first.descr == "Synthetic VLAN (offline fixture)"


def test_get_interface_vlans_only_calls_endpoint_with_default_limit():
    client, transport = _interface_vlans_client()
    client.get_interface_vlans()
    assert transport.calls == [("GET", "/api/v2/interface/vlans?limit=100")]


def test_get_interface_vlans_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_vlans_body()
    transport.register("GET", "/api/v2/interface/vlans?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_vlans(limit=5)
    assert transport.calls == [("GET", "/api/v2/interface/vlans?limit=5")]


def test_get_interface_vlans_rejects_zero_limit():
    client, _ = _interface_vlans_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_vlans(limit=0)


def test_get_interface_vlans_rejects_limit_above_max():
    client, _ = _interface_vlans_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_vlans(limit=101)


def test_get_interface_vlans_invalid_limit_never_calls_transport():
    client, transport = _interface_vlans_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_vlans(limit=0)
    assert transport.calls == []


def test_get_interface_vlans_missing_data_key_raises_shape_error():
    body = _interface_vlans_body()
    del body["data"]
    client, _ = _interface_vlans_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_vlans()


def test_get_interface_vlans_item_wrong_type_raises_shape_error():
    body = _interface_vlans_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_vlans_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_vlans()


def test_get_interface_vlans_required_field_missing_raises_shape_error():
    body = _interface_vlans_body()
    del body["data"][0]["tag"]
    client, _ = _interface_vlans_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_vlans()


def test_get_interface_vlans_shape_error_does_not_leak_raw_field_values():
    body = _interface_vlans_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _interface_vlans_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_vlans()
    assert sentinel not in str(excinfo.value)


ROUTING_STATIC_ROUTES_FIXTURE = Path(__file__).parent / "fixtures" / "routing_static_routes_response.json"
ROUTING_STATIC_ROUTES_IDENTIFYING_FIELDS = ("gateway", "network")


def _routing_static_routes_body() -> dict:
    return json.loads(ROUTING_STATIC_ROUTES_FIXTURE.read_text())


def _routing_static_routes_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _routing_static_routes_body()
    transport.register("GET", "/api/v2/routing/static_routes?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_routing_static_routes_parses_empty_list():
    """2026-08-20 LAB verification observed exactly this shape: HTTP
    200, `{"data": []}` -- zero static routes configured on the LAB
    appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _routing_static_routes_client(body)
    assert client.get_routing_static_routes() == []


def test_get_routing_static_routes_omits_identifying_fields_by_default():
    client, _ = _routing_static_routes_client()
    routes = client.get_routing_static_routes()
    assert len(routes) == 2
    for route in routes:
        for field in ROUTING_STATIC_ROUTES_IDENTIFYING_FIELDS:
            assert getattr(route, field) is None


def test_get_routing_static_routes_includes_identifying_fields_when_requested():
    client, _ = _routing_static_routes_client()
    routes = client.get_routing_static_routes(include_identifying_metadata=True)
    first = next(r for r in routes if r.disabled is False)
    assert first.network == "198.51.100.0/24"
    assert first.gateway == "WAN_GW"


def test_get_routing_static_routes_maps_non_sensitive_fields():
    client, _ = _routing_static_routes_client()
    routes = client.get_routing_static_routes()
    first = next(r for r in routes if r.disabled is False)
    assert first.descr == "Synthetic static route (offline fixture)"


def test_get_routing_static_routes_only_calls_endpoint_with_default_limit():
    client, transport = _routing_static_routes_client()
    client.get_routing_static_routes()
    assert transport.calls == [("GET", "/api/v2/routing/static_routes?limit=100")]


def test_get_routing_static_routes_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _routing_static_routes_body()
    transport.register("GET", "/api/v2/routing/static_routes?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_routing_static_routes(limit=5)
    assert transport.calls == [("GET", "/api/v2/routing/static_routes?limit=5")]


def test_get_routing_static_routes_rejects_zero_limit():
    client, _ = _routing_static_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_static_routes(limit=0)


def test_get_routing_static_routes_rejects_limit_above_max():
    client, _ = _routing_static_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_static_routes(limit=101)


def test_get_routing_static_routes_invalid_limit_never_calls_transport():
    client, transport = _routing_static_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_static_routes(limit=0)
    assert transport.calls == []


def test_get_routing_static_routes_missing_data_key_raises_shape_error():
    body = _routing_static_routes_body()
    del body["data"]
    client, _ = _routing_static_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_static_routes()


def test_get_routing_static_routes_item_wrong_type_raises_shape_error():
    body = _routing_static_routes_body()
    body["data"] = ["not-an-object"]
    client, _ = _routing_static_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_static_routes()


def test_get_routing_static_routes_required_field_missing_raises_shape_error():
    body = _routing_static_routes_body()
    del body["data"][0]["disabled"]
    client, _ = _routing_static_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_static_routes()


def test_get_routing_static_routes_shape_error_does_not_leak_raw_field_values():
    body = _routing_static_routes_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _routing_static_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_routing_static_routes()
    assert sentinel not in str(excinfo.value)


INTERFACE_GROUPS_FIXTURE = Path(__file__).parent / "fixtures" / "interface_groups_response.json"


def _interface_groups_body() -> dict:
    return json.loads(INTERFACE_GROUPS_FIXTURE.read_text())


def _interface_groups_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_groups_body()
    transport.register("GET", "/api/v2/interface/groups?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_groups_parses_empty_list():
    """2026-08-20 LAB verification observed exactly this shape: HTTP
    200, `{"data": []}` -- zero interface groups configured on the LAB
    appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _interface_groups_client(body)
    assert client.get_interface_groups() == []


def test_get_interface_groups_maps_all_fields():
    client, _ = _interface_groups_client()
    groups = client.get_interface_groups()
    assert len(groups) == 2
    first = next(g for g in groups if g.ifname == "IOT")
    assert first.members == ["igb1.10", "igb1.20"]
    assert first.descr == "Synthetic interface group (offline fixture)"


def test_get_interface_groups_only_calls_endpoint_with_default_limit():
    client, transport = _interface_groups_client()
    client.get_interface_groups()
    assert transport.calls == [("GET", "/api/v2/interface/groups?limit=100")]


def test_get_interface_groups_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_groups_body()
    transport.register("GET", "/api/v2/interface/groups?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_groups(limit=5)
    assert transport.calls == [("GET", "/api/v2/interface/groups?limit=5")]


def test_get_interface_groups_rejects_zero_limit():
    client, _ = _interface_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_groups(limit=0)


def test_get_interface_groups_rejects_limit_above_max():
    client, _ = _interface_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_groups(limit=101)


def test_get_interface_groups_invalid_limit_never_calls_transport():
    client, transport = _interface_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_groups(limit=0)
    assert transport.calls == []


def test_get_interface_groups_missing_data_key_raises_shape_error():
    body = _interface_groups_body()
    del body["data"]
    client, _ = _interface_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_groups()


def test_get_interface_groups_item_wrong_type_raises_shape_error():
    body = _interface_groups_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_groups()


def test_get_interface_groups_required_field_missing_raises_shape_error():
    body = _interface_groups_body()
    del body["data"][0]["members"]
    client, _ = _interface_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_groups()


def test_get_interface_groups_shape_error_does_not_leak_raw_field_values():
    body = _interface_groups_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _interface_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_groups()
    assert sentinel not in str(excinfo.value)


FIREWALL_SCHEDULES_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_schedules_response.json"


def _firewall_schedules_body() -> dict:
    return json.loads(FIREWALL_SCHEDULES_FIXTURE.read_text())


def _firewall_schedules_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_schedules_body()
    transport.register("GET", "/api/v2/firewall/schedules?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_schedules_parses_empty_list():
    """2026-08-20 LAB verification observed exactly this shape: HTTP
    200, `{"data": []}` -- zero firewall schedules configured on the
    LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _firewall_schedules_client(body)
    assert client.get_firewall_schedules() == []


def test_get_firewall_schedules_maps_all_fields():
    client, _ = _firewall_schedules_client()
    schedules = client.get_firewall_schedules()
    assert len(schedules) == 2
    first = next(s for s in schedules if s.name == "BusinessHours")
    assert first.descr == "Synthetic firewall schedule (offline fixture)"
    assert first.schedlabel == "businesshours"
    assert first.active is True
    assert first.timerange == [
        {"month": [8], "day": [20], "hour": "0900-1700", "position": [1], "rangedescr": "Weekday business hours"}
    ]


def test_get_firewall_schedules_handles_null_schedlabel_and_empty_timerange():
    client, _ = _firewall_schedules_client()
    schedules = client.get_firewall_schedules()
    empty = next(s for s in schedules if s.name == "Empty")
    assert empty.schedlabel is None
    assert empty.timerange == []
    assert empty.active is False


def test_get_firewall_schedules_only_calls_endpoint_with_default_limit():
    client, transport = _firewall_schedules_client()
    client.get_firewall_schedules()
    assert transport.calls == [("GET", "/api/v2/firewall/schedules?limit=100")]


def test_get_firewall_schedules_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_schedules_body()
    transport.register("GET", "/api/v2/firewall/schedules?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_schedules(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/schedules?limit=5")]


def test_get_firewall_schedules_rejects_zero_limit():
    client, _ = _firewall_schedules_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_schedules(limit=0)


def test_get_firewall_schedules_rejects_limit_above_max():
    client, _ = _firewall_schedules_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_schedules(limit=101)


def test_get_firewall_schedules_invalid_limit_never_calls_transport():
    client, transport = _firewall_schedules_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_schedules(limit=0)
    assert transport.calls == []


def test_get_firewall_schedules_missing_data_key_raises_shape_error():
    body = _firewall_schedules_body()
    del body["data"]
    client, _ = _firewall_schedules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_schedules()


def test_get_firewall_schedules_item_wrong_type_raises_shape_error():
    body = _firewall_schedules_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_schedules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_schedules()


def test_get_firewall_schedules_required_field_missing_raises_shape_error():
    body = _firewall_schedules_body()
    del body["data"][0]["name"]
    client, _ = _firewall_schedules_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_schedules()


def test_get_firewall_schedules_shape_error_does_not_leak_raw_field_values():
    body = _firewall_schedules_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _firewall_schedules_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_schedules()
    assert sentinel not in str(excinfo.value)


SYSTEM_RESTAPI_VERSION_FIXTURE = Path(__file__).parent / "fixtures" / "system_restapi_version_response.json"


def _system_restapi_version_body() -> dict:
    return json.loads(SYSTEM_RESTAPI_VERSION_FIXTURE.read_text())


def _system_restapi_version_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_restapi_version_body()
    transport.register("GET", "/api/v2/system/restapi/version", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_restapi_version_maps_all_present_fields():
    """The committed fixture matches the exact live LAB response
    observed 2026-08-20 (https://pfsense-test.lab.invalid), which
    omitted `install_version` entirely."""

    client, _ = _system_restapi_version_client()
    version = client.get_system_restapi_version()
    assert version.current_version == "v2.10"
    assert version.latest_version == "v2.10.0"
    assert version.latest_version_release_date == "2026-08-08T01:08:52Z"
    assert version.update_available is True
    assert version.available_versions == ["v2.10.0", "v2.9.0", "v2.8.4"]


def test_get_system_restapi_version_install_version_absent_from_response_defaults_to_none():
    client, _ = _system_restapi_version_client()
    version = client.get_system_restapi_version()
    assert version.install_version is None


def test_get_system_restapi_version_install_version_present_is_captured():
    body = _system_restapi_version_body()
    body["data"]["install_version"] = "v2.10.0"
    client, _ = _system_restapi_version_client(body)
    version = client.get_system_restapi_version()
    assert version.install_version == "v2.10.0"


def test_get_system_restapi_version_calls_endpoint_with_no_params():
    client, transport = _system_restapi_version_client()
    client.get_system_restapi_version()
    assert transport.calls == [("GET", "/api/v2/system/restapi/version")]


def test_get_system_restapi_version_missing_data_key_raises_shape_error():
    body = _system_restapi_version_body()
    del body["data"]
    client, _ = _system_restapi_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_version()


def test_get_system_restapi_version_data_wrong_type_raises_shape_error():
    body = _system_restapi_version_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_restapi_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_version()


def test_get_system_restapi_version_required_field_missing_raises_shape_error():
    body = _system_restapi_version_body()
    del body["data"]["current_version"]
    client, _ = _system_restapi_version_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_version()


def test_get_system_restapi_version_shape_error_does_not_leak_raw_field_values():
    body = _system_restapi_version_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["current_version"] = [sentinel]
    client, _ = _system_restapi_version_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_restapi_version()
    assert sentinel not in str(excinfo.value)


FIREWALL_VIRTUAL_IPS_FIXTURE = Path(__file__).parent / "fixtures" / "firewall_virtual_ips_response.json"
FIREWALL_VIRTUAL_IPS_IDENTIFYING_FIELDS = ("carp_peer", "subnet")


def _firewall_virtual_ips_body() -> dict:
    return json.loads(FIREWALL_VIRTUAL_IPS_FIXTURE.read_text())


def _firewall_virtual_ips_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _firewall_virtual_ips_body()
    transport.register("GET", "/api/v2/firewall/virtual_ips?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_firewall_virtual_ips_never_exposes_password_field():
    """The confirmed CARP shared-secret field must never reach the
    caller under any argument combination -- unlike identifying
    fields, there is no flag that reveals it. The `password` value is
    injected into the raw response only in-memory here (never
    committed to the fixture file, which fixture_safety.py's
    prohibited-credential-field scan correctly refuses) -- proving the
    model ignores it even when genuinely present in the raw payload,
    not merely absent from test data."""

    body = _firewall_virtual_ips_body()
    for entry in body["data"]:
        entry["password"] = "SENTINEL-CARP-SHARED-SECRET"
    client, _ = _firewall_virtual_ips_client(body)
    for include in (False, True):
        vips = client.get_firewall_virtual_ips(include_identifying_metadata=include)
        for vip in vips:
            assert not hasattr(vip, "password")
            assert "password" not in vip.model_dump()


def test_get_firewall_virtual_ips_omits_identifying_fields_by_default():
    client, _ = _firewall_virtual_ips_client()
    vips = client.get_firewall_virtual_ips()
    assert len(vips) == 2
    for vip in vips:
        for field in FIREWALL_VIRTUAL_IPS_IDENTIFYING_FIELDS:
            assert getattr(vip, field) is None


def test_get_firewall_virtual_ips_includes_identifying_fields_when_requested():
    client, _ = _firewall_virtual_ips_client()
    vips = client.get_firewall_virtual_ips(include_identifying_metadata=True)
    first = next(v for v in vips if v.vhid == 1)
    assert first.subnet == "203.0.113.5"
    assert first.carp_peer == "203.0.113.6"


def test_get_firewall_virtual_ips_maps_non_sensitive_fields():
    client, _ = _firewall_virtual_ips_client()
    vips = client.get_firewall_virtual_ips()
    first = next(v for v in vips if v.vhid == 1)
    assert first.mode == "carp"
    assert first.interface == "wan"
    assert first.type == "network"
    assert first.subnet_bits == 32
    assert first.descr == "Synthetic virtual IP (offline fixture)"
    assert first.noexpand is False
    assert first.advbase == 1
    assert first.advskew == 0
    assert first.carp_status == "MASTER"
    assert first.carp_mode == "ipv4"
    assert first.uniqid == "68a1a1a1a1a1a"


def test_get_firewall_virtual_ips_only_calls_endpoint_with_default_limit():
    client, transport = _firewall_virtual_ips_client()
    client.get_firewall_virtual_ips()
    assert transport.calls == [("GET", "/api/v2/firewall/virtual_ips?limit=100")]


def test_get_firewall_virtual_ips_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _firewall_virtual_ips_body()
    transport.register("GET", "/api/v2/firewall/virtual_ips?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_firewall_virtual_ips(limit=5)
    assert transport.calls == [("GET", "/api/v2/firewall/virtual_ips?limit=5")]


def test_get_firewall_virtual_ips_rejects_zero_limit():
    client, _ = _firewall_virtual_ips_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_virtual_ips(limit=0)


def test_get_firewall_virtual_ips_rejects_limit_above_max():
    client, _ = _firewall_virtual_ips_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_virtual_ips(limit=101)


def test_get_firewall_virtual_ips_invalid_limit_never_calls_transport():
    client, transport = _firewall_virtual_ips_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_firewall_virtual_ips(limit=0)
    assert transport.calls == []


def test_get_firewall_virtual_ips_parses_empty_list():
    """2026-08-20 LAB verification observed exactly this shape: HTTP
    200, `{"data": []}` -- zero virtual IPs configured on the LAB
    appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _firewall_virtual_ips_client(body)
    assert client.get_firewall_virtual_ips() == []


def test_get_firewall_virtual_ips_missing_data_key_raises_shape_error():
    body = _firewall_virtual_ips_body()
    del body["data"]
    client, _ = _firewall_virtual_ips_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_virtual_ips()


def test_get_firewall_virtual_ips_item_wrong_type_raises_shape_error():
    body = _firewall_virtual_ips_body()
    body["data"] = ["not-an-object"]
    client, _ = _firewall_virtual_ips_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_virtual_ips()


def test_get_firewall_virtual_ips_required_field_missing_raises_shape_error():
    body = _firewall_virtual_ips_body()
    del body["data"][0]["vhid"]
    client, _ = _firewall_virtual_ips_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_firewall_virtual_ips()


def test_get_firewall_virtual_ips_shape_error_does_not_leak_raw_field_values():
    body = _firewall_virtual_ips_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _firewall_virtual_ips_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_firewall_virtual_ips()
    assert sentinel not in str(excinfo.value)


SYSTEM_CERTIFICATE_AUTHORITIES_FIXTURE = (
    Path(__file__).parent / "fixtures" / "system_certificate_authorities_response.json"
)


def _system_certificate_authorities_body() -> dict:
    return json.loads(SYSTEM_CERTIFICATE_AUTHORITIES_FIXTURE.read_text())


def _system_certificate_authorities_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_certificate_authorities_body()
    transport.register(
        "GET", "/api/v2/system/certificate_authorities?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_certificate_authorities_never_exposes_prv_field():
    """The confirmed CA private-key field must never reach the caller,
    even when the raw response genuinely includes a populated `prv`
    value -- proving the model ignores it rather than merely never
    having seen it in test data. The `prv` value is injected into the
    raw response only in-memory here (never committed to the fixture
    file, matching this codebase's `password`-field discipline even
    though `prv` isn't itself in fixture_safety.py's prohibited-field
    list). 2026-08-20 LAB verification independently confirmed this
    against a real, populated CertificateAuthority object (the LAB's
    own internal CA) -- the real `prv` value was never fetched into
    this test suite; only the parsed model's field set was inspected."""

    body = _system_certificate_authorities_body()
    body["data"][0]["prv"] = "SENTINEL-CA-PRIVATE-KEY-MATERIAL"
    client, _ = _system_certificate_authorities_client(body)
    cas = client.get_system_certificate_authorities()
    assert len(cas) == 2
    for ca in cas:
        assert not hasattr(ca, "prv")
        assert "prv" not in ca.model_dump()


def test_get_system_certificate_authorities_maps_non_sensitive_fields():
    client, _ = _system_certificate_authorities_client()
    cas = client.get_system_certificate_authorities()
    first = next(c for c in cas if c.serial == 1)
    assert first.descr == "Synthetic internal CA (offline fixture)"
    assert first.refid == "68a1a1a1a1a1b"
    assert first.caref == "68a1a1a1a1a1b"
    assert first.trust is True
    assert first.randomserial is False
    assert first.crt == "LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0t"


def test_get_system_certificate_authorities_only_calls_endpoint_with_default_limit():
    client, transport = _system_certificate_authorities_client()
    client.get_system_certificate_authorities()
    assert transport.calls == [("GET", "/api/v2/system/certificate_authorities?limit=100")]


def test_get_system_certificate_authorities_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_certificate_authorities_body()
    transport.register("GET", "/api/v2/system/certificate_authorities?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_certificate_authorities(limit=5)
    assert transport.calls == [("GET", "/api/v2/system/certificate_authorities?limit=5")]


def test_get_system_certificate_authorities_rejects_zero_limit():
    client, _ = _system_certificate_authorities_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_certificate_authorities(limit=0)


def test_get_system_certificate_authorities_rejects_limit_above_max():
    client, _ = _system_certificate_authorities_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_certificate_authorities(limit=101)


def test_get_system_certificate_authorities_invalid_limit_never_calls_transport():
    client, transport = _system_certificate_authorities_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_certificate_authorities(limit=0)
    assert transport.calls == []


def test_get_system_certificate_authorities_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _system_certificate_authorities_client(body)
    assert client.get_system_certificate_authorities() == []


def test_get_system_certificate_authorities_missing_data_key_raises_shape_error():
    body = _system_certificate_authorities_body()
    del body["data"]
    client, _ = _system_certificate_authorities_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificate_authorities()


def test_get_system_certificate_authorities_item_wrong_type_raises_shape_error():
    body = _system_certificate_authorities_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_certificate_authorities_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificate_authorities()


def test_get_system_certificate_authorities_required_field_missing_raises_shape_error():
    body = _system_certificate_authorities_body()
    del body["data"][0]["crt"]
    client, _ = _system_certificate_authorities_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_certificate_authorities()


def test_get_system_certificate_authorities_shape_error_does_not_leak_raw_field_values():
    body = _system_certificate_authorities_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _system_certificate_authorities_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_certificate_authorities()
    assert sentinel not in str(excinfo.value)


STATUS_IPSEC_SAS_FIXTURE = Path(__file__).parent / "fixtures" / "status_ipsec_sas_response.json"
STATUS_IPSEC_SAS_IDENTIFYING_FIELDS = ("local_host", "local_id", "remote_host", "remote_id")


def _status_ipsec_sas_body() -> dict:
    return json.loads(STATUS_IPSEC_SAS_FIXTURE.read_text())


def _status_ipsec_sas_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_ipsec_sas_body()
    transport.register("GET", "/api/v2/status/ipsec/sas?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_ipsec_sas_omits_identifying_fields_by_default():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas()
    assert len(sas) == 2
    for sa in sas:
        for field in STATUS_IPSEC_SAS_IDENTIFYING_FIELDS:
            assert getattr(sa, field) is None


def test_get_status_ipsec_sas_includes_identifying_fields_when_requested():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas(include_identifying_metadata=True)
    first = next(s for s in sas if s.con_id == "con1")
    assert first.local_host == "198.51.100.1"
    assert first.remote_host == "203.0.113.1"
    assert first.local_id == "198.51.100.1"
    assert first.remote_id == "203.0.113.1"


def test_get_status_ipsec_sas_maps_non_sensitive_fields():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas()
    first = next(s for s in sas if s.con_id == "con1")
    assert first.state == "ESTABLISHED"
    assert first.version == 2
    assert first.encr_alg == "AES_CBC"
    assert first.established == 3600


def test_get_status_ipsec_sas_nested_child_sas_constructed_as_typed_objects():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas()
    first = next(s for s in sas if s.con_id == "con1")
    assert first.child_sas is not None
    assert len(first.child_sas) == 1
    assert first.child_sas[0].name == "con1"
    assert first.child_sas[0].state == "INSTALLED"


def test_get_status_ipsec_sas_nested_child_sas_redaction_follows_parent_flag():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas()
    first = next(s for s in sas if s.con_id == "con1")
    assert first.child_sas[0].local_ts is None
    assert first.child_sas[0].remote_ts is None

    sas_revealed = client.get_status_ipsec_sas(include_identifying_metadata=True)
    first_revealed = next(s for s in sas_revealed if s.con_id == "con1")
    assert first_revealed.child_sas[0].local_ts == ["198.51.100.0/24"]
    assert first_revealed.child_sas[0].remote_ts == ["203.0.113.0/24"]


def test_get_status_ipsec_sas_handles_null_child_sas():
    client, _ = _status_ipsec_sas_client()
    sas = client.get_status_ipsec_sas()
    second = next(s for s in sas if s.con_id is None)
    assert second.child_sas is None


def test_get_status_ipsec_sas_only_calls_endpoint_with_default_limit():
    client, transport = _status_ipsec_sas_client()
    client.get_status_ipsec_sas()
    assert transport.calls == [("GET", "/api/v2/status/ipsec/sas?limit=100")]


def test_get_status_ipsec_sas_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_ipsec_sas_body()
    transport.register("GET", "/api/v2/status/ipsec/sas?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_ipsec_sas(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/ipsec/sas?limit=5")]


def test_get_status_ipsec_sas_rejects_zero_limit():
    client, _ = _status_ipsec_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_sas(limit=0)


def test_get_status_ipsec_sas_rejects_limit_above_max():
    client, _ = _status_ipsec_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_sas(limit=101)


def test_get_status_ipsec_sas_invalid_limit_never_calls_transport():
    client, transport = _status_ipsec_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_sas(limit=0)
    assert transport.calls == []


def test_get_status_ipsec_sas_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    IPsec SAs on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_ipsec_sas_client(body)
    assert client.get_status_ipsec_sas() == []


def test_get_status_ipsec_sas_missing_data_key_raises_shape_error():
    body = _status_ipsec_sas_body()
    del body["data"]
    client, _ = _status_ipsec_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_sas()


def test_get_status_ipsec_sas_item_wrong_type_raises_shape_error():
    body = _status_ipsec_sas_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_ipsec_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_sas()


def test_get_status_ipsec_sas_required_field_missing_raises_shape_error():
    body = _status_ipsec_sas_body()
    del body["data"][0]["con_id"]
    client, _ = _status_ipsec_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_sas()


def test_get_status_ipsec_sas_shape_error_does_not_leak_raw_field_values():
    body = _status_ipsec_sas_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["con_id"] = [sentinel]
    client, _ = _status_ipsec_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_ipsec_sas()
    assert sentinel not in str(excinfo.value)


STATUS_IPSEC_CHILD_SAS_FIXTURE = Path(__file__).parent / "fixtures" / "status_ipsec_child_sas_response.json"
STATUS_IPSEC_CHILD_SAS_IDENTIFYING_FIELDS = ("local_ts", "remote_ts")


def _status_ipsec_child_sas_body() -> dict:
    return json.loads(STATUS_IPSEC_CHILD_SAS_FIXTURE.read_text())


def _status_ipsec_child_sas_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_ipsec_child_sas_body()
    transport.register("GET", "/api/v2/status/ipsec/child_sas?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_ipsec_child_sas_omits_identifying_fields_by_default():
    client, _ = _status_ipsec_child_sas_client()
    sas = client.get_status_ipsec_child_sas()
    assert len(sas) == 2
    for sa in sas:
        for field in STATUS_IPSEC_CHILD_SAS_IDENTIFYING_FIELDS:
            assert getattr(sa, field) is None


def test_get_status_ipsec_child_sas_includes_identifying_fields_when_requested():
    client, _ = _status_ipsec_child_sas_client()
    sas = client.get_status_ipsec_child_sas(include_identifying_metadata=True)
    first = next(s for s in sas if s.name == "con1")
    assert first.local_ts == ["198.51.100.0/24"]
    assert first.remote_ts == ["203.0.113.0/24"]


def test_get_status_ipsec_child_sas_maps_non_sensitive_fields():
    client, _ = _status_ipsec_child_sas_client()
    sas = client.get_status_ipsec_child_sas()
    first = next(s for s in sas if s.name == "con1")
    assert first.state == "INSTALLED"
    assert first.mode == "TUNNEL"
    assert first.bytes_in == 1024


def test_get_status_ipsec_child_sas_only_calls_endpoint_with_default_limit():
    client, transport = _status_ipsec_child_sas_client()
    client.get_status_ipsec_child_sas()
    assert transport.calls == [("GET", "/api/v2/status/ipsec/child_sas?limit=100")]


def test_get_status_ipsec_child_sas_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_ipsec_child_sas_body()
    transport.register("GET", "/api/v2/status/ipsec/child_sas?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_ipsec_child_sas(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/ipsec/child_sas?limit=5")]


def test_get_status_ipsec_child_sas_rejects_zero_limit():
    client, _ = _status_ipsec_child_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_child_sas(limit=0)


def test_get_status_ipsec_child_sas_rejects_limit_above_max():
    client, _ = _status_ipsec_child_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_child_sas(limit=101)


def test_get_status_ipsec_child_sas_invalid_limit_never_calls_transport():
    client, transport = _status_ipsec_child_sas_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_ipsec_child_sas(limit=0)
    assert transport.calls == []


def test_get_status_ipsec_child_sas_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    IPsec child SAs on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_ipsec_child_sas_client(body)
    assert client.get_status_ipsec_child_sas() == []


def test_get_status_ipsec_child_sas_missing_data_key_raises_shape_error():
    body = _status_ipsec_child_sas_body()
    del body["data"]
    client, _ = _status_ipsec_child_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_child_sas()


def test_get_status_ipsec_child_sas_item_wrong_type_raises_shape_error():
    body = _status_ipsec_child_sas_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_ipsec_child_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_child_sas()


def test_get_status_ipsec_child_sas_required_field_missing_raises_shape_error():
    body = _status_ipsec_child_sas_body()
    del body["data"][0]["name"]
    client, _ = _status_ipsec_child_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_ipsec_child_sas()


def test_get_status_ipsec_child_sas_shape_error_does_not_leak_raw_field_values():
    body = _status_ipsec_child_sas_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _status_ipsec_child_sas_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_ipsec_child_sas()
    assert sentinel not in str(excinfo.value)


STATUS_WIREGUARD_TUNNELS_FIXTURE = Path(__file__).parent / "fixtures" / "status_wireguard_tunnels_response.json"
STATUS_WIREGUARD_PEERS_FIXTURE = Path(__file__).parent / "fixtures" / "status_wireguard_peers_response.json"
WIREGUARD_PEER_STATUS_IDENTIFYING_FIELDS = ("allowed_ips", "endpoint")


def _status_wireguard_tunnels_body() -> dict:
    return json.loads(STATUS_WIREGUARD_TUNNELS_FIXTURE.read_text())


def _status_wireguard_tunnels_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_wireguard_tunnels_body()
    transport.register("GET", "/api/v2/status/wireguard/tunnels?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def _status_wireguard_peers_body() -> dict:
    return json.loads(STATUS_WIREGUARD_PEERS_FIXTURE.read_text())


def _status_wireguard_peers_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_wireguard_peers_body()
    transport.register("GET", "/api/v2/status/wireguard/peers?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_wireguard_peers_never_exposes_preshared_key_field():
    """preshared_key is confirmed present in the raw response (matching
    real WireGuard status behavior) but injected only in-memory here --
    never committed to a fixture file. The model must never expose it
    under any argument combination."""

    body = _status_wireguard_peers_body()
    for entry in body["data"]:
        entry["preshared_key"] = "SENTINEL-WIREGUARD-PRESHARED-KEY"
    client, _ = _status_wireguard_peers_client(body)
    for include in (False, True):
        peers = client.get_status_wireguard_peers(include_identifying_metadata=include)
        for peer in peers:
            assert not hasattr(peer, "preshared_key")
            assert "preshared_key" not in peer.model_dump()


def test_get_status_wireguard_peers_omits_identifying_fields_by_default():
    client, _ = _status_wireguard_peers_client()
    peers = client.get_status_wireguard_peers()
    assert len(peers) == 2
    for peer in peers:
        for field in WIREGUARD_PEER_STATUS_IDENTIFYING_FIELDS:
            assert getattr(peer, field) is None


def test_get_status_wireguard_peers_includes_identifying_fields_when_requested():
    client, _ = _status_wireguard_peers_client()
    peers = client.get_status_wireguard_peers(include_identifying_metadata=True)
    first = next(p for p in peers if p.tunnel_device == "tun_wg0")
    assert first.endpoint == "203.0.113.20:51820"
    assert first.allowed_ips == ["192.0.2.2/32"]


def test_get_status_wireguard_peers_maps_non_sensitive_fields():
    client, _ = _status_wireguard_peers_client()
    peers = client.get_status_wireguard_peers()
    first = next(p for p in peers if p.tunnel_device == "tun_wg0")
    assert first.public_key == "SYNTHETIC-PUBLIC-KEY-BASE64=="
    assert first.transfer_rx == 1024
    assert first.persistent_keepalive == "25"


def test_get_status_wireguard_peers_only_calls_endpoint_with_default_limit():
    client, transport = _status_wireguard_peers_client()
    client.get_status_wireguard_peers()
    assert transport.calls == [("GET", "/api/v2/status/wireguard/peers?limit=100")]


def test_get_status_wireguard_peers_rejects_zero_limit():
    client, _ = _status_wireguard_peers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_peers(limit=0)


def test_get_status_wireguard_peers_rejects_limit_above_max():
    client, _ = _status_wireguard_peers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_peers(limit=101)


def test_get_status_wireguard_peers_invalid_limit_never_calls_transport():
    client, transport = _status_wireguard_peers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_peers(limit=0)
    assert transport.calls == []


def test_get_status_wireguard_peers_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE, after
    owner-authorized pfSense-pkg-WireGuard installation) observed
    exactly this shape: HTTP 200, `{"data": []}` -- the raw response
    was inspected directly and contained no unexpected nested fields."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_wireguard_peers_client(body)
    assert client.get_status_wireguard_peers() == []


def test_get_status_wireguard_peers_missing_data_key_raises_shape_error():
    body = _status_wireguard_peers_body()
    del body["data"]
    client, _ = _status_wireguard_peers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_wireguard_peers()


def test_get_status_wireguard_peers_item_wrong_type_raises_shape_error():
    body = _status_wireguard_peers_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_wireguard_peers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_wireguard_peers()


def test_get_status_wireguard_peers_shape_error_does_not_leak_raw_field_values():
    body = _status_wireguard_peers_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _status_wireguard_peers_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_wireguard_peers()
    assert sentinel not in str(excinfo.value)


def test_get_status_wireguard_tunnels_maps_non_sensitive_fields():
    client, _ = _status_wireguard_tunnels_client()
    tunnels = client.get_status_wireguard_tunnels()
    assert len(tunnels) == 2
    first = next(t for t in tunnels if t.name == "tun_wg0")
    assert first.status == "up"
    assert first.public_key == "SYNTHETIC-TUNNEL-PUBLIC-KEY-BASE64=="
    assert first.listen_port == "51820"


def test_get_status_wireguard_tunnels_nested_peers_constructed_as_typed_objects():
    client, _ = _status_wireguard_tunnels_client()
    tunnels = client.get_status_wireguard_tunnels()
    first = next(t for t in tunnels if t.name == "tun_wg0")
    assert first.peers is not None
    assert len(first.peers) == 1
    assert first.peers[0].public_key == "SYNTHETIC-PUBLIC-KEY-BASE64=="


def test_get_status_wireguard_tunnels_nested_peers_never_expose_preshared_key():
    """Confirms the tunnel-status tool cannot leak a peer's
    preshared_key through its nested peers field, even though the raw
    per-peer object genuinely carries that field in real WireGuard
    status responses (injected in-memory only, never in a fixture)."""

    body = _status_wireguard_tunnels_body()
    body["data"][0]["peers"][0]["preshared_key"] = "SENTINEL-WIREGUARD-PRESHARED-KEY"
    client, _ = _status_wireguard_tunnels_client(body)
    tunnels = client.get_status_wireguard_tunnels()
    first = next(t for t in tunnels if t.name == "tun_wg0")
    assert not hasattr(first.peers[0], "preshared_key")
    assert "preshared_key" not in first.peers[0].model_dump()


def test_get_status_wireguard_tunnels_nested_peers_redaction_follows_parent_flag():
    client, _ = _status_wireguard_tunnels_client()
    tunnels = client.get_status_wireguard_tunnels()
    first = next(t for t in tunnels if t.name == "tun_wg0")
    assert first.peers[0].endpoint is None

    tunnels_revealed = client.get_status_wireguard_tunnels(include_identifying_metadata=True)
    first_revealed = next(t for t in tunnels_revealed if t.name == "tun_wg0")
    assert first_revealed.peers[0].endpoint == "203.0.113.20:51820"


def test_get_status_wireguard_tunnels_handles_null_peers():
    client, _ = _status_wireguard_tunnels_client()
    tunnels = client.get_status_wireguard_tunnels()
    second = next(t for t in tunnels if t.name is None)
    assert second.peers is None


def test_get_status_wireguard_tunnels_only_calls_endpoint_with_default_limit():
    client, transport = _status_wireguard_tunnels_client()
    client.get_status_wireguard_tunnels()
    assert transport.calls == [("GET", "/api/v2/status/wireguard/tunnels?limit=100")]


def test_get_status_wireguard_tunnels_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_wireguard_tunnels_body()
    transport.register("GET", "/api/v2/status/wireguard/tunnels?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_wireguard_tunnels(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/wireguard/tunnels?limit=5")]


def test_get_status_wireguard_tunnels_rejects_zero_limit():
    client, _ = _status_wireguard_tunnels_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_tunnels(limit=0)


def test_get_status_wireguard_tunnels_rejects_limit_above_max():
    client, _ = _status_wireguard_tunnels_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_tunnels(limit=101)


def test_get_status_wireguard_tunnels_invalid_limit_never_calls_transport():
    client, transport = _status_wireguard_tunnels_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_wireguard_tunnels(limit=0)
    assert transport.calls == []


def test_get_status_wireguard_tunnels_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE, after
    owner-authorized pfSense-pkg-WireGuard installation) observed
    exactly this shape: HTTP 200, `{"data": []}` -- the raw response
    was inspected directly and contained no unexpected nested fields."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_wireguard_tunnels_client(body)
    assert client.get_status_wireguard_tunnels() == []


def test_get_status_wireguard_tunnels_missing_data_key_raises_shape_error():
    body = _status_wireguard_tunnels_body()
    del body["data"]
    client, _ = _status_wireguard_tunnels_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_wireguard_tunnels()


def test_get_status_wireguard_tunnels_item_wrong_type_raises_shape_error():
    body = _status_wireguard_tunnels_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_wireguard_tunnels_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_wireguard_tunnels()


def test_get_status_wireguard_tunnels_required_field_missing_raises_shape_error():
    body = _status_wireguard_tunnels_body()
    del body["data"][0]["name"]
    client, _ = _status_wireguard_tunnels_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_wireguard_tunnels()


def test_get_status_wireguard_tunnels_shape_error_does_not_leak_raw_field_values():
    body = _status_wireguard_tunnels_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _status_wireguard_tunnels_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_wireguard_tunnels()
    assert sentinel not in str(excinfo.value)


STATUS_OPENVPN_SERVER_CONNECTIONS_FIXTURE = (
    Path(__file__).parent / "fixtures" / "status_openvpn_server_connections_response.json"
)
STATUS_OPENVPN_SERVER_CONNECTIONS_IDENTIFYING_FIELDS = (
    "common_name",
    "remote_host",
    "user_name",
    "virtual_addr",
    "virtual_addr6",
)


def _status_openvpn_server_connections_body() -> dict:
    return json.loads(STATUS_OPENVPN_SERVER_CONNECTIONS_FIXTURE.read_text())


def _status_openvpn_server_connections_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_openvpn_server_connections_body()
    transport.register(
        "GET", "/api/v2/status/openvpn/server/connections?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_openvpn_server_connections_omits_identifying_fields_by_default():
    client, _ = _status_openvpn_server_connections_client()
    conns = client.get_status_openvpn_server_connections()
    assert len(conns) == 2
    for conn in conns:
        for field in STATUS_OPENVPN_SERVER_CONNECTIONS_IDENTIFYING_FIELDS:
            assert getattr(conn, field) is None


def test_get_status_openvpn_server_connections_includes_identifying_fields_when_requested():
    client, _ = _status_openvpn_server_connections_client()
    conns = client.get_status_openvpn_server_connections(include_identifying_metadata=True)
    first = next(c for c in conns if c.client_id == 1)
    assert first.common_name == "client1.example.invalid"
    assert first.remote_host == "203.0.113.30"
    assert first.user_name == "vpnuser1"
    assert first.virtual_addr == "198.51.100.70"


def test_get_status_openvpn_server_connections_maps_non_sensitive_fields():
    client, _ = _status_openvpn_server_connections_client()
    conns = client.get_status_openvpn_server_connections()
    first = next(c for c in conns if c.client_id == 1)
    assert first.cipher == "AES-256-GCM"
    assert first.bytes_recv == 1024
    assert first.bytes_sent == 2048


def test_get_status_openvpn_server_connections_only_calls_endpoint_with_default_limit():
    client, transport = _status_openvpn_server_connections_client()
    client.get_status_openvpn_server_connections()
    assert transport.calls == [("GET", "/api/v2/status/openvpn/server/connections?limit=100")]


def test_get_status_openvpn_server_connections_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_openvpn_server_connections_body()
    transport.register(
        "GET", "/api/v2/status/openvpn/server/connections?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_openvpn_server_connections(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/openvpn/server/connections?limit=5")]


def test_get_status_openvpn_server_connections_rejects_zero_limit():
    client, _ = _status_openvpn_server_connections_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_connections(limit=0)


def test_get_status_openvpn_server_connections_rejects_limit_above_max():
    client, _ = _status_openvpn_server_connections_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_connections(limit=101)


def test_get_status_openvpn_server_connections_invalid_limit_never_calls_transport():
    client, transport = _status_openvpn_server_connections_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_connections(limit=0)
    assert transport.calls == []


def test_get_status_openvpn_server_connections_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero active OpenVPN
    server connections on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_openvpn_server_connections_client(body)
    assert client.get_status_openvpn_server_connections() == []


def test_get_status_openvpn_server_connections_missing_data_key_raises_shape_error():
    body = _status_openvpn_server_connections_body()
    del body["data"]
    client, _ = _status_openvpn_server_connections_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_connections()


def test_get_status_openvpn_server_connections_item_wrong_type_raises_shape_error():
    body = _status_openvpn_server_connections_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_openvpn_server_connections_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_connections()


def test_get_status_openvpn_server_connections_required_field_missing_raises_shape_error():
    body = _status_openvpn_server_connections_body()
    del body["data"][0]["cipher"]
    client, _ = _status_openvpn_server_connections_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_connections()


def test_get_status_openvpn_server_connections_shape_error_does_not_leak_raw_field_values():
    body = _status_openvpn_server_connections_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["cipher"] = [sentinel]
    client, _ = _status_openvpn_server_connections_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_openvpn_server_connections()
    assert sentinel not in str(excinfo.value)


STATUS_OPENVPN_SERVER_ROUTES_FIXTURE = Path(__file__).parent / "fixtures" / "status_openvpn_server_routes_response.json"
STATUS_OPENVPN_SERVER_ROUTES_IDENTIFYING_FIELDS = ("common_name", "remote_host", "virtual_addr")


def _status_openvpn_server_routes_body() -> dict:
    return json.loads(STATUS_OPENVPN_SERVER_ROUTES_FIXTURE.read_text())


def _status_openvpn_server_routes_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_openvpn_server_routes_body()
    transport.register(
        "GET", "/api/v2/status/openvpn/server/routes?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_openvpn_server_routes_omits_identifying_fields_by_default():
    client, _ = _status_openvpn_server_routes_client()
    routes = client.get_status_openvpn_server_routes()
    assert len(routes) == 2
    for route in routes:
        for field in STATUS_OPENVPN_SERVER_ROUTES_IDENTIFYING_FIELDS:
            assert getattr(route, field) is None


def test_get_status_openvpn_server_routes_includes_identifying_fields_when_requested():
    client, _ = _status_openvpn_server_routes_client()
    routes = client.get_status_openvpn_server_routes(include_identifying_metadata=True)
    first = next(r for r in routes if r.common_name == "client1.example.invalid")
    assert first.remote_host == "203.0.113.30"
    assert first.virtual_addr == "198.51.100.70"


def test_get_status_openvpn_server_routes_maps_non_sensitive_fields():
    client, _ = _status_openvpn_server_routes_client()
    routes = client.get_status_openvpn_server_routes()
    first = next(r for r in routes if r.last_time is not None)
    assert first.last_time == "Fri Aug 21 00:00:00 2026"


def test_get_status_openvpn_server_routes_only_calls_endpoint_with_default_limit():
    client, transport = _status_openvpn_server_routes_client()
    client.get_status_openvpn_server_routes()
    assert transport.calls == [("GET", "/api/v2/status/openvpn/server/routes?limit=100")]


def test_get_status_openvpn_server_routes_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_openvpn_server_routes_body()
    transport.register("GET", "/api/v2/status/openvpn/server/routes?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_openvpn_server_routes(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/openvpn/server/routes?limit=5")]


def test_get_status_openvpn_server_routes_rejects_zero_limit():
    client, _ = _status_openvpn_server_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_routes(limit=0)


def test_get_status_openvpn_server_routes_rejects_limit_above_max():
    client, _ = _status_openvpn_server_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_routes(limit=101)


def test_get_status_openvpn_server_routes_invalid_limit_never_calls_transport():
    client, transport = _status_openvpn_server_routes_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_server_routes(limit=0)
    assert transport.calls == []


def test_get_status_openvpn_server_routes_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero OpenVPN server
    routes on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_openvpn_server_routes_client(body)
    assert client.get_status_openvpn_server_routes() == []


def test_get_status_openvpn_server_routes_missing_data_key_raises_shape_error():
    body = _status_openvpn_server_routes_body()
    del body["data"]
    client, _ = _status_openvpn_server_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_routes()


def test_get_status_openvpn_server_routes_item_wrong_type_raises_shape_error():
    body = _status_openvpn_server_routes_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_openvpn_server_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_routes()


def test_get_status_openvpn_server_routes_required_field_missing_raises_shape_error():
    body = _status_openvpn_server_routes_body()
    del body["data"][0]["last_time"]
    client, _ = _status_openvpn_server_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_server_routes()


def test_get_status_openvpn_server_routes_shape_error_does_not_leak_raw_field_values():
    body = _status_openvpn_server_routes_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["last_time"] = [sentinel]
    client, _ = _status_openvpn_server_routes_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_openvpn_server_routes()
    assert sentinel not in str(excinfo.value)


STATUS_OPENVPN_SERVERS_FIXTURE = Path(__file__).parent / "fixtures" / "status_openvpn_servers_response.json"


def _status_openvpn_servers_body() -> dict:
    return json.loads(STATUS_OPENVPN_SERVERS_FIXTURE.read_text())


def _status_openvpn_servers_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_openvpn_servers_body()
    transport.register("GET", "/api/v2/status/openvpn/servers?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_openvpn_servers_maps_non_sensitive_fields():
    client, _ = _status_openvpn_servers_client()
    servers = client.get_status_openvpn_servers()
    assert len(servers) == 2
    first = next(s for s in servers if s.name == "server1")
    assert first.mode == "server_tls"
    assert first.port == "1194"
    assert first.vpnid == 1


def test_get_status_openvpn_servers_nested_conns_and_routes_constructed_as_typed_objects():
    client, _ = _status_openvpn_servers_client()
    servers = client.get_status_openvpn_servers()
    first = next(s for s in servers if s.name == "server1")
    assert first.conns is not None and len(first.conns) == 1
    assert first.conns[0].cipher == "AES-256-GCM"
    assert first.routes is not None and len(first.routes) == 1
    assert first.routes[0].last_time == "Fri Aug 21 00:00:00 2026"


def test_get_status_openvpn_servers_nested_redaction_follows_parent_flag():
    client, _ = _status_openvpn_servers_client()
    servers = client.get_status_openvpn_servers()
    first = next(s for s in servers if s.name == "server1")
    assert first.conns[0].common_name is None
    assert first.routes[0].common_name is None

    servers_revealed = client.get_status_openvpn_servers(include_identifying_metadata=True)
    first_revealed = next(s for s in servers_revealed if s.name == "server1")
    assert first_revealed.conns[0].common_name == "client1.example.invalid"
    assert first_revealed.routes[0].common_name == "client1.example.invalid"


def test_get_status_openvpn_servers_handles_null_conns_and_routes():
    client, _ = _status_openvpn_servers_client()
    servers = client.get_status_openvpn_servers()
    second = next(s for s in servers if s.name is None)
    assert second.conns is None
    assert second.routes is None


def test_get_status_openvpn_servers_only_calls_endpoint_with_default_limit():
    client, transport = _status_openvpn_servers_client()
    client.get_status_openvpn_servers()
    assert transport.calls == [("GET", "/api/v2/status/openvpn/servers?limit=100")]


def test_get_status_openvpn_servers_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_openvpn_servers_body()
    transport.register("GET", "/api/v2/status/openvpn/servers?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_openvpn_servers(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/openvpn/servers?limit=5")]


def test_get_status_openvpn_servers_rejects_zero_limit():
    client, _ = _status_openvpn_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_servers(limit=0)


def test_get_status_openvpn_servers_rejects_limit_above_max():
    client, _ = _status_openvpn_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_servers(limit=101)


def test_get_status_openvpn_servers_invalid_limit_never_calls_transport():
    client, transport = _status_openvpn_servers_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_servers(limit=0)
    assert transport.calls == []


def test_get_status_openvpn_servers_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    OpenVPN servers on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_openvpn_servers_client(body)
    assert client.get_status_openvpn_servers() == []


def test_get_status_openvpn_servers_missing_data_key_raises_shape_error():
    body = _status_openvpn_servers_body()
    del body["data"]
    client, _ = _status_openvpn_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_servers()


def test_get_status_openvpn_servers_item_wrong_type_raises_shape_error():
    body = _status_openvpn_servers_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_openvpn_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_servers()


def test_get_status_openvpn_servers_required_field_missing_raises_shape_error():
    body = _status_openvpn_servers_body()
    del body["data"][0]["mode"]
    client, _ = _status_openvpn_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_servers()


def test_get_status_openvpn_servers_shape_error_does_not_leak_raw_field_values():
    body = _status_openvpn_servers_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["mode"] = [sentinel]
    client, _ = _status_openvpn_servers_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_openvpn_servers()
    assert sentinel not in str(excinfo.value)


STATUS_OPENVPN_CLIENTS_FIXTURE = Path(__file__).parent / "fixtures" / "status_openvpn_clients_response.json"
STATUS_OPENVPN_CLIENTS_IDENTIFYING_FIELDS = ("local_host", "remote_host", "virtual_addr", "virtual_addr6")


def _status_openvpn_clients_body() -> dict:
    return json.loads(STATUS_OPENVPN_CLIENTS_FIXTURE.read_text())


def _status_openvpn_clients_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _status_openvpn_clients_body()
    transport.register("GET", "/api/v2/status/openvpn/clients?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_status_openvpn_clients_omits_identifying_fields_by_default():
    client, _ = _status_openvpn_clients_client()
    clients = client.get_status_openvpn_clients()
    assert len(clients) == 2
    for c in clients:
        for field in STATUS_OPENVPN_CLIENTS_IDENTIFYING_FIELDS:
            assert getattr(c, field) is None


def test_get_status_openvpn_clients_includes_identifying_fields_when_requested():
    client, _ = _status_openvpn_clients_client()
    clients = client.get_status_openvpn_clients(include_identifying_metadata=True)
    first = next(c for c in clients if c.name == "client1")
    assert first.local_host == "198.51.100.1"
    assert first.remote_host == "203.0.113.40"
    assert first.virtual_addr == "198.51.100.80"


def test_get_status_openvpn_clients_maps_non_sensitive_fields():
    client, _ = _status_openvpn_clients_client()
    clients = client.get_status_openvpn_clients()
    first = next(c for c in clients if c.name == "client1")
    assert first.status == "up"
    assert first.state == "CONNECTED"
    assert first.vpnid == 1


def test_get_status_openvpn_clients_only_calls_endpoint_with_default_limit():
    client, transport = _status_openvpn_clients_client()
    client.get_status_openvpn_clients()
    assert transport.calls == [("GET", "/api/v2/status/openvpn/clients?limit=100")]


def test_get_status_openvpn_clients_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _status_openvpn_clients_body()
    transport.register("GET", "/api/v2/status/openvpn/clients?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_status_openvpn_clients(limit=5)
    assert transport.calls == [("GET", "/api/v2/status/openvpn/clients?limit=5")]


def test_get_status_openvpn_clients_rejects_zero_limit():
    client, _ = _status_openvpn_clients_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_clients(limit=0)


def test_get_status_openvpn_clients_rejects_limit_above_max():
    client, _ = _status_openvpn_clients_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_clients(limit=101)


def test_get_status_openvpn_clients_invalid_limit_never_calls_transport():
    client, transport = _status_openvpn_clients_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_status_openvpn_clients(limit=0)
    assert transport.calls == []


def test_get_status_openvpn_clients_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    OpenVPN clients on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _status_openvpn_clients_client(body)
    assert client.get_status_openvpn_clients() == []


def test_get_status_openvpn_clients_missing_data_key_raises_shape_error():
    body = _status_openvpn_clients_body()
    del body["data"]
    client, _ = _status_openvpn_clients_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_clients()


def test_get_status_openvpn_clients_item_wrong_type_raises_shape_error():
    body = _status_openvpn_clients_body()
    body["data"] = ["not-an-object"]
    client, _ = _status_openvpn_clients_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_clients()


def test_get_status_openvpn_clients_required_field_missing_raises_shape_error():
    body = _status_openvpn_clients_body()
    del body["data"][0]["status"]
    client, _ = _status_openvpn_clients_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_status_openvpn_clients()


def test_get_status_openvpn_clients_shape_error_does_not_leak_raw_field_values():
    body = _status_openvpn_clients_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["status"] = [sentinel]
    client, _ = _status_openvpn_clients_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_status_openvpn_clients()
    assert sentinel not in str(excinfo.value)


DNS_FORWARDER_HOST_OVERRIDES_FIXTURE = Path(__file__).parent / "fixtures" / "dns_forwarder_host_overrides_response.json"


def _dns_forwarder_host_overrides_body() -> dict:
    return json.loads(DNS_FORWARDER_HOST_OVERRIDES_FIXTURE.read_text())


def _dns_forwarder_host_overrides_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dns_forwarder_host_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_forwarder/host_overrides?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dns_forwarder_host_overrides_maps_fields():
    client, _ = _dns_forwarder_host_overrides_client()
    raw = _dns_forwarder_host_overrides_body()["data"]
    overrides = client.get_dns_forwarder_host_overrides()
    assert len(overrides) == 2
    assert overrides[0].host == raw[0]["host"]
    assert overrides[0].domain == raw[0]["domain"]
    assert overrides[0].ip == raw[0]["ip"]
    assert overrides[1].aliases == raw[1]["aliases"]


def test_get_dns_forwarder_host_overrides_only_calls_endpoint_with_default_limit():
    client, transport = _dns_forwarder_host_overrides_client()
    client.get_dns_forwarder_host_overrides()
    assert transport.calls == [("GET", "/api/v2/services/dns_forwarder/host_overrides?limit=100")]


def test_get_dns_forwarder_host_overrides_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dns_forwarder_host_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_forwarder/host_overrides?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dns_forwarder_host_overrides(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/dns_forwarder/host_overrides?limit=5")]


def test_get_dns_forwarder_host_overrides_rejects_zero_limit():
    client, _ = _dns_forwarder_host_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_forwarder_host_overrides(limit=0)


def test_get_dns_forwarder_host_overrides_rejects_limit_above_max():
    client, _ = _dns_forwarder_host_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_forwarder_host_overrides(limit=101)


def test_get_dns_forwarder_host_overrides_invalid_limit_never_calls_transport():
    client, transport = _dns_forwarder_host_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_forwarder_host_overrides(limit=0)
    assert transport.calls == []


def test_get_dns_forwarder_host_overrides_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    host overrides on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _dns_forwarder_host_overrides_client(body)
    assert client.get_dns_forwarder_host_overrides() == []


def test_get_dns_forwarder_host_overrides_missing_data_key_raises_shape_error():
    body = _dns_forwarder_host_overrides_body()
    del body["data"]
    client, _ = _dns_forwarder_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_forwarder_host_overrides()


def test_get_dns_forwarder_host_overrides_item_wrong_type_raises_shape_error():
    body = _dns_forwarder_host_overrides_body()
    body["data"] = ["not-an-object"]
    client, _ = _dns_forwarder_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_forwarder_host_overrides()


def test_get_dns_forwarder_host_overrides_required_field_missing_raises_shape_error():
    body = _dns_forwarder_host_overrides_body()
    del body["data"][0]["ip"]
    client, _ = _dns_forwarder_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_forwarder_host_overrides()


def test_get_dns_forwarder_host_overrides_shape_error_does_not_leak_raw_field_values():
    body = _dns_forwarder_host_overrides_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["ip"] = [sentinel]
    client, _ = _dns_forwarder_host_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dns_forwarder_host_overrides()
    assert sentinel not in str(excinfo.value)


DNS_RESOLVER_DOMAIN_OVERRIDES_FIXTURE = (
    Path(__file__).parent / "fixtures" / "dns_resolver_domain_overrides_response.json"
)


def _dns_resolver_domain_overrides_body() -> dict:
    return json.loads(DNS_RESOLVER_DOMAIN_OVERRIDES_FIXTURE.read_text())


def _dns_resolver_domain_overrides_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dns_resolver_domain_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/domain_overrides?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dns_resolver_domain_overrides_maps_fields():
    client, _ = _dns_resolver_domain_overrides_client()
    raw = _dns_resolver_domain_overrides_body()["data"]
    overrides = client.get_dns_resolver_domain_overrides()
    assert len(overrides) == 2
    assert overrides[0].domain == raw[0]["domain"]
    assert overrides[0].ip == raw[0]["ip"]
    assert overrides[1].forward_tls_upstream is True
    assert overrides[1].tls_hostname == "resolver.example.invalid"


def test_get_dns_resolver_domain_overrides_only_calls_endpoint_with_default_limit():
    client, transport = _dns_resolver_domain_overrides_client()
    client.get_dns_resolver_domain_overrides()
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/domain_overrides?limit=100")]


def test_get_dns_resolver_domain_overrides_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dns_resolver_domain_overrides_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/domain_overrides?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dns_resolver_domain_overrides(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/domain_overrides?limit=5")]


def test_get_dns_resolver_domain_overrides_rejects_zero_limit():
    client, _ = _dns_resolver_domain_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_domain_overrides(limit=0)


def test_get_dns_resolver_domain_overrides_rejects_limit_above_max():
    client, _ = _dns_resolver_domain_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_domain_overrides(limit=101)


def test_get_dns_resolver_domain_overrides_invalid_limit_never_calls_transport():
    client, transport = _dns_resolver_domain_overrides_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_domain_overrides(limit=0)
    assert transport.calls == []


def test_get_dns_resolver_domain_overrides_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    domain overrides on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _dns_resolver_domain_overrides_client(body)
    assert client.get_dns_resolver_domain_overrides() == []


def test_get_dns_resolver_domain_overrides_missing_data_key_raises_shape_error():
    body = _dns_resolver_domain_overrides_body()
    del body["data"]
    client, _ = _dns_resolver_domain_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_domain_overrides()


def test_get_dns_resolver_domain_overrides_item_wrong_type_raises_shape_error():
    body = _dns_resolver_domain_overrides_body()
    body["data"] = ["not-an-object"]
    client, _ = _dns_resolver_domain_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_domain_overrides()


def test_get_dns_resolver_domain_overrides_required_field_missing_raises_shape_error():
    body = _dns_resolver_domain_overrides_body()
    del body["data"][0]["ip"]
    client, _ = _dns_resolver_domain_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_domain_overrides()


def test_get_dns_resolver_domain_overrides_shape_error_does_not_leak_raw_field_values():
    body = _dns_resolver_domain_overrides_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["ip"] = [sentinel]
    client, _ = _dns_resolver_domain_overrides_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dns_resolver_domain_overrides()
    assert sentinel not in str(excinfo.value)


DNS_RESOLVER_ACCESS_LISTS_FIXTURE = Path(__file__).parent / "fixtures" / "dns_resolver_access_lists_response.json"


def _dns_resolver_access_lists_body() -> dict:
    return json.loads(DNS_RESOLVER_ACCESS_LISTS_FIXTURE.read_text())


def _dns_resolver_access_lists_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dns_resolver_access_lists_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/access_lists?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dns_resolver_access_lists_maps_fields():
    client, _ = _dns_resolver_access_lists_client()
    raw = _dns_resolver_access_lists_body()["data"]
    acls = client.get_dns_resolver_access_lists()
    assert len(acls) == 2
    assert acls[0].name == raw[0]["name"]
    assert acls[0].action == raw[0]["action"]
    assert acls[0].networks == raw[0]["networks"]
    assert acls[1].networks == []


def test_get_dns_resolver_access_lists_only_calls_endpoint_with_default_limit():
    client, transport = _dns_resolver_access_lists_client()
    client.get_dns_resolver_access_lists()
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/access_lists?limit=100")]


def test_get_dns_resolver_access_lists_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dns_resolver_access_lists_body()
    transport.register(
        "GET", "/api/v2/services/dns_resolver/access_lists?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dns_resolver_access_lists(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/dns_resolver/access_lists?limit=5")]


def test_get_dns_resolver_access_lists_rejects_zero_limit():
    client, _ = _dns_resolver_access_lists_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_access_lists(limit=0)


def test_get_dns_resolver_access_lists_rejects_limit_above_max():
    client, _ = _dns_resolver_access_lists_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_access_lists(limit=101)


def test_get_dns_resolver_access_lists_invalid_limit_never_calls_transport():
    client, transport = _dns_resolver_access_lists_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dns_resolver_access_lists(limit=0)
    assert transport.calls == []


def test_get_dns_resolver_access_lists_parses_empty_list():
    """2026-08-21 LAB verification (pfSense CE 2.9.0-RELEASE) observed
    exactly this shape: HTTP 200, `{"data": []}` -- zero configured
    access lists on the LAB appliance at verification time."""

    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _dns_resolver_access_lists_client(body)
    assert client.get_dns_resolver_access_lists() == []


def test_get_dns_resolver_access_lists_missing_data_key_raises_shape_error():
    body = _dns_resolver_access_lists_body()
    del body["data"]
    client, _ = _dns_resolver_access_lists_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_access_lists()


def test_get_dns_resolver_access_lists_item_wrong_type_raises_shape_error():
    body = _dns_resolver_access_lists_body()
    body["data"] = ["not-an-object"]
    client, _ = _dns_resolver_access_lists_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_access_lists()


def test_get_dns_resolver_access_lists_required_field_missing_raises_shape_error():
    body = _dns_resolver_access_lists_body()
    del body["data"][0]["name"]
    client, _ = _dns_resolver_access_lists_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dns_resolver_access_lists()


def test_get_dns_resolver_access_lists_shape_error_does_not_leak_raw_field_values():
    body = _dns_resolver_access_lists_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _dns_resolver_access_lists_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dns_resolver_access_lists()
    assert sentinel not in str(excinfo.value)


INTERFACE_AVAILABLE_INTERFACES_FIXTURE = (
    Path(__file__).parent / "fixtures" / "interface_available_interfaces_response.json"
)
INTERFACE_AVAILABLE_INTERFACES_IDENTIFYING_FIELDS = ("mac",)


def _interface_available_interfaces_body() -> dict:
    return json.loads(INTERFACE_AVAILABLE_INTERFACES_FIXTURE.read_text())


def _interface_available_interfaces_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_available_interfaces_body()
    transport.register(
        "GET", "/api/v2/interface/available_interfaces?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_available_interfaces_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _interface_available_interfaces_client(body)
    assert client.get_interface_available_interfaces() == []


def test_get_interface_available_interfaces_omits_identifying_fields_by_default():
    client, _ = _interface_available_interfaces_client()
    interfaces = client.get_interface_available_interfaces()
    assert len(interfaces) == 2
    for interface in interfaces:
        for field in INTERFACE_AVAILABLE_INTERFACES_IDENTIFYING_FIELDS:
            assert getattr(interface, field) is None


def test_get_interface_available_interfaces_includes_identifying_fields_when_requested():
    client, _ = _interface_available_interfaces_client()
    interfaces = client.get_interface_available_interfaces(include_identifying_metadata=True)
    first = next(i for i in interfaces if i.if_ == "igb0")
    assert first.mac == "02:00:00:aa:bb:cc"


def test_get_interface_available_interfaces_maps_non_sensitive_fields():
    client, _ = _interface_available_interfaces_client()
    interfaces = client.get_interface_available_interfaces()
    first = next(i for i in interfaces if i.if_ == "igb0")
    assert first.in_use_by == "wan"
    assert first.dmesg is not None and "igb0" in first.dmesg
    second = next(i for i in interfaces if i.if_ == "igb1")
    assert second.dmesg is None
    assert second.in_use_by is None


def test_get_interface_available_interfaces_only_calls_endpoint_with_default_limit():
    client, transport = _interface_available_interfaces_client()
    client.get_interface_available_interfaces()
    assert transport.calls == [("GET", "/api/v2/interface/available_interfaces?limit=100")]


def test_get_interface_available_interfaces_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_available_interfaces_body()
    transport.register("GET", "/api/v2/interface/available_interfaces?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_available_interfaces(limit=5)
    assert transport.calls == [("GET", "/api/v2/interface/available_interfaces?limit=5")]


def test_get_interface_available_interfaces_rejects_zero_limit():
    client, _ = _interface_available_interfaces_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_available_interfaces(limit=0)


def test_get_interface_available_interfaces_rejects_limit_above_max():
    client, _ = _interface_available_interfaces_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_available_interfaces(limit=101)


def test_get_interface_available_interfaces_invalid_limit_never_calls_transport():
    client, transport = _interface_available_interfaces_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_available_interfaces(limit=0)
    assert transport.calls == []


def test_get_interface_available_interfaces_missing_data_key_raises_shape_error():
    body = _interface_available_interfaces_body()
    del body["data"]
    client, _ = _interface_available_interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_available_interfaces()


def test_get_interface_available_interfaces_item_wrong_type_raises_shape_error():
    body = _interface_available_interfaces_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_available_interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_available_interfaces()


def test_get_interface_available_interfaces_required_field_missing_raises_shape_error():
    body = _interface_available_interfaces_body()
    del body["data"][0]["if"]
    client, _ = _interface_available_interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_available_interfaces()


def test_get_interface_available_interfaces_shape_error_does_not_leak_raw_field_values():
    body = _interface_available_interfaces_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["dmesg"] = [sentinel]
    client, _ = _interface_available_interfaces_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_available_interfaces()
    assert sentinel not in str(excinfo.value)


INTERFACE_GRES_FIXTURE = Path(__file__).parent / "fixtures" / "interface_gres_response.json"
INTERFACE_GRES_IDENTIFYING_FIELDS = (
    "remote_addr",
    "tunnel_local_addr",
    "tunnel_remote_addr",
    "tunnel_remote_net",
    "tunnel_local_addr6",
    "tunnel_remote_addr6",
    "tunnel_remote_net6",
)


def _interface_gres_body() -> dict:
    return json.loads(INTERFACE_GRES_FIXTURE.read_text())


def _interface_gres_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_gres_body()
    transport.register("GET", "/api/v2/interface/gres?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_gres_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _interface_gres_client(body)
    assert client.get_interface_gres() == []


def test_get_interface_gres_omits_identifying_fields_by_default():
    client, _ = _interface_gres_client()
    tunnels = client.get_interface_gres()
    assert len(tunnels) == 2
    for tunnel in tunnels:
        for field in INTERFACE_GRES_IDENTIFYING_FIELDS:
            assert getattr(tunnel, field) is None


def test_get_interface_gres_includes_identifying_fields_when_requested():
    client, _ = _interface_gres_client()
    tunnels = client.get_interface_gres(include_identifying_metadata=True)
    first = next(t for t in tunnels if t.if_ == "igb1")
    assert first.remote_addr == "198.51.100.10"
    assert first.tunnel_local_addr == "203.0.113.1"
    assert first.tunnel_remote_addr == "203.0.113.2"
    assert first.tunnel_remote_net == 30
    assert first.tunnel_local_addr6 == "2001:db8::1"
    assert first.tunnel_remote_addr6 == "2001:db8::2"
    assert first.tunnel_remote_net6 == 126


def test_get_interface_gres_maps_non_sensitive_fields():
    client, _ = _interface_gres_client()
    tunnels = client.get_interface_gres()
    first = next(t for t in tunnels if t.if_ == "igb1")
    assert first.greif == "gre0"
    assert first.descr == "Synthetic GRE tunnel (offline fixture)"
    assert first.add_static_route is True


def test_get_interface_gres_only_calls_endpoint_with_default_limit():
    client, transport = _interface_gres_client()
    client.get_interface_gres()
    assert transport.calls == [("GET", "/api/v2/interface/gres?limit=100")]


def test_get_interface_gres_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_gres_body()
    transport.register("GET", "/api/v2/interface/gres?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_gres(limit=5)
    assert transport.calls == [("GET", "/api/v2/interface/gres?limit=5")]


def test_get_interface_gres_rejects_zero_limit():
    client, _ = _interface_gres_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_gres(limit=0)


def test_get_interface_gres_rejects_limit_above_max():
    client, _ = _interface_gres_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_gres(limit=101)


def test_get_interface_gres_invalid_limit_never_calls_transport():
    client, transport = _interface_gres_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_gres(limit=0)
    assert transport.calls == []


def test_get_interface_gres_missing_data_key_raises_shape_error():
    body = _interface_gres_body()
    del body["data"]
    client, _ = _interface_gres_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_gres()


def test_get_interface_gres_item_wrong_type_raises_shape_error():
    body = _interface_gres_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_gres_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_gres()


def test_get_interface_gres_required_field_missing_raises_shape_error():
    body = _interface_gres_body()
    del body["data"][0]["descr"]
    client, _ = _interface_gres_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_gres()


def test_get_interface_gres_shape_error_does_not_leak_raw_field_values():
    body = _interface_gres_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _interface_gres_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_gres()
    assert sentinel not in str(excinfo.value)


INTERFACE_LAGGS_FIXTURE = Path(__file__).parent / "fixtures" / "interface_laggs_response.json"


def _interface_laggs_body() -> dict:
    return json.loads(INTERFACE_LAGGS_FIXTURE.read_text())


def _interface_laggs_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _interface_laggs_body()
    transport.register("GET", "/api/v2/interface/laggs?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_interface_laggs_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _interface_laggs_client(body)
    assert client.get_interface_laggs() == []


def test_get_interface_laggs_maps_fields():
    client, _ = _interface_laggs_client()
    laggs = client.get_interface_laggs()
    first = next(lagg for lagg in laggs if lagg.laggif == "lagg0")
    assert first.descr == "Synthetic LAGG (offline fixture)"
    assert first.members == ["igb1", "igb2"]
    assert first.proto == "lacp"
    assert first.lacptimeout == "fast"
    assert first.lagghash == "l2,l3,l4"
    assert first.failovermaster == "auto"


def test_get_interface_laggs_tolerates_missing_conditional_fields():
    """`lacptimeout`/`lagghash`/`failovermaster` are each schema-documented
    as only available for specific `proto` values -- confirm the model
    falls back to the schema's own declared default when a conditional
    field is genuinely absent from a live item, rather than raising a
    shape error."""

    body = _interface_laggs_body()
    del body["data"][0]["lacptimeout"]
    del body["data"][0]["lagghash"]
    del body["data"][0]["failovermaster"]
    client, _ = _interface_laggs_client(body)
    laggs = client.get_interface_laggs()
    first = next(lagg for lagg in laggs if lagg.laggif == "lagg0")
    assert first.lacptimeout == "slow"
    assert first.lagghash == "l2,l3,l4"
    assert first.failovermaster == "auto"


def test_get_interface_laggs_only_calls_endpoint_with_default_limit():
    client, transport = _interface_laggs_client()
    client.get_interface_laggs()
    assert transport.calls == [("GET", "/api/v2/interface/laggs?limit=100")]


def test_get_interface_laggs_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _interface_laggs_body()
    transport.register("GET", "/api/v2/interface/laggs?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_interface_laggs(limit=5)
    assert transport.calls == [("GET", "/api/v2/interface/laggs?limit=5")]


def test_get_interface_laggs_rejects_zero_limit():
    client, _ = _interface_laggs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_laggs(limit=0)


def test_get_interface_laggs_rejects_limit_above_max():
    client, _ = _interface_laggs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_laggs(limit=101)


def test_get_interface_laggs_invalid_limit_never_calls_transport():
    client, transport = _interface_laggs_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_interface_laggs(limit=0)
    assert transport.calls == []


def test_get_interface_laggs_missing_data_key_raises_shape_error():
    body = _interface_laggs_body()
    del body["data"]
    client, _ = _interface_laggs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_laggs()


def test_get_interface_laggs_item_wrong_type_raises_shape_error():
    body = _interface_laggs_body()
    body["data"] = ["not-an-object"]
    client, _ = _interface_laggs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_laggs()


def test_get_interface_laggs_required_field_missing_raises_shape_error():
    body = _interface_laggs_body()
    del body["data"][0]["members"]
    client, _ = _interface_laggs_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_interface_laggs()


def test_get_interface_laggs_shape_error_does_not_leak_raw_field_values():
    body = _interface_laggs_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _interface_laggs_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_interface_laggs()
    assert sentinel not in str(excinfo.value)


ROUTING_GATEWAY_GROUPS_FIXTURE = Path(__file__).parent / "fixtures" / "routing_gateway_groups_response.json"
ROUTING_GATEWAY_GROUP_PRIORITY_IDENTIFYING_FIELDS = ("gateway", "virtual_ip")


def _routing_gateway_groups_body() -> dict:
    return json.loads(ROUTING_GATEWAY_GROUPS_FIXTURE.read_text())


def _routing_gateway_groups_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _routing_gateway_groups_body()
    transport.register("GET", "/api/v2/routing/gateway/groups?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_routing_gateway_groups_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _routing_gateway_groups_client(body)
    assert client.get_routing_gateway_groups() == []


def test_get_routing_gateway_groups_omits_identifying_fields_by_default():
    client, _ = _routing_gateway_groups_client()
    groups = client.get_routing_gateway_groups()
    first = next(g for g in groups if g.name == "WAN_FAILOVER")
    for priority in first.priorities:
        for field in ROUTING_GATEWAY_GROUP_PRIORITY_IDENTIFYING_FIELDS:
            assert getattr(priority, field) is None


def test_get_routing_gateway_groups_includes_identifying_fields_when_requested():
    client, _ = _routing_gateway_groups_client()
    groups = client.get_routing_gateway_groups(include_identifying_metadata=True)
    first = next(g for g in groups if g.name == "WAN_FAILOVER")
    assert first.priorities[0].gateway == "WAN_GW"
    assert first.priorities[0].tier == 1
    assert first.priorities[0].virtual_ip == "address"
    assert first.priorities[1].gateway == "OPT1_GW"
    assert first.priorities[1].virtual_ip == "198.51.100.5"


def test_get_routing_gateway_groups_maps_non_sensitive_fields():
    client, _ = _routing_gateway_groups_client()
    groups = client.get_routing_gateway_groups()
    first = next(g for g in groups if g.name == "WAN_FAILOVER")
    assert first.trigger == "down"
    assert first.descr == "Synthetic gateway group (offline fixture)"
    assert first.ipprotocol == "inet"
    assert len(first.priorities) == 2
    assert first.priorities[0].tier == 1
    second = next(g for g in groups if g.name == "EMPTY_GROUP")
    assert second.ipprotocol is None
    assert second.priorities == []


def test_get_routing_gateway_groups_only_calls_endpoint_with_default_limit():
    client, transport = _routing_gateway_groups_client()
    client.get_routing_gateway_groups()
    assert transport.calls == [("GET", "/api/v2/routing/gateway/groups?limit=100")]


def test_get_routing_gateway_groups_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _routing_gateway_groups_body()
    transport.register("GET", "/api/v2/routing/gateway/groups?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_routing_gateway_groups(limit=5)
    assert transport.calls == [("GET", "/api/v2/routing/gateway/groups?limit=5")]


def test_get_routing_gateway_groups_rejects_zero_limit():
    client, _ = _routing_gateway_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_gateway_groups(limit=0)


def test_get_routing_gateway_groups_rejects_limit_above_max():
    client, _ = _routing_gateway_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_gateway_groups(limit=101)


def test_get_routing_gateway_groups_invalid_limit_never_calls_transport():
    client, transport = _routing_gateway_groups_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_routing_gateway_groups(limit=0)
    assert transport.calls == []


def test_get_routing_gateway_groups_missing_data_key_raises_shape_error():
    body = _routing_gateway_groups_body()
    del body["data"]
    client, _ = _routing_gateway_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_groups()


def test_get_routing_gateway_groups_item_wrong_type_raises_shape_error():
    body = _routing_gateway_groups_body()
    body["data"] = ["not-an-object"]
    client, _ = _routing_gateway_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_groups()


def test_get_routing_gateway_groups_required_field_missing_raises_shape_error():
    body = _routing_gateway_groups_body()
    del body["data"][0]["priorities"][0]["tier"]
    client, _ = _routing_gateway_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_groups()


def test_get_routing_gateway_groups_shape_error_does_not_leak_raw_field_values():
    body = _routing_gateway_groups_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["descr"] = [sentinel]
    client, _ = _routing_gateway_groups_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_routing_gateway_groups()
    assert sentinel not in str(excinfo.value)


ROUTING_GATEWAY_DEFAULT_FIXTURE = Path(__file__).parent / "fixtures" / "routing_gateway_default_response.json"
ROUTING_GATEWAY_DEFAULT_IDENTIFYING_FIELDS = ("defaultgw4", "defaultgw6")


def _routing_gateway_default_body() -> dict:
    return json.loads(ROUTING_GATEWAY_DEFAULT_FIXTURE.read_text())


def _routing_gateway_default_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _routing_gateway_default_body()
    transport.register("GET", "/api/v2/routing/gateway/default", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_routing_gateway_default_omits_identifying_fields_by_default():
    client, _ = _routing_gateway_default_client()
    default_gw = client.get_routing_gateway_default()
    for field in ROUTING_GATEWAY_DEFAULT_IDENTIFYING_FIELDS:
        assert getattr(default_gw, field) is None


def test_get_routing_gateway_default_includes_identifying_fields_when_requested():
    client, _ = _routing_gateway_default_client()
    default_gw = client.get_routing_gateway_default(include_identifying_metadata=True)
    assert default_gw.defaultgw4 == "WAN_GW"
    assert default_gw.defaultgw6 == "-"


def test_get_routing_gateway_default_only_calls_endpoint():
    client, transport = _routing_gateway_default_client()
    client.get_routing_gateway_default()
    assert transport.calls == [("GET", "/api/v2/routing/gateway/default")]


def test_get_routing_gateway_default_missing_data_key_raises_shape_error():
    body = _routing_gateway_default_body()
    del body["data"]
    client, _ = _routing_gateway_default_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_default()


def test_get_routing_gateway_default_data_wrong_type_raises_shape_error():
    body = _routing_gateway_default_body()
    body["data"] = "not-an-object"
    client, _ = _routing_gateway_default_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_default()


def test_get_routing_gateway_default_required_field_missing_raises_shape_error():
    body = _routing_gateway_default_body()
    del body["data"]["defaultgw4"]
    client, _ = _routing_gateway_default_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_routing_gateway_default()


def test_get_routing_gateway_default_shape_error_does_not_leak_raw_field_values():
    body = _routing_gateway_default_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["defaultgw4"] = [sentinel]
    client, _ = _routing_gateway_default_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_routing_gateway_default(include_identifying_metadata=True)
    assert sentinel not in str(excinfo.value)


DHCP_RELAY_FIXTURE = Path(__file__).parent / "fixtures" / "dhcp_relay_response.json"


def _dhcp_relay_body() -> dict:
    return json.loads(DHCP_RELAY_FIXTURE.read_text())


def _dhcp_relay_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_relay_body()
    transport.register("GET", "/api/v2/services/dhcp_relay", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_relay_omits_identifying_fields_by_default():
    client, _ = _dhcp_relay_client()
    relay = client.get_dhcp_relay()
    assert relay.server is None


def test_get_dhcp_relay_object_metadata_is_visible_by_default():
    client, _ = _dhcp_relay_client()
    raw = _dhcp_relay_body()["data"]
    relay = client.get_dhcp_relay()
    assert relay.enable == raw["enable"]
    assert relay.interface == raw["interface"]
    assert relay.agentoption == raw["agentoption"]
    assert relay.carpstatusvip == raw["carpstatusvip"]


def test_get_dhcp_relay_parses_null_interface_and_server():
    """2026-08-21 LAB verification (P1 Batch E) observed exactly this
    shape on the LAB's unconfigured DHCP Relay: HTTP 200 with
    `interface`/`server` both `null`, despite the pinned schema
    declaring `interface` `nullable: false`."""

    body = _dhcp_relay_body()
    body["data"]["interface"] = None
    body["data"]["server"] = None
    client, _ = _dhcp_relay_client(body)
    relay = client.get_dhcp_relay(include_identifying_metadata=True)
    assert relay.interface is None
    assert relay.server is None


def test_get_dhcp_relay_includes_identifying_fields_when_requested():
    client, _ = _dhcp_relay_client()
    relay = client.get_dhcp_relay(include_identifying_metadata=True)
    assert relay.server == ["198.51.100.10", "198.51.100.11"]


def test_get_dhcp_relay_only_calls_endpoint():
    client, transport = _dhcp_relay_client()
    client.get_dhcp_relay()
    assert transport.calls == [("GET", "/api/v2/services/dhcp_relay")]


def test_get_dhcp_relay_missing_data_key_raises_shape_error():
    body = _dhcp_relay_body()
    del body["data"]
    client, _ = _dhcp_relay_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_relay()


def test_get_dhcp_relay_data_wrong_type_raises_shape_error():
    body = _dhcp_relay_body()
    body["data"] = "not-an-object"
    client, _ = _dhcp_relay_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_relay()


def test_get_dhcp_relay_required_field_missing_raises_shape_error():
    body = _dhcp_relay_body()
    del body["data"]["enable"]
    client, _ = _dhcp_relay_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_relay()


def test_get_dhcp_relay_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_relay_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["enable"] = [sentinel]
    client, _ = _dhcp_relay_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_relay()
    assert sentinel not in str(excinfo.value)


DHCP_SERVER_ADDRESS_POOLS_FIXTURE = Path(__file__).parent / "fixtures" / "dhcp_server_address_pools_response.json"


def _dhcp_server_address_pools_body() -> dict:
    return json.loads(DHCP_SERVER_ADDRESS_POOLS_FIXTURE.read_text())


def _dhcp_server_address_pools_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_server_address_pools_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/address_pools?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_server_address_pools_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _dhcp_server_address_pools_client(body)
    assert client.get_dhcp_server_address_pools() == []


def test_get_dhcp_server_address_pools_maps_fields_with_no_redaction():
    client, _ = _dhcp_server_address_pools_client()
    pools = client.get_dhcp_server_address_pools()
    first = next(p for p in pools if p.range_from == "198.51.100.100")
    assert first.range_to == "198.51.100.199"
    assert first.domain == "example.invalid"
    assert first.mac_allow == ["02:00:00:aa:bb:cc"]
    assert first.mac_deny == []
    assert first.gateway == "198.51.100.1"
    assert first.dnsserver == ["198.51.100.1"]


def test_get_dhcp_server_address_pools_parses_null_optional_fields():
    client, _ = _dhcp_server_address_pools_client()
    pools = client.get_dhcp_server_address_pools()
    second = next(p for p in pools if p.range_from == "203.0.113.100")
    assert second.domain is None
    assert second.mac_allow is None
    assert second.mac_deny is None
    assert second.domainsearchlist is None
    assert second.defaultleasetime is None
    assert second.maxleasetime is None
    assert second.gateway is None
    assert second.dnsserver is None
    assert second.winsserver is None
    assert second.ntpserver is None
    assert second.denyunknown is None


def test_get_dhcp_server_address_pools_only_calls_endpoint_with_default_limit():
    client, transport = _dhcp_server_address_pools_client()
    client.get_dhcp_server_address_pools()
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/address_pools?limit=100")]


def test_get_dhcp_server_address_pools_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dhcp_server_address_pools_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/address_pools?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dhcp_server_address_pools(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/address_pools?limit=5")]


def test_get_dhcp_server_address_pools_rejects_zero_limit():
    client, _ = _dhcp_server_address_pools_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_address_pools(limit=0)


def test_get_dhcp_server_address_pools_rejects_limit_above_max():
    client, _ = _dhcp_server_address_pools_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_address_pools(limit=101)


def test_get_dhcp_server_address_pools_invalid_limit_never_calls_transport():
    client, transport = _dhcp_server_address_pools_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_address_pools(limit=0)
    assert transport.calls == []


def test_get_dhcp_server_address_pools_missing_data_key_raises_shape_error():
    body = _dhcp_server_address_pools_body()
    del body["data"]
    client, _ = _dhcp_server_address_pools_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_address_pools()


def test_get_dhcp_server_address_pools_item_wrong_type_raises_shape_error():
    body = _dhcp_server_address_pools_body()
    body["data"] = ["not-an-object"]
    client, _ = _dhcp_server_address_pools_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_address_pools()


def test_get_dhcp_server_address_pools_required_field_missing_raises_shape_error():
    body = _dhcp_server_address_pools_body()
    del body["data"][0]["range_from"]
    client, _ = _dhcp_server_address_pools_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_address_pools()


def test_get_dhcp_server_address_pools_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_server_address_pools_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["range_from"] = [sentinel]
    client, _ = _dhcp_server_address_pools_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_server_address_pools()
    assert sentinel not in str(excinfo.value)


DHCP_SERVER_CUSTOM_OPTIONS_FIXTURE = Path(__file__).parent / "fixtures" / "dhcp_server_custom_options_response.json"


def _dhcp_server_custom_options_body() -> dict:
    return json.loads(DHCP_SERVER_CUSTOM_OPTIONS_FIXTURE.read_text())


def _dhcp_server_custom_options_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _dhcp_server_custom_options_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/custom_options?limit=100", status_code=200, text=json.dumps(payload)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_dhcp_server_custom_options_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _dhcp_server_custom_options_client(body)
    assert client.get_dhcp_server_custom_options() == []


def test_get_dhcp_server_custom_options_maps_fields():
    client, _ = _dhcp_server_custom_options_client()
    options = client.get_dhcp_server_custom_options()
    first = next(o for o in options if o.number == 43)
    assert first.type == "text"
    assert first.value == "Synthetic vendor-specific option (offline fixture)"


def test_get_dhcp_server_custom_options_only_calls_endpoint_with_default_limit():
    client, transport = _dhcp_server_custom_options_client()
    client.get_dhcp_server_custom_options()
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/custom_options?limit=100")]


def test_get_dhcp_server_custom_options_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _dhcp_server_custom_options_body()
    transport.register(
        "GET", "/api/v2/services/dhcp_server/custom_options?limit=5", status_code=200, text=json.dumps(body)
    )
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_dhcp_server_custom_options(limit=5)
    assert transport.calls == [("GET", "/api/v2/services/dhcp_server/custom_options?limit=5")]


def test_get_dhcp_server_custom_options_rejects_zero_limit():
    client, _ = _dhcp_server_custom_options_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_custom_options(limit=0)


def test_get_dhcp_server_custom_options_rejects_limit_above_max():
    client, _ = _dhcp_server_custom_options_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_custom_options(limit=101)


def test_get_dhcp_server_custom_options_invalid_limit_never_calls_transport():
    client, transport = _dhcp_server_custom_options_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_dhcp_server_custom_options(limit=0)
    assert transport.calls == []


def test_get_dhcp_server_custom_options_missing_data_key_raises_shape_error():
    body = _dhcp_server_custom_options_body()
    del body["data"]
    client, _ = _dhcp_server_custom_options_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_custom_options()


def test_get_dhcp_server_custom_options_item_wrong_type_raises_shape_error():
    body = _dhcp_server_custom_options_body()
    body["data"] = ["not-an-object"]
    client, _ = _dhcp_server_custom_options_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_custom_options()


def test_get_dhcp_server_custom_options_required_field_missing_raises_shape_error():
    body = _dhcp_server_custom_options_body()
    del body["data"][0]["value"]
    client, _ = _dhcp_server_custom_options_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_dhcp_server_custom_options()


def test_get_dhcp_server_custom_options_shape_error_does_not_leak_raw_field_values():
    body = _dhcp_server_custom_options_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["value"] = [sentinel]
    client, _ = _dhcp_server_custom_options_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_dhcp_server_custom_options()
    assert sentinel not in str(excinfo.value)


SYSTEM_HOSTNAME_FIXTURE = Path(__file__).parent / "fixtures" / "system_hostname_response.json"
SYSTEM_HOSTNAME_IDENTIFYING_FIELDS = ("hostname", "domain")


def _system_hostname_body() -> dict:
    return json.loads(SYSTEM_HOSTNAME_FIXTURE.read_text())


def _system_hostname_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_hostname_body()
    transport.register("GET", "/api/v2/system/hostname", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_hostname_omits_identifying_fields_by_default():
    client, _ = _system_hostname_client()
    hostname = client.get_system_hostname()
    for field in SYSTEM_HOSTNAME_IDENTIFYING_FIELDS:
        assert getattr(hostname, field) is None


def test_get_system_hostname_includes_identifying_fields_when_requested():
    client, _ = _system_hostname_client()
    hostname = client.get_system_hostname(include_identifying_metadata=True)
    assert hostname.hostname == "pfsense-lab"
    assert hostname.domain == "example.invalid"


def test_get_system_hostname_only_calls_endpoint():
    client, transport = _system_hostname_client()
    client.get_system_hostname()
    assert transport.calls == [("GET", "/api/v2/system/hostname")]


def test_get_system_hostname_missing_data_key_raises_shape_error():
    body = _system_hostname_body()
    del body["data"]
    client, _ = _system_hostname_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hostname()


def test_get_system_hostname_data_wrong_type_raises_shape_error():
    body = _system_hostname_body()
    body["data"] = "not-an-object"
    client, _ = _system_hostname_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hostname()


def test_get_system_hostname_required_field_missing_raises_shape_error():
    body = _system_hostname_body()
    del body["data"]["hostname"]
    client, _ = _system_hostname_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_hostname()


def test_get_system_hostname_shape_error_does_not_leak_raw_field_values():
    body = _system_hostname_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["hostname"] = [sentinel]
    client, _ = _system_hostname_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_hostname(include_identifying_metadata=True)
    assert sentinel not in str(excinfo.value)


SYSTEM_TIMEZONE_FIXTURE = Path(__file__).parent / "fixtures" / "system_timezone_response.json"


def _system_timezone_body() -> dict:
    return json.loads(SYSTEM_TIMEZONE_FIXTURE.read_text())


def _system_timezone_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_timezone_body()
    transport.register("GET", "/api/v2/system/timezone", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_timezone_maps_fields():
    client, _ = _system_timezone_client()
    tz = client.get_system_timezone()
    assert tz.timezone == "Etc/UTC"


def test_get_system_timezone_only_calls_endpoint():
    client, transport = _system_timezone_client()
    client.get_system_timezone()
    assert transport.calls == [("GET", "/api/v2/system/timezone")]


def test_get_system_timezone_missing_data_key_raises_shape_error():
    body = _system_timezone_body()
    del body["data"]
    client, _ = _system_timezone_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_timezone()


def test_get_system_timezone_data_wrong_type_raises_shape_error():
    body = _system_timezone_body()
    body["data"] = "not-an-object"
    client, _ = _system_timezone_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_timezone()


def test_get_system_timezone_required_field_missing_raises_shape_error():
    body = _system_timezone_body()
    del body["data"]["timezone"]
    client, _ = _system_timezone_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_timezone()


def test_get_system_timezone_shape_error_does_not_leak_raw_field_values():
    body = _system_timezone_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["timezone"] = [sentinel]
    client, _ = _system_timezone_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_timezone()
    assert sentinel not in str(excinfo.value)


SYSTEM_DNS_FIXTURE = Path(__file__).parent / "fixtures" / "system_dns_response.json"


def _system_dns_body() -> dict:
    return json.loads(SYSTEM_DNS_FIXTURE.read_text())


def _system_dns_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_dns_body()
    transport.register("GET", "/api/v2/system/dns", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_dns_omits_identifying_fields_by_default():
    client, _ = _system_dns_client()
    dns = client.get_system_dns()
    assert dns.dnsserver is None


def test_get_system_dns_object_metadata_is_visible_by_default():
    client, _ = _system_dns_client()
    raw = _system_dns_body()["data"]
    dns = client.get_system_dns()
    assert dns.dnsallowoverride == raw["dnsallowoverride"]
    assert dns.dnslocalhost == raw["dnslocalhost"]


def test_get_system_dns_includes_identifying_fields_when_requested():
    client, _ = _system_dns_client()
    dns = client.get_system_dns(include_identifying_metadata=True)
    assert dns.dnsserver == ["198.51.100.1", "198.51.100.2"]


def test_get_system_dns_only_calls_endpoint():
    client, transport = _system_dns_client()
    client.get_system_dns()
    assert transport.calls == [("GET", "/api/v2/system/dns")]


def test_get_system_dns_missing_data_key_raises_shape_error():
    body = _system_dns_body()
    del body["data"]
    client, _ = _system_dns_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_dns()


def test_get_system_dns_data_wrong_type_raises_shape_error():
    body = _system_dns_body()
    body["data"] = "not-an-object"
    client, _ = _system_dns_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_dns()


def test_get_system_dns_required_field_missing_raises_shape_error():
    body = _system_dns_body()
    del body["data"]["dnsallowoverride"]
    client, _ = _system_dns_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_dns()


def test_get_system_dns_shape_error_does_not_leak_raw_field_values():
    body = _system_dns_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["dnsallowoverride"] = [sentinel]
    client, _ = _system_dns_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_dns()
    assert sentinel not in str(excinfo.value)


SYSTEM_CONSOLE_FIXTURE = Path(__file__).parent / "fixtures" / "system_console_response.json"


def _system_console_body() -> dict:
    return json.loads(SYSTEM_CONSOLE_FIXTURE.read_text())


def _system_console_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_console_body()
    transport.register("GET", "/api/v2/system/console", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_console_maps_fields():
    client, _ = _system_console_client()
    console = client.get_system_console()
    assert console.passwd_protect_console is False


def test_get_system_console_only_calls_endpoint():
    client, transport = _system_console_client()
    client.get_system_console()
    assert transport.calls == [("GET", "/api/v2/system/console")]


def test_get_system_console_missing_data_key_raises_shape_error():
    body = _system_console_body()
    del body["data"]
    client, _ = _system_console_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_console()


def test_get_system_console_data_wrong_type_raises_shape_error():
    body = _system_console_body()
    body["data"] = "not-an-object"
    client, _ = _system_console_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_console()


def test_get_system_console_required_field_missing_raises_shape_error():
    body = _system_console_body()
    del body["data"]["passwd_protect_console"]
    client, _ = _system_console_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_console()


def test_get_system_console_shape_error_does_not_leak_raw_field_values():
    body = _system_console_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["passwd_protect_console"] = [sentinel]
    client, _ = _system_console_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_console()
    assert sentinel not in str(excinfo.value)


SYSTEM_WEBGUI_SETTINGS_FIXTURE = Path(__file__).parent / "fixtures" / "system_webgui_settings_response.json"


def _system_webgui_settings_body() -> dict:
    return json.loads(SYSTEM_WEBGUI_SETTINGS_FIXTURE.read_text())


def _system_webgui_settings_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_webgui_settings_body()
    transport.register("GET", "/api/v2/system/webgui/settings", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_webgui_settings_maps_fields():
    client, _ = _system_webgui_settings_client()
    settings = client.get_system_webgui_settings()
    assert settings.protocol == "https"
    assert settings.port == "443"
    assert settings.sslcertref == "68f9c9c1a2b3c"


def test_get_system_webgui_settings_parses_null_sslcertref():
    body = _system_webgui_settings_body()
    body["data"]["sslcertref"] = None
    client, _ = _system_webgui_settings_client(body)
    settings = client.get_system_webgui_settings()
    assert settings.sslcertref is None


def test_get_system_webgui_settings_only_calls_endpoint():
    client, transport = _system_webgui_settings_client()
    client.get_system_webgui_settings()
    assert transport.calls == [("GET", "/api/v2/system/webgui/settings")]


def test_get_system_webgui_settings_missing_data_key_raises_shape_error():
    body = _system_webgui_settings_body()
    del body["data"]
    client, _ = _system_webgui_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_webgui_settings()


def test_get_system_webgui_settings_data_wrong_type_raises_shape_error():
    body = _system_webgui_settings_body()
    body["data"] = "not-an-object"
    client, _ = _system_webgui_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_webgui_settings()


def test_get_system_webgui_settings_required_field_missing_raises_shape_error():
    body = _system_webgui_settings_body()
    del body["data"]["protocol"]
    client, _ = _system_webgui_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_webgui_settings()


def test_get_system_webgui_settings_shape_error_does_not_leak_raw_field_values():
    body = _system_webgui_settings_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"]["protocol"] = [sentinel]
    client, _ = _system_webgui_settings_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_webgui_settings()
    assert sentinel not in str(excinfo.value)


SYSTEM_RESTAPI_ACCESS_LIST_FIXTURE = Path(__file__).parent / "fixtures" / "system_restapi_access_list_response.json"
SYSTEM_RESTAPI_ACCESS_LIST_IDENTIFYING_FIELDS = ("network",)


def _system_restapi_access_list_body() -> dict:
    return json.loads(SYSTEM_RESTAPI_ACCESS_LIST_FIXTURE.read_text())


def _system_restapi_access_list_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_restapi_access_list_body()
    transport.register("GET", "/api/v2/system/restapi/access_list?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_restapi_access_list_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _system_restapi_access_list_client(body)
    assert client.get_system_restapi_access_list() == []


def test_get_system_restapi_access_list_omits_identifying_fields_by_default():
    client, _ = _system_restapi_access_list_client()
    entries = client.get_system_restapi_access_list()
    assert len(entries) == 2
    for entry in entries:
        for field in SYSTEM_RESTAPI_ACCESS_LIST_IDENTIFYING_FIELDS:
            assert getattr(entry, field) is None


def test_get_system_restapi_access_list_includes_identifying_fields_when_requested():
    client, _ = _system_restapi_access_list_client()
    entries = client.get_system_restapi_access_list(include_identifying_metadata=True)
    first = next(e for e in entries if e.type == "allow")
    assert first.network == "198.51.100.0/24"


def test_get_system_restapi_access_list_maps_non_sensitive_fields():
    client, _ = _system_restapi_access_list_client()
    entries = client.get_system_restapi_access_list()
    first = next(e for e in entries if e.type == "allow")
    assert first.weight == 1
    assert first.users == ["admin"]
    assert first.descr == "Synthetic access list entry (offline fixture)"


def test_get_system_restapi_access_list_only_calls_endpoint_with_default_limit():
    client, transport = _system_restapi_access_list_client()
    client.get_system_restapi_access_list()
    assert transport.calls == [("GET", "/api/v2/system/restapi/access_list?limit=100")]


def test_get_system_restapi_access_list_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_restapi_access_list_body()
    transport.register("GET", "/api/v2/system/restapi/access_list?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_restapi_access_list(limit=5)
    assert transport.calls == [("GET", "/api/v2/system/restapi/access_list?limit=5")]


def test_get_system_restapi_access_list_rejects_zero_limit():
    client, _ = _system_restapi_access_list_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_restapi_access_list(limit=0)


def test_get_system_restapi_access_list_rejects_limit_above_max():
    client, _ = _system_restapi_access_list_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_restapi_access_list(limit=101)


def test_get_system_restapi_access_list_invalid_limit_never_calls_transport():
    client, transport = _system_restapi_access_list_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_restapi_access_list(limit=0)
    assert transport.calls == []


def test_get_system_restapi_access_list_missing_data_key_raises_shape_error():
    body = _system_restapi_access_list_body()
    del body["data"]
    client, _ = _system_restapi_access_list_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_access_list()


def test_get_system_restapi_access_list_item_wrong_type_raises_shape_error():
    body = _system_restapi_access_list_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_restapi_access_list_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_access_list()


def test_get_system_restapi_access_list_required_field_missing_raises_shape_error():
    body = _system_restapi_access_list_body()
    del body["data"][0]["weight"]
    client, _ = _system_restapi_access_list_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_restapi_access_list()


def test_get_system_restapi_access_list_shape_error_does_not_leak_raw_field_values():
    body = _system_restapi_access_list_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["weight"] = [sentinel]
    client, _ = _system_restapi_access_list_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_restapi_access_list()
    assert sentinel not in str(excinfo.value)


SYSTEM_CRLS_FIXTURE = Path(__file__).parent / "fixtures" / "system_crls_response.json"


def _system_crls_body() -> dict:
    return json.loads(SYSTEM_CRLS_FIXTURE.read_text())


def _system_crls_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_crls_body()
    transport.register("GET", "/api/v2/system/crls?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_crls_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _system_crls_client(body)
    assert client.get_system_crls() == []


def test_get_system_crls_maps_internal_method_with_nested_cert_list():
    client, _ = _system_crls_client()
    crls = client.get_system_crls()
    internal = next(c for c in crls if c.method == "internal")
    assert internal.refid == "68f9c9c1a2b3c"
    assert internal.descr == "Synthetic internal CRL (offline fixture)"
    assert len(internal.cert) == 1
    assert internal.cert[0].certref == "68f9c9c1a2b3e"
    assert internal.cert[0].reason == 0
    assert internal.cert[0].revoke_time == 1750000000
    assert internal.text == ""


def test_get_system_crls_never_exposes_revoked_certificate_private_key_field():
    """CertificateRevocationListRevokedCertificate.prv is the revoked
    certificate's X509 private key. Confirmed absent by construction,
    not merely by trusting the schema's writeOnly claim -- injected
    in-memory only, never in a committed fixture."""

    body = _system_crls_body()
    body["data"][0]["cert"][0]["prv"] = "SENTINEL-PRIVATE-KEY-MATERIAL"
    client, _ = _system_crls_client(body)
    crls = client.get_system_crls()
    internal = next(c for c in crls if c.method == "internal")
    assert not hasattr(internal.cert[0], "prv")
    assert "prv" not in internal.cert[0].model_dump()


def test_get_system_crls_maps_existing_method_with_text():
    client, _ = _system_crls_client()
    crls = client.get_system_crls()
    existing = next(c for c in crls if c.method == "existing")
    assert existing.refid is None
    assert existing.text.startswith("-----BEGIN X509 CRL-----")
    assert existing.cert == []


def test_get_system_crls_only_calls_endpoint_with_default_limit():
    client, transport = _system_crls_client()
    client.get_system_crls()
    assert transport.calls == [("GET", "/api/v2/system/crls?limit=100")]


def test_get_system_crls_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_crls_body()
    transport.register("GET", "/api/v2/system/crls?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_crls(limit=5)
    assert transport.calls == [("GET", "/api/v2/system/crls?limit=5")]


def test_get_system_crls_rejects_zero_limit():
    client, _ = _system_crls_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_crls(limit=0)


def test_get_system_crls_rejects_limit_above_max():
    client, _ = _system_crls_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_crls(limit=101)


def test_get_system_crls_invalid_limit_never_calls_transport():
    client, transport = _system_crls_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_crls(limit=0)
    assert transport.calls == []


def test_get_system_crls_missing_data_key_raises_shape_error():
    body = _system_crls_body()
    del body["data"]
    client, _ = _system_crls_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_crls()


def test_get_system_crls_item_wrong_type_raises_shape_error():
    body = _system_crls_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_crls_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_crls()


def test_get_system_crls_required_field_missing_raises_shape_error():
    body = _system_crls_body()
    del body["data"][0]["caref"]
    client, _ = _system_crls_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_crls()


def test_get_system_crls_shape_error_does_not_leak_raw_field_values():
    body = _system_crls_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["caref"] = [sentinel]
    client, _ = _system_crls_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_crls()
    assert sentinel not in str(excinfo.value)


SYSTEM_PACKAGE_AVAILABLE_FIXTURE = Path(__file__).parent / "fixtures" / "system_package_available_response.json"


def _system_package_available_body() -> dict:
    return json.loads(SYSTEM_PACKAGE_AVAILABLE_FIXTURE.read_text())


def _system_package_available_client(body: dict | None = None) -> tuple[PfSenseClient, MockTransport]:
    transport = MockTransport()
    payload = body if body is not None else _system_package_available_body()
    transport.register("GET", "/api/v2/system/package/available?limit=100", status_code=200, text=json.dumps(payload))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    return PfSenseClient(rest_client), transport


def test_get_system_package_available_parses_empty_list():
    body = {"code": 200, "data": [], "message": "", "response_id": "SUCCESS", "status": "ok"}
    client, _ = _system_package_available_client(body)
    assert client.get_system_package_available() == []


def test_get_system_package_available_maps_fields():
    client, _ = _system_package_available_client()
    packages = client.get_system_package_available()
    first = next(p for p in packages if p.name == "pfSense-pkg-WireGuard")
    assert first.shortname == "WireGuard"
    assert first.version == "0.2.13_4"
    assert first.installed is True
    assert first.deps == []


def test_get_system_package_available_parses_null_optional_fields():
    client, _ = _system_package_available_client()
    packages = client.get_system_package_available()
    second = next(p for p in packages if p.name == "pfSense-pkg-Zabbix-agent")
    assert second.shortname is None
    assert second.descr is None
    assert second.version is None
    assert second.installed is None
    assert second.deps is None


def test_get_system_package_available_only_calls_endpoint_with_default_limit():
    client, transport = _system_package_available_client()
    client.get_system_package_available()
    assert transport.calls == [("GET", "/api/v2/system/package/available?limit=100")]


def test_get_system_package_available_passes_custom_limit_in_query_string():
    transport = MockTransport()
    body = _system_package_available_body()
    transport.register("GET", "/api/v2/system/package/available?limit=5", status_code=200, text=json.dumps(body))
    rest_client = RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)
    client = PfSenseClient(rest_client)
    client.get_system_package_available(limit=5)
    assert transport.calls == [("GET", "/api/v2/system/package/available?limit=5")]


def test_get_system_package_available_rejects_zero_limit():
    client, _ = _system_package_available_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_package_available(limit=0)


def test_get_system_package_available_rejects_limit_above_max():
    client, _ = _system_package_available_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_package_available(limit=101)


def test_get_system_package_available_invalid_limit_never_calls_transport():
    client, transport = _system_package_available_client()
    with pytest.raises(PfSenseRequestValidationError):
        client.get_system_package_available(limit=0)
    assert transport.calls == []


def test_get_system_package_available_missing_data_key_raises_shape_error():
    body = _system_package_available_body()
    del body["data"]
    client, _ = _system_package_available_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_package_available()


def test_get_system_package_available_item_wrong_type_raises_shape_error():
    body = _system_package_available_body()
    body["data"] = ["not-an-object"]
    client, _ = _system_package_available_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_package_available()


def test_get_system_package_available_required_field_missing_raises_shape_error():
    body = _system_package_available_body()
    del body["data"][0]["name"]
    client, _ = _system_package_available_client(body)
    with pytest.raises(PfSenseResponseShapeError):
        client.get_system_package_available()


def test_get_system_package_available_shape_error_does_not_leak_raw_field_values():
    body = _system_package_available_body()
    sentinel = "SENTINEL-SECRET-VALUE"
    body["data"][0]["name"] = [sentinel]
    client, _ = _system_package_available_client(body)
    with pytest.raises(PfSenseResponseShapeError) as excinfo:
        client.get_system_package_available()
    assert sentinel not in str(excinfo.value)
