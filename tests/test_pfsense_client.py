import json
from pathlib import Path

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import PfSenseResponseShapeError
from pfsense_mcp.pfsense_client import PfSenseClient
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport

FIXTURE = Path(__file__).parent / "fixtures" / "system_status_response.json"
INTERFACES_FIXTURE = Path(__file__).parent / "fixtures" / "interfaces_status_response.json"

INTERFACES_IDENTIFYING_FIELDS = (
    "macaddr", "ipaddr", "subnet", "linklocal", "ipaddrv6", "subnetv6", "gateway", "gatewayv6",
)


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
