import json

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.endpoints import Endpoints
from pfsense_mcp.errors import PfSenseAPIError, PfSenseAuthError, UnsupportedOperationError
from pfsense_mcp.rest_api_client import RestApiClient
from pfsense_mcp.transport.mock import MockTransport


def _client(transport: MockTransport) -> RestApiClient:
    return RestApiClient(transport, identity="api-mcp-admin", api_version=ApiVersion.V2)


def test_get_success_returns_parsed_json():
    transport = MockTransport()
    body = {"code": 200, "status": "ok", "response_id": "SUCCESS", "data": {"platform": "Netgate pfSense Plus"}}
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(body))
    client = _client(transport)

    result = client.get(Endpoints.SYSTEM_STATUS)

    assert result == body
    assert transport.calls == [("GET", "/api/v2/status/system")]


def test_get_401_raises_auth_error():
    transport = MockTransport()
    transport.register(
        "GET",
        "/api/v2/status/system",
        status_code=401,
        text=json.dumps({"response_id": "AUTH_AUTHENTICATION_FAILED"}),
    )
    client = _client(transport)
    with pytest.raises(PfSenseAuthError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_get_403_raises_auth_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=403, text="{}")
    client = _client(transport)
    with pytest.raises(PfSenseAuthError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_get_500_raises_api_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=500, text="{}")
    client = _client(transport)
    with pytest.raises(PfSenseAPIError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_get_non_json_response_raises_api_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text="not json")
    client = _client(transport)
    with pytest.raises(PfSenseAPIError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_unregistered_call_surfaces_as_connection_error():
    transport = MockTransport()
    client = _client(transport)
    with pytest.raises(KeyError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_post_is_rejected_as_unsupported():
    transport = MockTransport()
    client = _client(transport)
    with pytest.raises(UnsupportedOperationError):
        client._request("POST", "/api/v2/status/system")


def test_get_with_params_appends_query_string():
    transport = MockTransport()
    body = {"code": 200, "status": "ok", "response_id": "SUCCESS", "data": []}
    transport.register("GET", "/api/v2/firewall/states?limit=5", status_code=200, text=json.dumps(body))
    client = _client(transport)

    result = client.get(Endpoints.FIREWALL_STATES, params={"limit": 5})

    assert result == body
    assert transport.calls == [("GET", "/api/v2/firewall/states?limit=5")]


def test_get_without_params_has_no_query_string():
    transport = MockTransport()
    body = {"code": 200, "status": "ok", "response_id": "SUCCESS", "data": {}}
    transport.register("GET", "/api/v2/firewall/apply", status_code=200, text=json.dumps(body))
    client = _client(transport)

    client.get(Endpoints.FIREWALL_APPLY_STATUS)

    assert transport.calls == [("GET", "/api/v2/firewall/apply")]


def test_get_with_empty_params_has_no_query_string():
    transport = MockTransport()
    body = {"code": 200, "status": "ok", "response_id": "SUCCESS", "data": {}}
    transport.register("GET", "/api/v2/firewall/apply", status_code=200, text=json.dumps(body))
    client = _client(transport)

    client.get(Endpoints.FIREWALL_APPLY_STATUS, params={})

    assert transport.calls == [("GET", "/api/v2/firewall/apply")]
