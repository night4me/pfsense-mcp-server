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
    with pytest.raises(PfSenseAuthError) as excinfo:
        client.get(Endpoints.SYSTEM_STATUS)
    assert "api-mcp-admin" not in str(excinfo.value)


def test_get_403_raises_auth_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=403, text="{}")
    client = _client(transport)
    with pytest.raises(PfSenseAuthError) as excinfo:
        client.get(Endpoints.SYSTEM_STATUS)
    assert "api-mcp-admin" not in str(excinfo.value)


def test_get_500_raises_api_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=500, text="{}")
    client = _client(transport)
    with pytest.raises(PfSenseAPIError):
        client.get(Endpoints.SYSTEM_STATUS)


@pytest.mark.parametrize("status_code", [100, 300, 301, 302, 307, 308, 400, 404, 409, 429, 500, 503])
def test_non_2xx_statuses_raise_sanitized_api_error(status_code, caplog):
    secret = "SYNTHETIC-RESPONSE-SECRET-MUST-NOT-ESCAPE"
    transport = MockTransport()
    transport.register(
        "GET",
        "/api/v2/status/system",
        status_code=status_code,
        text=json.dumps({"response_id": "SYNTHETIC", "message": secret}),
    )

    with pytest.raises(PfSenseAPIError) as excinfo:
        _client(transport).get(Endpoints.SYSTEM_STATUS)

    assert excinfo.value.status_code == status_code
    assert secret not in str(excinfo.value)
    assert secret not in caplog.text


def test_get_non_json_response_raises_api_error():
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text="not json")
    client = _client(transport)
    with pytest.raises(PfSenseAPIError):
        client.get(Endpoints.SYSTEM_STATUS)


def test_get_json_array_response_raises_api_error():
    """A 200 response that is valid JSON but not a JSON object (e.g. a
    bare array) must fail closed with a typed error, not be silently
    returned as if it were the declared dict[str, Any] shape (found by
    mypy --strict's no-any-return check, 2026-08-09 -- this closes the
    gap, not merely satisfies the type checker)."""
    transport = MockTransport()
    transport.register("GET", "/api/v2/status/system", status_code=200, text=json.dumps(["unexpected", "array"]))
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
