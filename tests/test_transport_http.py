import httpx
import pytest
import respx

from pfsense_mcp.transport.base import TransportConnectionError, TransportTimeoutError
from pfsense_mcp.transport.http import HttpTransport


@respx.mock
def test_request_sends_api_key_header_and_returns_response():
    route = respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        response = transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["X-API-Key"] == "fake-key"
    assert response.status_code == 200
    assert response.text == '{"status": "ok"}'


@respx.mock
def test_connect_error_raises_transport_connection_error():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.ConnectError("boom"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError):
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()


@respx.mock
def test_timeout_raises_transport_timeout_error():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.TimeoutException("boom"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportTimeoutError):
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()


@respx.mock
def test_other_httpx_transport_error_is_sanitized():
    secret = "SYNTHETIC-SECRET-MUST-NOT-ESCAPE"
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        side_effect=httpx.RemoteProtocolError(secret)
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportConnectionError) as excinfo:
            transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    assert secret not in str(excinfo.value)
