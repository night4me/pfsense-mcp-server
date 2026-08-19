import base64

import httpx
import pytest
import respx

from pfsense_mcp.transport.base import (
    TransportConfigurationError,
    TransportConnectionError,
    TransportRequestNotSentError,
    TransportTimeoutError,
)
from pfsense_mcp.transport.http import BasicAuthHttpTransport, HttpTransport


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
def test_request_sends_body_and_content_type_when_provided():
    route = respx.patch("https://pfsense.example.invalid/api/v2/firewall/alias").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        response = transport.request("PATCH", "/api/v2/firewall/alias", body=b'{"descr":"updated"}')
    finally:
        transport.close()

    assert route.called
    sent_request = route.calls.last.request
    assert sent_request.headers["X-API-Key"] == "fake-key"
    assert sent_request.headers["Content-Type"] == "application/json"
    assert sent_request.content == b'{"descr":"updated"}'
    assert response.status_code == 200


@respx.mock
def test_request_without_body_sends_no_content_type_and_no_content():
    route = respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        transport.request("GET", "/api/v2/status/system")
    finally:
        transport.close()

    sent_request = route.calls.last.request
    assert "Content-Type" not in sent_request.headers
    assert sent_request.content == b""


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
def test_connect_timeout_is_proven_not_sent_for_transition_accounting():
    respx.get("https://pfsense.example.invalid/api/v2/status/system").mock(side_effect=httpx.ConnectTimeout("hidden"))
    transport = HttpTransport("https://pfsense.example.invalid", "fake-key", True)
    try:
        with pytest.raises(TransportRequestNotSentError):
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


@respx.mock
def test_basic_auth_transport_sends_only_basic_auth_and_json_headers():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(200, text='{"status": "ok"}')
    )
    transport = BasicAuthHttpTransport(
        "https://pfsense.example.invalid", "synthetic-service-user", "synthetic:password", True
    )

    response = transport.request("POST", "/api/v2/auth/key", body=b'{"descr":"bootstrap"}')

    sent_request = route.calls.last.request
    expected = base64.b64encode(b"synthetic-service-user:synthetic:password").decode("ascii")
    assert sent_request.headers["Authorization"] == f"Basic {expected}"
    assert "X-API-Key" not in sent_request.headers
    assert sent_request.headers["Accept"] == "application/json"
    assert sent_request.headers["Content-Type"] == "application/json"
    assert sent_request.content == b'{"descr":"bootstrap"}'
    assert response.status_code == 200


@pytest.mark.parametrize(
    ("base_url", "username", "password", "verify"),
    [
        ("http://pfsense.example.invalid", "svc", "password", True),
        ("https://user@pfsense.example.invalid", "svc", "password", True),
        ("https://pfsense.example.invalid/api", "svc", "password", True),
        ("https://pfsense.example.invalid", "", "password", True),
        ("https://pfsense.example.invalid", " svc", "password", True),
        ("https://pfsense.example.invalid", "svc:other", "password", True),
        ("https://pfsense.example.invalid", "svc\nother", "password", True),
        ("https://pfsense.example.invalid", "svc", "", True),
        ("https://pfsense.example.invalid", "svc", " password", True),
        ("https://pfsense.example.invalid", "svc", "pass\rword", True),
        ("https://pfsense.example.invalid", "svc", "password", False),
        ("https://pfsense.example.invalid", "svc", "password", ""),
    ],
)
def test_basic_auth_transport_rejects_unsafe_or_ambiguous_configuration(base_url, username, password, verify):
    with pytest.raises(TransportConfigurationError):
        BasicAuthHttpTransport(base_url, username, password, verify)


def test_basic_auth_invalid_credential_value_is_not_exposed_by_error():
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    with pytest.raises(TransportConfigurationError) as excinfo:
        BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", f"{canary}\n", True)
    assert canary not in str(excinfo.value)


def test_basic_auth_transport_repr_never_contains_credentials():
    username = "synthetic-service-user"
    password = "SYNTHETIC-CREDENTIAL-CANARY"
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", username, password, True)
    try:
        rendered = repr(transport)
    finally:
        transport.close()

    assert username not in rendered
    assert password not in rendered
    assert rendered == "BasicAuthHttpTransport(single_use=True)"


@respx.mock
def test_basic_auth_transport_is_single_use_and_never_retries():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        side_effect=httpx.ReadTimeout("SYNTHETIC-CREDENTIAL-CANARY")
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    with pytest.raises(TransportTimeoutError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")
    with pytest.raises(TransportConfigurationError):
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert len(route.calls) == 1
    assert "SYNTHETIC-CREDENTIAL-CANARY" not in str(excinfo.value)


@respx.mock
def test_basic_auth_transport_does_not_follow_redirects():
    first = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(307, headers={"Location": "https://other.example.invalid/collect"})
    )
    redirected = respx.post("https://other.example.invalid/collect").mock(
        return_value=httpx.Response(200, text="unexpected")
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    response = transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert response.status_code == 307
    assert len(first.calls) == 1
    assert len(redirected.calls) == 0


@respx.mock
def test_closing_unused_basic_auth_transport_sends_nothing_and_consumes_it():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(200, text='{"status":"unexpected"}')
    )
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    transport.close()

    with pytest.raises(TransportConfigurationError):
        transport.request("POST", "/api/v2/auth/key", body=b"{}")
    assert len(route.calls) == 0


def test_basic_auth_close_failure_is_sanitized(monkeypatch):
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    class CloseFailingClient:
        def request(self, method, path, *, content, headers):
            return httpx.Response(200, text='{"status":"ok"}')

        def close(self):
            raise RuntimeError(canary)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: CloseFailingClient())
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", canary, True)

    with pytest.raises(TransportConnectionError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert canary not in str(excinfo.value)


def test_basic_auth_request_error_remains_sanitized_when_close_also_fails(monkeypatch):
    canary = "SYNTHETIC-CREDENTIAL-CANARY"

    class RequestAndCloseFailingClient:
        def request(self, method, path, *, content, headers):
            raise httpx.ReadTimeout(canary)

        def close(self):
            raise RuntimeError(canary)

    monkeypatch.setattr(httpx, "Client", lambda **kwargs: RequestAndCloseFailingClient())
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", canary, True)

    with pytest.raises(TransportTimeoutError) as excinfo:
        transport.request("POST", "/api/v2/auth/key", body=b"{}")

    assert canary not in str(excinfo.value)


@respx.mock
def test_basic_auth_transport_error_does_not_echo_method_or_path():
    canary = "SYNTHETIC-CREDENTIAL-CANARY"
    respx.route().mock(side_effect=httpx.ConnectError("synthetic failure"))
    transport = BasicAuthHttpTransport("https://pfsense.example.invalid", "svc", "synthetic-password", True)

    with pytest.raises(TransportConnectionError) as excinfo:
        transport.request(f"POST-{canary}", f"/api/v2/auth/key?value={canary}", body=b"{}")

    assert canary not in str(excinfo.value)
