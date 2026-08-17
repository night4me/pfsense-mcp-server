"""Phase F: adversarial coverage for NexusSession -- login, JWT `exp`
handling, refresh, and the "never leak a credential or token" rule,
mirroring the respx-based pattern tests/test_transport_http.py already
established for the community backend's HttpTransport."""

from __future__ import annotations

import base64
import inspect
import json
import time

import httpx
import pytest
import respx

from pfsense_mcp.backends.nexus.session import NexusSession
from pfsense_mcp.errors import PfSenseAuthError, PfSenseConnectionError

CONTROLLER = "https://nexus.example.invalid"


def _jwt(payload: dict) -> str:
    def _b64(obj) -> str:
        raw = json.dumps(obj).encode("utf-8") if not isinstance(obj, bytes) else obj
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    return f"{_b64({'alg': 'none'})}.{_b64(payload)}.{_b64(b'sig')}"


def _future_exp(seconds: float = 3600) -> int:
    return int(time.time() + seconds)


def _session(**kwargs) -> NexusSession:
    return NexusSession(controller_url=CONTROLLER, username="admin", password="hunter2", **kwargs)


# --- login ---------------------------------------------------------


@respx.mock
def test_login_success_stores_token():
    token = _jwt({"exp": _future_exp()})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    session = _session()
    session.login()
    assert session.get_valid_access_token() == token


@respx.mock
def test_login_sends_base64_encoded_credentials():
    token = _jwt({"exp": _future_exp()})
    route = respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    session = _session()
    session.login()

    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body["username"] == base64.b64encode(b"admin").decode("ascii")
    assert sent_body["password"] == base64.b64encode(b"hunter2").decode("ascii")


@respx.mock
def test_login_failure_raises_auth_error():
    respx.post(f"{CONTROLLER}/api/login").mock(
        return_value=httpx.Response(400, json={"errcode": 1, "errlevel": "error", "errmsg": "bad credentials"})
    )
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_response_missing_token_raises_auth_error():
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"user": "admin"}))
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_response_not_json_raises_auth_error():
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, text="not json"))
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_malformed_jwt_raises_auth_error():
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": "not.a.valid.jwt.x"}))
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_jwt_missing_exp_claim_raises_auth_error():
    token = _jwt({"user": "admin"})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_jwt_non_numeric_exp_claim_raises_auth_error():
    token = _jwt({"exp": "not-a-number"})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    with pytest.raises(PfSenseAuthError):
        _session().login()


@respx.mock
def test_login_jwt_valid_exp_is_accepted():
    exp = _future_exp(120)
    token = _jwt({"exp": exp})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    session = _session()
    session.login()
    assert session.get_valid_access_token() == token


@respx.mock
def test_login_network_timeout_raises_connection_error():
    respx.post(f"{CONTROLLER}/api/login").mock(side_effect=httpx.TimeoutException("boom"))
    with pytest.raises(PfSenseConnectionError):
        _session().login()


@respx.mock
def test_login_connect_error_raises_connection_error():
    respx.post(f"{CONTROLLER}/api/login").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(PfSenseConnectionError):
        _session().login()


@respx.mock
def test_login_issues_exactly_one_request_on_failure_no_retry():
    """Confirmed this phase, from Netgate's own generated client source
    (py/pfapi/client.py, py/pfapi/api/login/login.py): a single
    unwrapped request, no retry wrapper anywhere. This project's own
    transport matches that -- no automatic retry."""

    route = respx.post(f"{CONTROLLER}/api/login").mock(side_effect=httpx.ConnectError("boom"))
    with pytest.raises(PfSenseConnectionError):
        _session().login()
    assert route.call_count == 1


# --- get_valid_access_token / expiry ---------------------------------


def test_get_valid_access_token_before_login_raises_auth_error():
    with pytest.raises(PfSenseAuthError):
        _session().get_valid_access_token()


@respx.mock
def test_get_valid_access_token_refreshes_when_near_expiry():
    almost_expired = _jwt({"exp": _future_exp(5)})  # inside the 30s safety margin
    fresh = _jwt({"exp": _future_exp(3600)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": almost_expired}))
    refresh_route = respx.post(f"{CONTROLLER}/api/login/refresh").mock(
        return_value=httpx.Response(200, json={"token": fresh})
    )

    session = _session()
    session.login()
    token = session.get_valid_access_token()

    assert refresh_route.called
    assert token == fresh


@respx.mock
def test_get_valid_access_token_refreshes_when_already_expired():
    expired = _jwt({"exp": int(time.time()) - 10})
    fresh = _jwt({"exp": _future_exp(3600)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": expired}))
    refresh_route = respx.post(f"{CONTROLLER}/api/login/refresh").mock(
        return_value=httpx.Response(200, json={"token": fresh})
    )

    session = _session()
    session.login()
    token = session.get_valid_access_token()

    assert refresh_route.called
    assert token == fresh


@respx.mock
def test_get_valid_access_token_does_not_refresh_when_far_from_expiry():
    token = _jwt({"exp": _future_exp(3600)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    refresh_route = respx.post(f"{CONTROLLER}/api/login/refresh").mock(return_value=httpx.Response(500))

    session = _session()
    session.login()
    result = session.get_valid_access_token()

    assert not refresh_route.called
    assert result == token


# --- refresh -----------------------------------------------------


@respx.mock
def test_refresh_before_login_raises_auth_error():
    with pytest.raises(PfSenseAuthError):
        _session().refresh()


@respx.mock
def test_refresh_success_updates_token():
    old = _jwt({"exp": _future_exp(3600)})
    new = _jwt({"exp": _future_exp(7200)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": old}))
    respx.post(f"{CONTROLLER}/api/login/refresh").mock(return_value=httpx.Response(200, json={"token": new}))

    session = _session()
    session.login()
    session.refresh()

    assert session.get_valid_access_token() == new


@respx.mock
def test_refresh_failure_raises_auth_error():
    token = _jwt({"exp": _future_exp(3600)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    respx.post(f"{CONTROLLER}/api/login/refresh").mock(
        return_value=httpx.Response(400, json={"errcode": 1, "errlevel": "error", "errmsg": "refresh token expired"})
    )

    session = _session()
    session.login()
    with pytest.raises(PfSenseAuthError):
        session.refresh()


@respx.mock
def test_refresh_network_failure_raises_connection_error():
    token = _jwt({"exp": _future_exp(3600)})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))
    respx.post(f"{CONTROLLER}/api/login/refresh").mock(side_effect=httpx.ConnectError("boom"))

    session = _session()
    session.login()
    with pytest.raises(PfSenseConnectionError):
        session.refresh()


# --- redaction / secret hygiene -----------------------------------


@respx.mock
def test_repr_never_contains_password_or_token():
    secret_password = "SYNTHETIC-SECRET-PASSWORD-MUST-NOT-LEAK"
    token = _jwt({"exp": _future_exp()})
    respx.post(f"{CONTROLLER}/api/login").mock(return_value=httpx.Response(200, json={"token": token}))

    session = NexusSession(controller_url=CONTROLLER, username="admin", password=secret_password)
    session.login()

    dump = repr(session)
    assert secret_password not in dump
    assert token not in dump


@respx.mock
def test_login_failure_exception_never_contains_password():
    secret_password = "SYNTHETIC-SECRET-PASSWORD-MUST-NOT-LEAK"
    respx.post(f"{CONTROLLER}/api/login").mock(
        return_value=httpx.Response(400, json={"errcode": 1, "errlevel": "error", "errmsg": "bad credentials"})
    )
    session = NexusSession(controller_url=CONTROLLER, username="admin", password=secret_password)

    with pytest.raises(PfSenseAuthError) as excinfo:
        session.login()
    assert secret_password not in str(excinfo.value)


@respx.mock
def test_connection_error_exception_never_contains_raw_httpx_message():
    secret = "SYNTHETIC-SECRET-MUST-NOT-ESCAPE"
    respx.post(f"{CONTROLLER}/api/login").mock(side_effect=httpx.ConnectError(secret))
    with pytest.raises(PfSenseConnectionError) as excinfo:
        _session().login()
    assert secret not in str(excinfo.value)


# --- TLS / timeout / redirect defaults ------------------------------


def test_verify_defaults_to_strict():
    assert inspect.signature(NexusSession.__init__).parameters["verify"].default is True


def test_no_hardcoded_insecure_verify_in_source():
    """AST-based, not substring-based: verify=False/verify_ssl=False
    must never appear as an actual keyword-argument literal in this
    module -- the only way verification is ever disabled is a caller
    explicitly passing verify=False in, never a default baked in here
    (unlike every official Netgate example, which hardcodes
    verify_ssl=False -- ADR-032)."""

    import ast
    import inspect as _inspect

    from pfsense_mcp.backends.nexus import session as session_module

    tree = ast.parse(_inspect.getsource(session_module))
    offenders = []
    for node in ast.walk(tree):
        is_verify_kwarg = isinstance(node, ast.keyword) and node.arg in ("verify", "verify_ssl")
        if is_verify_kwarg and isinstance(node.value, ast.Constant) and node.value.value is False:
            offenders.append(node.lineno)
    assert offenders == [], f"hardcoded insecure verify= found at lines {offenders}"


@respx.mock
def test_client_does_not_follow_redirects():
    assert _session()._client.follow_redirects is False


@respx.mock
def test_client_has_explicit_default_timeout():
    session = _session()
    assert session._client.timeout.connect == 10.0
    assert session._client.timeout.read == 30.0


def test_client_accepts_explicit_custom_timeout():
    custom = httpx.Timeout(connect=1.0, read=2.0, write=1.0, pool=1.0)
    session = _session(timeout=custom)
    assert session._client.timeout.connect == 1.0
    assert session._client.timeout.read == 2.0
