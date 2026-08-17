"""Unit tests for `pfsense_mcp.security_bootstrap_client`
(`ADR-033` implementation Phase C) -- the four enumerated pfSense HTTP
operations this project's bootstrap engine consumes. Every test uses
`MockTransport` (in-memory, no HTTP library involved); no real pfSense
appliance is ever contacted."""

from __future__ import annotations

import json

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import BootstrapProvisioningError
from pfsense_mcp.security_bootstrap_client import BootstrapProvisioningClient, ObservedUser, ProvisionedApiKey
from pfsense_mcp.transport.mock import MockTransport

_USERS_PATH = "/api/v2/users"
_USER_PATH = "/api/v2/user"
_AUTH_KEY_PATH = "/api/v2/auth/key"


def _client(transport: MockTransport) -> BootstrapProvisioningClient:
    return BootstrapProvisioningClient(transport, api_version=ApiVersion.V2)


# --- list_users() -----------------------------------------------------


def test_list_users_parses_multiple_records():
    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps(
            {
                "data": [
                    {"id": 0, "name": "admin", "priv": ["page-all"], "disabled": False},
                    {"id": 1, "name": "svc", "priv": ["api-v2-status-system-get"], "disabled": False},
                ]
            }
        ),
    )

    users = _client(transport).list_users()

    assert users == (
        ObservedUser(id=0, name="admin", priv=frozenset({"page-all"}), disabled=False),
        ObservedUser(id=1, name="svc", priv=frozenset({"api-v2-status-system-get"}), disabled=False),
    )


def test_list_users_empty_data_is_empty_tuple():
    transport = MockTransport()
    transport.register("GET", _USERS_PATH, status_code=200, text=json.dumps({"data": []}))

    assert _client(transport).list_users() == ()


def test_list_users_non_2xx_raises_without_leaking_body():
    transport = MockTransport()
    transport.register("GET", _USERS_PATH, status_code=403, text=json.dumps({"secret_canary": "SHOULD_NOT_LEAK"}))

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        _client(transport).list_users()

    assert "SHOULD_NOT_LEAK" not in str(excinfo.value)
    assert "403" in str(excinfo.value)


def test_list_users_malformed_data_shape_raises():
    transport = MockTransport()
    transport.register("GET", _USERS_PATH, status_code=200, text=json.dumps({"data": "not-a-list"}))

    with pytest.raises(BootstrapProvisioningError):
        _client(transport).list_users()


def test_list_users_missing_field_raises():
    transport = MockTransport()
    transport.register(
        "GET", _USERS_PATH, status_code=200, text=json.dumps({"data": [{"id": 0, "name": "admin", "disabled": False}]})
    )

    with pytest.raises(BootstrapProvisioningError):
        _client(transport).list_users()


# --- create_user() ------------------------------------------------------


def test_create_user_sends_expected_payload_and_parses_response():
    transport = MockTransport()
    transport.register(
        "POST",
        _USER_PATH,
        status_code=200,
        text=json.dumps({"data": {"id": 5, "name": "svc", "priv": ["a-get", "b-get"], "disabled": False}}),
    )

    created = _client(transport).create_user(
        name="svc", password="hunter2-generated", descr="a service account", priv=frozenset({"b-get", "a-get"})
    )

    assert created == ObservedUser(id=5, name="svc", priv=frozenset({"a-get", "b-get"}), disabled=False)
    sent = json.loads(transport.request_bodies[0])
    assert sent == {
        "name": "svc",
        "password": "hunter2-generated",
        "descr": "a service account",
        "disabled": False,
        "priv": ["a-get", "b-get"],
    }


def test_create_user_non_2xx_raises():
    transport = MockTransport()
    transport.register("POST", _USER_PATH, status_code=400, text=json.dumps({"message": "duplicate name"}))

    with pytest.raises(BootstrapProvisioningError):
        _client(transport).create_user(name="svc", password="x", descr="d", priv=frozenset())


# --- update_user_privileges() -------------------------------------------


def test_update_user_privileges_sends_full_replace_payload():
    transport = MockTransport()
    transport.register(
        "PATCH",
        _USER_PATH,
        status_code=200,
        text=json.dumps({"data": {"id": 5, "name": "svc", "priv": ["a-get"], "disabled": False}}),
    )

    updated = _client(transport).update_user_privileges(user_id=5, priv=frozenset({"a-get"}))

    assert updated.priv == frozenset({"a-get"})
    sent = json.loads(transport.request_bodies[0])
    assert sent == {"id": 5, "priv": ["a-get"]}


def test_update_user_privileges_non_2xx_raises():
    transport = MockTransport()
    transport.register("PATCH", _USER_PATH, status_code=500, text=json.dumps({"message": "server error"}))

    with pytest.raises(BootstrapProvisioningError):
        _client(transport).update_user_privileges(user_id=5, priv=frozenset())


# --- create_auth_key() ---------------------------------------------------


def test_create_auth_key_parses_and_redacts_secret():
    transport = MockTransport()
    transport.register(
        "POST",
        _AUTH_KEY_PATH,
        status_code=200,
        text=json.dumps(
            {
                "data": {
                    "username": "svc",
                    "descr": "d",
                    "hash_algo": "sha256",
                    "length_bytes": 32,
                    "key": "TOP-SECRET-VALUE",
                }
            }
        ),
    )

    key = _client(transport).create_auth_key(descr="d")

    assert isinstance(key, ProvisionedApiKey)
    assert key.reveal() == "TOP-SECRET-VALUE"
    assert "TOP-SECRET-VALUE" not in repr(key)
    assert "TOP-SECRET-VALUE" not in str(key)
    assert key.username == "svc"
    assert key.hash_algo == "sha256"
    assert key.length_bytes == 32


def test_create_auth_key_missing_key_field_raises():
    transport = MockTransport()
    transport.register(
        "POST",
        _AUTH_KEY_PATH,
        status_code=200,
        text=json.dumps({"data": {"username": "svc", "descr": "d", "hash_algo": "sha256", "length_bytes": 32}}),
    )

    with pytest.raises(BootstrapProvisioningError):
        _client(transport).create_auth_key(descr="d")


def test_create_auth_key_non_2xx_raises_without_leaking_body():
    transport = MockTransport()
    transport.register("POST", _AUTH_KEY_PATH, status_code=403, text=json.dumps({"secret_canary": "SHOULD_NOT_LEAK"}))

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        _client(transport).create_auth_key(descr="d")

    assert "SHOULD_NOT_LEAK" not in str(excinfo.value)


# --- No generic dispatch --------------------------------------------------


def test_client_public_surface_is_exactly_four_named_operations():
    public_methods = {name for name in dir(BootstrapProvisioningClient) if not name.startswith("_")}
    assert public_methods == {"list_users", "create_user", "update_user_privileges", "create_auth_key"}
