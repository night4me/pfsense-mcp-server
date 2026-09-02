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
from pfsense_mcp.security_bootstrap_client import (
    BootstrapProvisioningClient,
    ObservedAuthSettings,
    ObservedUser,
    ProvisionedApiKey,
)
from pfsense_mcp.transport.mock import MockTransport

_USERS_PATH = "/api/v2/users"
_USER_PATH = "/api/v2/user"
_AUTH_KEY_PATH = "/api/v2/auth/key"
_SETTINGS_PATH = "/api/v2/system/restapi/settings"


def _client(transport: MockTransport) -> BootstrapProvisioningClient:
    return BootstrapProvisioningClient(transport, api_version=ApiVersion.V2)


def test_auth_transition_client_operations_are_fixed_and_preserve_sibling_evidence():
    transport = MockTransport()
    transport.register(
        "GET",
        _SETTINGS_PATH,
        status_code=200,
        text=json.dumps({"data": {"auth_methods": ["KeyAuth"], "sibling": "preserved"}}),
    )
    transport.register("PATCH", _SETTINGS_PATH, status_code=200, text=json.dumps({"data": {}}))
    client = _client(transport)

    observed = client._observe_auth_settings_for_transition()
    client._enable_basic_auth_for_transition()
    client._restore_key_auth_for_transition()

    assert isinstance(observed, ObservedAuthSettings)
    assert observed.auth_methods == frozenset({"KeyAuth"})
    assert len(observed.unrelated_digest) == 64
    assert transport.calls == [
        ("GET", _SETTINGS_PATH),
        ("PATCH", _SETTINGS_PATH),
        ("PATCH", _SETTINGS_PATH),
    ]
    assert transport.request_bodies == [
        None,
        b'{"auth_methods":["KeyAuth","BasicAuth"]}',
        b'{"auth_methods":["KeyAuth"]}',
    ]


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
                    {"id": 0, "name": "admin", "descr": "Administrator", "priv": ["page-all"], "disabled": False},
                    {
                        "id": 1,
                        "name": "svc",
                        "descr": "Dedicated service account",
                        "priv": ["api-v2-status-system-get"],
                        "disabled": False,
                    },
                ]
            }
        ),
    )

    users = _client(transport).list_users()

    assert users == (
        ObservedUser(id=0, name="admin", descr="Administrator", priv=frozenset({"page-all"}), disabled=False),
        ObservedUser(
            id=1,
            name="svc",
            descr="Dedicated service account",
            priv=frozenset({"api-v2-status-system-get"}),
            disabled=False,
        ),
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


def test_list_users_null_priv_is_treated_as_empty_privilege_set():
    """A pfSense user whose effective privileges come entirely from
    group membership legitimately reports `priv: null`, not `priv: []`
    -- observed live against production during an ADR-033 read_only
    bootstrap pre-flight observation. Must be accepted as an empty
    directly-assigned privilege set, not rejected."""

    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps(
            {"data": [{"id": 2, "name": "api-mcp-admin", "descr": "api-mcp-admin", "priv": None, "disabled": False}]}
        ),
    )

    users = _client(transport).list_users()

    assert users == (ObservedUser(id=2, name="api-mcp-admin", descr="api-mcp-admin", priv=frozenset(), disabled=False),)


def test_list_users_empty_list_priv_is_accepted_unchanged():
    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps({"data": [{"id": 3, "name": "svc", "descr": "svc", "priv": [], "disabled": False}]}),
    )

    users = _client(transport).list_users()

    assert users == (ObservedUser(id=3, name="svc", descr="svc", priv=frozenset(), disabled=False),)


def test_list_users_valid_string_list_priv_is_accepted_unchanged():
    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps(
            {"data": [{"id": 4, "name": "svc", "descr": "svc", "priv": ["a-get", "b-get"], "disabled": False}]}
        ),
    )

    users = _client(transport).list_users()

    assert users == (ObservedUser(id=4, name="svc", descr="svc", priv=frozenset({"a-get", "b-get"}), disabled=False),)


def test_list_users_non_null_non_list_priv_still_raises():
    """A bare string (or any other non-null, non-list shape) must still
    fail closed exactly as before -- only literal `None` is normalized."""

    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps({"data": [{"id": 5, "name": "svc", "descr": "svc", "priv": "page-all", "disabled": False}]}),
    )

    with pytest.raises(BootstrapProvisioningError, match="was not a list of strings"):
        _client(transport).list_users()


def test_list_users_priv_list_with_non_string_member_still_raises():
    transport = MockTransport()
    transport.register(
        "GET",
        _USERS_PATH,
        status_code=200,
        text=json.dumps({"data": [{"id": 6, "name": "svc", "descr": "svc", "priv": ["a-get", 1], "disabled": False}]}),
    )

    with pytest.raises(BootstrapProvisioningError, match="was not a list of strings"):
        _client(transport).list_users()


# --- create_user() ------------------------------------------------------


def test_create_user_sends_expected_payload_and_parses_response():
    transport = MockTransport()
    transport.register(
        "POST",
        _USER_PATH,
        status_code=200,
        text=json.dumps(
            {
                "data": {
                    "id": 5,
                    "name": "svc",
                    "descr": "a service account",
                    "priv": ["a-get", "b-get"],
                    "disabled": False,
                }
            }
        ),
    )

    created = _client(transport).create_user(
        name="svc", password="hunter2-generated", descr="a service account", priv=frozenset({"b-get", "a-get"})
    )

    assert created == ObservedUser(
        id=5, name="svc", descr="a service account", priv=frozenset({"a-get", "b-get"}), disabled=False
    )
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
        text=json.dumps(
            {"data": {"id": 5, "name": "svc", "descr": "a service account", "priv": ["a-get"], "disabled": False}}
        ),
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
