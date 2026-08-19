"""BootstrapProvisioningClient — the third, and only other, module
(alongside `rest_api_client.py` and `write_api_client.py`; see
`scripts/get_only_check.py`'s allow-list) permitted to call a
Transport's `request()` method directly.

`ADR-033` implementation Phase C, requirement 8 ("HTTP surface"): this
client exposes a closed set of named pfSense REST API operations,
deliberately kept separate from the normal 42-tool endpoint catalogue
(`endpoints.py`/`Endpoints`) and from the write allow-list
(`write_endpoints.py`/`WriteEndpoints`) -- provisioning a pfSense
identity is an orthogonal concern from both. There is no generic
`request(method, path)` passthrough anywhere on this class; every
operation is a named method with a fixed, hard-coded path.

- `list_users()` -- `GET /api/v2/users`. Read-before-write observation.
- `create_user()` -- `POST /api/v2/user` (singular). Dedicated-account
  creation only.
- `update_user_privileges()` -- `PATCH /api/v2/user` (singular). Full
  privilege-list replace semantics -- the live pfSense REST API has no
  append/remove query support for this field, confirmed by the actual
  live ADR-026 provisioning procedure this client's payload shapes are
  derived from (see module-level citation below).
- `create_auth_key()` -- `POST /api/v2/auth/key` (singular). Must be
  called with a Transport authenticated as the target account itself
  (HTTP Basic Auth, username + password) -- pfSense's REST API key
  model is self-service only (`username = $this->client->username`),
  never callable on another account's behalf, matching
  `security_bootstrap_transaction.py`'s own documented reason for why
  `BOOTSTRAP_ONLY_PRIVILEGE` exists at all.
- `_list_auth_keys_for_recovery()` -- `GET /api/v2/auth/keys`. Read-only recovery
  observation that deliberately omits any plaintext key field.
- `_revoke_auth_key_for_recovery()` -- `DELETE /api/v2/auth/key` and
  `_delete_user_for_recovery()` -- `DELETE /api/v2/user`. These two
  private methods are callable only by `security_bootstrap_recovery.py`'s
  fixed-identity, read-before-write recovery functions. They are not a
  generic DELETE surface and accept only an integer model ID.
- `_observe_auth_settings_for_transition()` and the two fixed enable/restore
  projections use only `GET`/`PATCH /api/v2/system/restapi/settings`. The
  private mutation projections have literal payloads; callers cannot choose
  another setting or authentication-method set. The separately isolated
  `security_auth_transition.py` coordinator owns fresh-transport,
  at-most-once, bounded-reconnect, and independent-verification semantics.

**Payload/response shapes are not guessed.** They are transcribed
directly from a real, already-executed, already-authorized live
provisioning procedure performed during `ADR-026`'s acceptance-matrix
work (2026-08-16, scratch scripts `provision_step1_create_user.py`
through `provision_step5_revoke_bootstrap.py`), which created and later
decommissioned the real least-privilege LAB identity
`pfsense_mcp_tier1_lab` against a live pfSense v2 appliance. This phase
performs **no new live call** -- it packages already-observed evidence
into named, tested, reusable methods.

No pfSense contact happens merely by importing or constructing this
class -- every method requires an explicit, caller-supplied `Transport`
and is only ever exercised in this repository via `MockTransport`
(`tests/test_security_bootstrap_client.py`). Never imports
`pfsense_mcp.tier1` in any form.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from hashlib import sha256
from typing import Any

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .transport.base import Transport

_USER_PATH = "/user"
_USERS_PATH = "/users"
_AUTH_KEY_PATH = "/auth/key"
_AUTH_KEYS_PATH = "/auth/keys?limit=100"
_RESTAPI_SETTINGS_PATH = "/system/restapi/settings"


def _full_path(path_suffix: str, api_version: ApiVersion) -> str:
    return f"/api/{api_version.value}{path_suffix}"


@dataclass(frozen=True)
class ObservedUser:
    """A single pfSense user account record, as actually observed via
    `GET /api/v2/users`, `POST /api/v2/user`, or `PATCH /api/v2/user`'s
    response -- never a caller-constructed value. `priv` is a
    `frozenset` (order and duplication are not meaningful for privilege
    membership)."""

    id: int
    name: str
    descr: str
    priv: frozenset[str]
    disabled: bool
    scope: str | None = None


@dataclass(frozen=True)
class ObservedApiKey:
    """Non-secret API-key metadata from an authoritative list read.

    The upstream representation may contain a plaintext ``key`` field
    in some contexts.  This type intentionally has no such field, so a
    recovery observation cannot retain, print, or return credential
    material.
    """

    id: int
    username: str | None
    descr: str
    hash_algo: str
    length_bytes: int


@dataclass(frozen=True)
class ObservedAuthSettings:
    """Minimal, secret-free authoritative authentication-settings view.

    The complete response participates in ``unrelated_digest`` after removing
    only ``auth_methods``.  This lets the transition coordinator prove that no
    sibling setting changed without retaining or exposing identifying settings.
    """

    auth_methods: frozenset[str]
    unrelated_digest: str


@dataclass(frozen=True)
class ProvisionedApiKey:
    """The result of a successful `create_auth_key()` call. The raw
    secret is held in a `repr=False` field so it can never appear in
    `repr()`, `str()`, a log line built from `%r`/`%s` of this object,
    or an ordinary exception message that happens to include this
    object -- the only way to obtain the actual value is the explicit
    `reveal()` call, matching this phase's requirement 7."""

    username: str
    descr: str
    hash_algo: str
    length_bytes: int
    _secret: str = field(default="", repr=False)

    def reveal(self) -> str:
        """The one, explicit, unmistakably-named accessor for the
        secret value. Callers must not store the return value longer
        than needed and must never log, print, or embed it in an
        exception message."""

        return self._secret


def _check_response(response_status: int, response_text: str, *, operation: str) -> dict[str, Any]:
    """Shared status/shape handling for all four operations. Never
    includes `response_text` (which may echo a password or other
    caller-supplied payload field) in a raised exception's message --
    only the operation name and status code."""

    if not 200 <= response_status < 300:
        raise BootstrapProvisioningError(
            f"{operation} failed: pfSense API returned HTTP {response_status}.", status_code=response_status
        )

    try:
        body = json.loads(response_text)
    except ValueError:
        raise BootstrapProvisioningError(f"{operation}: response was not valid JSON.") from None

    if not isinstance(body, dict):
        raise BootstrapProvisioningError(f"{operation}: response was not a JSON object.")

    data = body.get("data")
    if not isinstance(data, dict):
        raise BootstrapProvisioningError(f"{operation}: response had no 'data' object.")

    return data


def _parse_observed_user(data: dict[str, Any], *, operation: str) -> ObservedUser:
    try:
        user_id = data["id"]
        name = data["name"]
        descr = data["descr"]
        priv = data["priv"]
        disabled = data["disabled"]
    except KeyError as exc:
        raise BootstrapProvisioningError(f"{operation}: response 'data' missing expected field {exc}.") from None

    scope = data.get("scope")
    if (
        not isinstance(user_id, int)
        or not isinstance(name, str)
        or not isinstance(descr, str)
        or not isinstance(disabled, bool)
        or (scope is not None and not isinstance(scope, str))
    ):
        raise BootstrapProvisioningError(f"{operation}: response 'data' had an unexpected field type.")
    if not isinstance(priv, list) or not all(isinstance(p, str) for p in priv):
        raise BootstrapProvisioningError(f"{operation}: response 'data.priv' was not a list of strings.")

    return ObservedUser(id=user_id, name=name, descr=descr, priv=frozenset(priv), disabled=disabled, scope=scope)


def _parse_observed_api_key(data: dict[str, Any], *, operation: str) -> ObservedApiKey:
    try:
        key_id = data["id"]
        username = data["username"]
        descr = data["descr"]
        hash_algo = data["hash_algo"]
        length_bytes = data["length_bytes"]
    except KeyError as exc:
        raise BootstrapProvisioningError(f"{operation}: response 'data' missing expected field {exc}.") from None

    if (
        not isinstance(key_id, int)
        or isinstance(key_id, bool)
        or key_id < 0
        or (username is not None and not isinstance(username, str))
        or not isinstance(descr, str)
        or not isinstance(hash_algo, str)
        or not isinstance(length_bytes, int)
        or isinstance(length_bytes, bool)
    ):
        raise BootstrapProvisioningError(f"{operation}: response 'data' had an unexpected field type.")
    return ObservedApiKey(
        id=key_id,
        username=username,
        descr=descr,
        hash_algo=hash_algo,
        length_bytes=length_bytes,
    )


def _parse_auth_settings(data: dict[str, Any], *, operation: str) -> ObservedAuthSettings:
    auth_methods = data.get("auth_methods")
    if (
        not isinstance(auth_methods, list)
        or not auth_methods
        or not all(isinstance(method, str) and method for method in auth_methods)
        or len(set(auth_methods)) != len(auth_methods)
    ):
        raise BootstrapProvisioningError(f"{operation}: response had malformed authentication methods.")
    unrelated = {key: value for key, value in data.items() if key != "auth_methods"}
    try:
        canonical = json.dumps(unrelated, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, UnicodeError):
        raise BootstrapProvisioningError(f"{operation}: response had malformed unrelated settings.") from None
    digest = sha256(b"pfsense-restapi-settings-unrelated-v1\x00" + canonical).hexdigest()
    return ObservedAuthSettings(auth_methods=frozenset(auth_methods), unrelated_digest=digest)


class BootstrapProvisioningClient:
    """Bound to exactly one `Transport` for its lifetime -- callers
    needing both an admin-authenticated call and a self-service
    (Basic-Auth) call construct two separate instances, one per
    Transport. This class has no opinion on how a Transport is
    authenticated; that is entirely the caller's concern."""

    def __init__(self, transport: Transport, *, api_version: ApiVersion) -> None:
        self._transport = transport
        self._api_version = api_version

    def list_users(self) -> tuple[ObservedUser, ...]:
        """`GET /api/v2/users` -- the read-before-write observation
        step. Returns every user account pfSense reports; callers
        filter by `name` themselves."""

        path = _full_path(_USERS_PATH, self._api_version)
        response = self._transport.request("GET", path)
        if not 200 <= response.status_code < 300:
            raise BootstrapProvisioningError(f"list_users failed: pfSense API returned HTTP {response.status_code}.")
        try:
            body = json.loads(response.text)
        except ValueError:
            raise BootstrapProvisioningError("list_users: response was not valid JSON.") from None
        if not isinstance(body, dict):
            raise BootstrapProvisioningError("list_users: response was not a JSON object.")
        data = body.get("data")
        if not isinstance(data, list):
            raise BootstrapProvisioningError("list_users: response 'data' was not a list.")
        if not all(isinstance(entry, dict) for entry in data):
            raise BootstrapProvisioningError("list_users: response 'data' contained a non-object entry.")
        return tuple(_parse_observed_user(entry, operation="list_users") for entry in data)

    def _list_auth_keys_for_recovery(self) -> tuple[ObservedApiKey, ...]:
        """Authoritatively list non-secret API-key metadata for recovery."""

        path = _full_path(_AUTH_KEYS_PATH, self._api_version)
        response = self._transport.request("GET", path)
        if not 200 <= response.status_code < 300:
            raise BootstrapProvisioningError(
                f"list_auth_keys failed: pfSense API returned HTTP {response.status_code}."
            )
        try:
            body = json.loads(response.text)
        except ValueError:
            raise BootstrapProvisioningError("list_auth_keys: response was not valid JSON.") from None
        if not isinstance(body, dict):
            raise BootstrapProvisioningError("list_auth_keys: response was not a JSON object.")
        data = body.get("data")
        if not isinstance(data, list):
            raise BootstrapProvisioningError("list_auth_keys: response 'data' was not a list.")
        if not all(isinstance(entry, dict) for entry in data):
            raise BootstrapProvisioningError("list_auth_keys: response 'data' contained a non-object entry.")
        return tuple(_parse_observed_api_key(entry, operation="list_auth_keys") for entry in data)

    def _observe_auth_settings_for_transition(self) -> ObservedAuthSettings:
        """Read the one fixed settings resource for auth-transition evidence."""

        path = _full_path(_RESTAPI_SETTINGS_PATH, self._api_version)
        response = self._transport.request("GET", path)
        data = _check_response(response.status_code, response.text, operation="observe_auth_settings")
        return _parse_auth_settings(data, operation="observe_auth_settings")

    def _enable_basic_auth_for_transition(self) -> None:
        """Send the sole accepted enable payload; selection remains closed."""

        path = _full_path(_RESTAPI_SETTINGS_PATH, self._api_version)
        response = self._transport.request(
            "PATCH",
            path,
            body=b'{"auth_methods":["KeyAuth","BasicAuth"]}',
        )
        _check_response(response.status_code, response.text, operation="enable_basic_auth")

    def _restore_key_auth_for_transition(self) -> None:
        """Send the sole accepted steady-state restoration payload."""

        path = _full_path(_RESTAPI_SETTINGS_PATH, self._api_version)
        response = self._transport.request(
            "PATCH",
            path,
            body=b'{"auth_methods":["KeyAuth"]}',
        )
        _check_response(response.status_code, response.text, operation="restore_key_auth")

    def create_user(self, *, name: str, password: str, descr: str, priv: frozenset[str]) -> ObservedUser:
        """`POST /api/v2/user` -- creates one new pfSense account.
        `password` is included in the request body only (never logged,
        never included in any exception message this client raises)."""

        path = _full_path(_USER_PATH, self._api_version)
        payload = {
            "name": name,
            "password": password,
            "descr": descr,
            "disabled": False,
            "priv": sorted(priv),
        }
        response = self._transport.request("POST", path, body=json.dumps(payload).encode("utf-8"))
        data = _check_response(response.status_code, response.text, operation="create_user")
        return _parse_observed_user(data, operation="create_user")

    def update_user_privileges(self, *, user_id: int, priv: frozenset[str]) -> ObservedUser:
        """`PATCH /api/v2/user` -- full-replace of the target account's
        privilege list (confirmed by live evidence: this endpoint has
        no partial-update semantics for `priv`). Callers must always
        compute `priv` from a fresh read plus an explicit diff, never a
        hard-coded list -- this method itself performs no diffing; that
        is `security_bootstrap_engine.py`'s responsibility."""

        path = _full_path(_USER_PATH, self._api_version)
        payload = {"id": user_id, "priv": sorted(priv)}
        response = self._transport.request("PATCH", path, body=json.dumps(payload).encode("utf-8"))
        data = _check_response(response.status_code, response.text, operation="update_user_privileges")
        return _parse_observed_user(data, operation="update_user_privileges")

    def create_auth_key(self, *, descr: str) -> ProvisionedApiKey:
        """`POST /api/v2/auth/key` -- self-service API-key generation.
        The bound `Transport` must already be authenticated as the
        target account (HTTP Basic Auth); this method does not manage
        authentication itself. Requires the account to currently hold
        `security_bootstrap_transaction.BOOTSTRAP_ONLY_PRIVILEGE`."""

        path = _full_path(_AUTH_KEY_PATH, self._api_version)
        payload = {"descr": descr}
        response = self._transport.request("POST", path, body=json.dumps(payload).encode("utf-8"))
        data = _check_response(response.status_code, response.text, operation="create_auth_key")

        try:
            username = data["username"]
            hash_algo = data["hash_algo"]
            length_bytes = data["length_bytes"]
            raw_key = data["key"]
        except KeyError as exc:
            raise BootstrapProvisioningError(
                f"create_auth_key: response 'data' missing expected field {exc}."
            ) from None

        if not isinstance(raw_key, str) or not raw_key:
            raise BootstrapProvisioningError("create_auth_key: response did not contain a usable 'key' string.")
        if not isinstance(username, str) or not isinstance(hash_algo, str) or not isinstance(length_bytes, int):
            raise BootstrapProvisioningError("create_auth_key: response 'data' had an unexpected field type.")

        return ProvisionedApiKey(
            username=username,
            descr=descr,
            hash_algo=hash_algo,
            length_bytes=length_bytes,
            _secret=raw_key,
        )

    def _revoke_auth_key_for_recovery(self, *, key_id: int) -> None:
        """Delete one ID selected by the fixed recovery coordinator.

        This private transport projection performs no selection and is
        intentionally unusable as a generic public recovery API.
        """

        if not isinstance(key_id, int) or isinstance(key_id, bool) or key_id < 0:
            raise BootstrapProvisioningError("revoke_auth_key_for_recovery: key ID is invalid.")
        path = _full_path(_AUTH_KEY_PATH, self._api_version)
        response = self._transport.request("DELETE", path, body=json.dumps({"id": key_id}).encode("utf-8"))
        _check_response(response.status_code, response.text, operation="revoke_auth_key_for_recovery")

    def _delete_user_for_recovery(self, *, user_id: int) -> None:
        """Delete one ID selected by the fixed recovery coordinator."""

        if not isinstance(user_id, int) or isinstance(user_id, bool) or user_id < 0:
            raise BootstrapProvisioningError("delete_user_for_recovery: user ID is invalid.")
        path = _full_path(_USER_PATH, self._api_version)
        response = self._transport.request("DELETE", path, body=json.dumps({"id": user_id}).encode("utf-8"))
        _check_response(response.status_code, response.text, operation="delete_user_for_recovery")
