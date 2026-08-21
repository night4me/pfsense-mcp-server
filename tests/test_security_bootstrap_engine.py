"""Tests for `pfsense_mcp.security_bootstrap_engine`
(`ADR-033` implementation Phase C) -- the full read-before-write
provisioning sequence, exercised entirely against deterministic,
in-memory fake transports (`_FakeAdminTransport`/
`_FakeSelfServiceTransport` below), never a real pfSense appliance.

`_FakeAdminTransport` models just enough of pfSense's user-array
behavior (GET/POST/PATCH on the `/user(s)` resource) to drive the
engine through every state the real sequence would produce, including
mid-sequence failures at each named checkpoint -- `MockTransport`
(the shared fixed-response fake used elsewhere in this suite) cannot
express "the same GET returns different data on successive calls,"
which this engine's re-read-after-every-mutation design requires.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest
import respx

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.security_bootstrap_engine import (
    ProvisioningOutcome,
    TargetProfile,
    provision_service_account,
)
from pfsense_mcp.security_bootstrap_transaction import (
    BOOTSTRAP_ONLY_PRIVILEGE,
    BootstrapState,
    is_steady_state_privilege_set,
)
from pfsense_mcp.security_privileges import read_profile_requirements, resolve_profile_privileges
from pfsense_mcp.transport.base import TransportConfigurationError, TransportResponse
from pfsense_mcp.transport.http import BasicAuthHttpTransport

_USERS_PATH = "/api/v2/users"
_USER_PATH = "/api/v2/user"
_AUTH_KEY_PATH = "/api/v2/auth/key"
_USER_DESCR = "Dedicated service account for pfsense-mcp-server"


def _load_trimmed_schema() -> dict:
    import pathlib

    path = pathlib.Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
    return json.loads(path.read_text(encoding="utf-8"))


_SCHEMA = _load_trimmed_schema()


def _read_only_expected_privileges() -> frozenset[str]:
    from pfsense_mcp.security_privileges import distinct_ok_privileges

    resolved = resolve_profile_privileges(_SCHEMA, read_profile_requirements())
    return distinct_ok_privileges(resolved)


_EXPECTED_READ_PRIVS = _read_only_expected_privileges()


class _FakeAdminTransport:
    """In-memory stand-in for the admin-authenticated pfSense
    connection. `fail_on` maps an operation key
    ("GET_users" | "POST_user" | "PATCH_user") to a 1-indexed call
    ordinal (scoped to that key) that should return a synthetic error
    instead of succeeding -- lets a test fail exactly one specific step
    in the sequence without needing a stateful protocol mock."""

    def __init__(self) -> None:
        self.users: dict[int, dict] = {}
        self._next_id = 1
        self.calls: list[tuple[str, str]] = []
        self._call_counts: dict[str, int] = {}
        self.fail_on: dict[str, int] = {}

    def seed_user(
        self, *, user_id: int, name: str, priv: frozenset[str], disabled: bool = False, descr: str = _USER_DESCR
    ) -> None:
        self.users[user_id] = {
            "id": user_id,
            "name": name,
            "descr": descr,
            "priv": sorted(priv),
            "disabled": disabled,
        }
        self._next_id = max(self._next_id, user_id + 1)

    def _maybe_fail(self, key: str) -> TransportResponse | None:
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        if self.fail_on.get(key) == self._call_counts[key]:
            return TransportResponse(500, json.dumps({"message": "synthetic failure"}))
        return None

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))

        if method == "GET" and path == _USERS_PATH:
            failure = self._maybe_fail("GET_users")
            if failure is not None:
                return failure
            return TransportResponse(200, json.dumps({"data": list(self.users.values())}))

        if method == "POST" and path == _USER_PATH:
            failure = self._maybe_fail("POST_user")
            if failure is not None:
                return failure
            payload = json.loads(body)
            user_id = self._next_id
            self._next_id += 1
            record = {
                "id": user_id,
                "name": payload["name"],
                "descr": payload["descr"],
                "priv": payload["priv"],
                "disabled": False,
            }
            self.users[user_id] = record
            return TransportResponse(200, json.dumps({"data": record}))

        if method == "PATCH" and path == _USER_PATH:
            failure = self._maybe_fail("PATCH_user")
            if failure is not None:
                return failure
            payload = json.loads(body)
            record = self.users[payload["id"]]
            record["priv"] = payload["priv"]
            return TransportResponse(200, json.dumps({"data": record}))

        raise AssertionError(f"_FakeAdminTransport received an unexpected call: {method} {path}")


class _FakeSelfServiceTransport:
    def __init__(self, *, status_code: int = 200, key_value: str = "fake-generated-secret-key") -> None:
        self.calls: list[tuple[str, str]] = []
        self._status_code = status_code
        self._key_value = key_value

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        if method != "POST" or path != _AUTH_KEY_PATH:
            raise AssertionError(f"_FakeSelfServiceTransport received an unexpected call: {method} {path}")
        if self._status_code != 200:
            return TransportResponse(self._status_code, json.dumps({"message": "synthetic failure"}))
        return TransportResponse(
            200,
            json.dumps(
                {
                    "data": {
                        "username": "svc",
                        "descr": "d",
                        "hash_algo": "sha256",
                        "length_bytes": 32,
                        "key": self._key_value,
                    }
                }
            ),
        )


def _factory(self_transport: _FakeSelfServiceTransport):
    def _build(username: str, password: str):
        assert username == "pfsense_mcp_svc"
        assert password  # a real (non-empty) generated value was supplied
        return self_transport

    return _build


def _provision(admin: _FakeAdminTransport, *, self_transport: _FakeSelfServiceTransport | None = None, **kwargs):
    self_transport = self_transport or _FakeSelfServiceTransport()
    return provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(self_transport),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=_SCHEMA,
        **kwargs,
    ), self_transport


# --- derivation gate -------------------------------------------------


def test_missing_schema_fails_closed_before_any_http_call():
    admin = _FakeAdminTransport()
    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=None,
    )

    assert result.outcome is ProvisioningOutcome.DERIVATION_FAILED
    assert admin.calls == []


def test_schema_source_disagreement_fails_closed():
    admin = _FakeAdminTransport()
    bad_schema = json.loads(json.dumps(_SCHEMA))
    op = bad_schema["paths"]["/api/v2/status/system"]["get"]
    op["description"] = op["description"].replace("api-v2-status-system-get", "api-v2-totally-renamed-get")

    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=bad_schema,
    )

    assert result.outcome is ProvisioningOutcome.DERIVATION_FAILED
    assert admin.calls == []


def test_malformed_privilege_evidence_fails_closed():
    admin = _FakeAdminTransport()
    bad_schema = json.loads(json.dumps(_SCHEMA))
    op = bad_schema["paths"]["/api/v2/status/system"]["get"]
    op["description"] = "no allowed privileges text here at all"

    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=bad_schema,
    )

    assert result.outcome is ProvisioningOutcome.DERIVATION_FAILED
    assert admin.calls == []


@pytest.mark.parametrize("version", [(2, 6, 0), (2, 11, 0)])
def test_unsupported_package_version_fails_closed(version):
    admin = _FakeAdminTransport()
    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=_SCHEMA,
        installed_package_version=version,
    )

    assert result.outcome is ProvisioningOutcome.DERIVATION_FAILED
    assert admin.calls == []


def test_supported_package_version_does_not_block():
    admin = _FakeAdminTransport()
    result, _ = _provision(admin, installed_package_version=(2, 10, 0))
    assert result.outcome is ProvisioningOutcome.COMPLETED


# --- fresh account: happy path -------------------------------------------


def test_fresh_account_completes_full_sequence_read_only_profile():
    admin = _FakeAdminTransport()
    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.COMPLETED
    assert result.transaction is not None
    assert result.transaction.state is BootstrapState.VERIFIED
    assert result.transaction.privileges == _EXPECTED_READ_PRIVS
    assert is_steady_state_privilege_set(result.transaction.privileges)
    assert BOOTSTRAP_ONLY_PRIVILEGE not in result.transaction.privileges

    assert result.api_key is not None
    assert result.api_key.reveal() == "fake-generated-secret-key"
    assert self_transport.calls == [("POST", _AUTH_KEY_PATH)]

    # Final observed server-side state: exactly the target profile, bootstrap privilege gone.
    final = admin.users[1]
    assert set(final["priv"]) == _EXPECTED_READ_PRIVS
    assert BOOTSTRAP_ONLY_PRIVILEGE not in final["priv"]

    # PATCH called exactly twice: grant, then revoke.
    patch_calls = [c for c in admin.calls if c[0] == "PATCH"]
    assert len(patch_calls) == 2


@respx.mock
def test_fresh_account_uses_real_basic_auth_transport_at_the_existing_factory_seam():
    """Offline end-to-end proof of the exact ADR-033 integration:
    the engine supplies its transient generated credentials to the
    caller-owned factory, while the fixed provisioning client remains
    the only component selecting POST /auth/key."""

    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        return_value=httpx.Response(
            200,
            json={
                "data": {
                    "username": "pfsense_mcp_svc",
                    "descr": "d",
                    "hash_algo": "sha256",
                    "length_bytes": 32,
                    "key": "synthetic-generated-api-key",
                }
            },
        )
    )
    admin = _FakeAdminTransport()

    def factory(username: str, password: str):
        return BasicAuthHttpTransport("https://pfsense.example.invalid", username, password, True)

    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=factory,
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=_SCHEMA,
        password_factory=lambda: "synthetic-bootstrap-password",
        key_descr="d",
    )

    assert result.outcome is ProvisioningOutcome.COMPLETED
    assert result.api_key is not None
    assert result.api_key.reveal() == "synthetic-generated-api-key"
    assert len(route.calls) == 1
    request = route.calls.last.request
    expected_auth = base64.b64encode(b"pfsense_mcp_svc:synthetic-bootstrap-password").decode("ascii")
    assert request.headers["Authorization"] == f"Basic {expected_auth}"
    assert "X-API-Key" not in request.headers


def test_basic_auth_factory_failure_is_sanitized_and_leaves_explicit_partial_state():
    canary = "SYNTHETIC-CREDENTIAL-CANARY"
    admin = _FakeAdminTransport()

    def factory(username: str, password: str):
        raise TransportConfigurationError(canary)

    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=factory,
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=_SCHEMA,
        password_factory=lambda: "synthetic-bootstrap-password",
    )

    assert result.outcome is ProvisioningOutcome.FAILED
    assert result.transaction is not None
    assert "API-key creation transport failed" in (result.transaction.failure_detail or "")
    assert canary not in (result.transaction.failure_detail or "")
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]
    assert len([call for call in admin.calls if call[0] == "PATCH"]) == 1


@respx.mock
def test_basic_auth_timeout_is_one_attempt_and_never_auto_revoked_or_retried():
    route = respx.post("https://pfsense.example.invalid/api/v2/auth/key").mock(
        side_effect=httpx.ReadTimeout("SYNTHETIC-CREDENTIAL-CANARY")
    )
    admin = _FakeAdminTransport()

    def factory(username: str, password: str):
        return BasicAuthHttpTransport("https://pfsense.example.invalid", username, password, True)

    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=factory,
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.READ_ONLY,
        schema=_SCHEMA,
        password_factory=lambda: "synthetic-bootstrap-password",
    )

    assert result.outcome is ProvisioningOutcome.FAILED
    assert result.transaction is not None
    assert "API-key creation transport failed" in (result.transaction.failure_detail or "")
    assert "SYNTHETIC-CREDENTIAL-CANARY" not in (result.transaction.failure_detail or "")
    assert len(route.calls) == 1
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]
    assert len([call for call in admin.calls if call[0] == "PATCH"]) == 1


def test_fresh_account_completes_full_sequence_write_protected_profile():
    admin = _FakeAdminTransport()
    result = provision_service_account(
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        username="pfsense_mcp_svc",
        target_profile=TargetProfile.WRITE_PROTECTED,
        schema=_SCHEMA,
    )

    assert result.outcome is ProvisioningOutcome.COMPLETED
    assert result.transaction is not None
    assert len(result.transaction.privileges) == 84
    assert "api-v2-firewall-alias-patch" in result.transaction.privileges


# --- fresh account: failure at each named checkpoint ----------------------


def test_account_creation_failure():
    admin = _FakeAdminTransport()
    admin.fail_on["POST_user"] = 1

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert result.transaction is not None
    assert result.transaction.state is BootstrapState.FAILED
    assert "account creation" in (result.transaction.failure_detail or "")
    assert self_transport.calls == []
    assert [c for c in admin.calls if c[0] == "PATCH"] == []


def test_privilege_grant_failure():
    admin = _FakeAdminTransport()
    admin.fail_on["PATCH_user"] = 1  # the grant PATCH, first of two

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert result.transaction is not None
    assert "bootstrap-privilege grant failed" in (result.transaction.failure_detail or "")
    assert self_transport.calls == []


def test_api_key_creation_failure_reports_bootstrap_privilege_still_present():
    admin = _FakeAdminTransport()
    self_transport = _FakeSelfServiceTransport(status_code=500)

    result, self_transport = _provision(admin, self_transport=self_transport)

    assert result.outcome is ProvisioningOutcome.FAILED
    detail = result.transaction.failure_detail or ""
    assert "API-key creation failed" in detail
    assert BOOTSTRAP_ONLY_PRIVILEGE in detail
    # Only one PATCH happened (the grant) -- revoke was never attempted.
    assert len([c for c in admin.calls if c[0] == "PATCH"]) == 1
    # The account is left, un-mutated further, still holding the bootstrap privilege.
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]


def test_bootstrap_privilege_revocation_failure_reports_key_already_issued():
    admin = _FakeAdminTransport()
    admin.fail_on["PATCH_user"] = 2  # the revoke PATCH, second of two

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    detail = result.transaction.failure_detail or ""
    assert "bootstrap-privilege revocation failed" in detail
    assert BOOTSTRAP_ONLY_PRIVILEGE in detail
    assert "API key was already generated" in detail
    assert self_transport.calls == [("POST", _AUTH_KEY_PATH)]
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]


def test_final_verification_failure_after_revocation():
    admin = _FakeAdminTransport()
    # GET calls in order: pre-flight(1), post-create(2), post-grant(3), post-revoke(4).
    admin.fail_on["GET_users"] = 4

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    detail = result.transaction.failure_detail or ""
    assert "post-revocation verification failed" in detail


def test_post_creation_verification_mismatch_is_reported_as_failure():
    """Simulates the API accepting the POST but returning a
    subsequently-observed privilege set that does not match what was
    requested -- the read-back, not the POST's own echo, is what this
    engine trusts."""

    class _DriftingAdminTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            response = super().request(method, path, body=body)
            if method == "GET" and path == _USERS_PATH and self.users:
                # Tamper with the read-back only, not the underlying create.
                data = json.loads(response.text)["data"]
                for record in data:
                    record["priv"] = [*record["priv"], "unexpected-drifted-priv"]
                return TransportResponse(200, json.dumps({"data": data}))
            return response

    admin = _DriftingAdminTransport()
    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "post-creation verification failed" in (result.transaction.failure_detail or "")
    assert self_transport.calls == []


# --- existing account: already-satisfied / sync / blocked -----------------


def test_already_correct_existing_account_is_a_no_op():
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=_EXPECTED_READ_PRIVS)

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.ALREADY_SATISFIED
    assert result.drift_before is not None and result.drift_before.clean
    assert admin.calls == [("GET", _USERS_PATH)]
    assert self_transport.calls == []


def test_existing_account_missing_privileges_gets_synced_additively():
    admin = _FakeAdminTransport()
    partial = frozenset(list(_EXPECTED_READ_PRIVS)[:-1])  # missing exactly one
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=partial)

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.PRIVILEGES_SYNCED
    assert result.drift_before is not None and not result.drift_before.clean
    assert result.drift_after is not None and result.drift_after.clean
    assert set(admin.users[7]["priv"]) == _EXPECTED_READ_PRIVS
    assert self_transport.calls == []  # no key generated for a modify-only sync
    assert len([c for c in admin.calls if c[0] == "POST"]) == 0  # never re-created
    assert "exclusive administrative window" in result.detail


def test_existing_account_unrelated_additional_privilege_is_preserved_during_sync():
    admin = _FakeAdminTransport()
    partial = frozenset(list(_EXPECTED_READ_PRIVS)[:-1]) | {"some-unrelated-priv-get"}
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=partial)

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.PRIVILEGES_SYNCED
    assert "some-unrelated-priv-get" in admin.users[7]["priv"]
    assert set(admin.users[7]["priv"]) == _EXPECTED_READ_PRIVS | {"some-unrelated-priv-get"}


def test_privilege_sync_refreshes_stale_snapshot_and_preserves_newly_observed_extra():
    class _DriftBeforeFinalReadTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            if method == "GET" and path == _USERS_PATH and self._call_counts.get("GET_users", 0) == 1:
                self.users[7]["priv"].append("concurrently-observed-extra-get")
            return super().request(method, path, body=body)

    admin = _DriftBeforeFinalReadTransport()
    partial = frozenset(list(_EXPECTED_READ_PRIVS)[:-1])
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=partial)

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.PRIVILEGES_SYNCED
    assert "concurrently-observed-extra-get" in admin.users[7]["priv"]


def test_privilege_sync_fails_if_server_drops_final_pre_mutation_privilege():
    class _DropsPrivilegeAfterPatchTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            response = super().request(method, path, body=body)
            if method == "PATCH" and path == _USER_PATH:
                self.users[7]["priv"].remove("preexisting-extra-get")
            return response

    admin = _DropsPrivilegeAfterPatchTransport()
    partial = frozenset(list(_EXPECTED_READ_PRIVS)[:-1]) | {"preexisting-extra-get"}
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=partial)

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "final pre-mutation snapshot were removed" in result.detail


def test_privilege_sync_refuses_if_account_changes_identity_before_patch():
    class _IdentityDriftTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            if method == "GET" and path == _USERS_PATH and self._call_counts.get("GET_users", 0) == 1:
                self.users[7]["id"] = 8
            return super().request(method, path, body=body)

    admin = _IdentityDriftTransport()
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=frozenset(list(_EXPECTED_READ_PRIVS)[:-1]))

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "same enabled account" in result.detail
    assert not any(method == "PATCH" for method, _path in admin.calls)


def test_privilege_sync_refuses_disabled_existing_account_without_patch():
    admin = _FakeAdminTransport()
    admin.seed_user(
        user_id=7,
        name="pfsense_mcp_svc",
        priv=frozenset(list(_EXPECTED_READ_PRIVS)[:-1]),
        disabled=True,
    )

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "disabled" in result.detail
    assert admin.calls == [("GET", _USERS_PATH)]


def test_privilege_sync_refuses_same_name_without_project_description():
    admin = _FakeAdminTransport()
    admin.seed_user(
        user_id=7,
        name="pfsense_mcp_svc",
        priv=frozenset(list(_EXPECTED_READ_PRIVS)[:-1]),
        descr="Unrelated operator account",
    )

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "project-owned" in result.detail
    assert admin.calls == [("GET", _USERS_PATH)]


def test_privilege_sync_refuses_new_bootstrap_privilege_seen_at_final_read():
    class _BootstrapDriftTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            if method == "GET" and path == _USERS_PATH and self._call_counts.get("GET_users", 0) == 1:
                self.users[7]["priv"].append(BOOTSTRAP_ONLY_PRIVILEGE)
            return super().request(method, path, body=body)

    admin = _BootstrapDriftTransport()
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=frozenset(list(_EXPECTED_READ_PRIVS)[:-1]))

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.BLOCKED_EXISTING_PARTIAL
    assert not any(method == "PATCH" for method, _path in admin.calls)


def test_existing_account_with_only_unrelated_extra_privilege_is_left_untouched():
    admin = _FakeAdminTransport()
    extra = _EXPECTED_READ_PRIVS | {"some-unrelated-priv-get"}
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=extra)

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES
    assert admin.calls == [("GET", _USERS_PATH)]  # no mutation at all
    assert self_transport.calls == []


def test_existing_account_still_holding_bootstrap_privilege_is_blocked():
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=_EXPECTED_READ_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE})

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.BLOCKED_EXISTING_PARTIAL
    assert admin.calls == [("GET", _USERS_PATH)]
    assert self_transport.calls == []
    # No mutation performed -- the account's privileges are unchanged.
    assert set(admin.users[7]["priv"]) == _EXPECTED_READ_PRIVS | {BOOTSTRAP_ONLY_PRIVILEGE}


def test_privilege_sync_failure_is_reported():
    class _RejectingPatchAdminTransport(_FakeAdminTransport):
        pass

    admin = _RejectingPatchAdminTransport()
    partial = frozenset(list(_EXPECTED_READ_PRIVS)[:-1])
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=partial)
    admin.fail_on["PATCH_user"] = 1

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "privilege sync" in result.detail


# --- idempotency / re-entry -------------------------------------------


def test_re_running_after_a_successful_run_is_a_no_op_second_time():
    admin = _FakeAdminTransport()
    first, _self_transport_1 = _provision(admin)
    assert first.outcome is ProvisioningOutcome.COMPLETED

    calls_after_first_run = len(admin.calls)

    second, self_transport_2 = _provision(admin, self_transport=_FakeSelfServiceTransport())

    assert second.outcome is ProvisioningOutcome.ALREADY_SATISFIED
    assert self_transport_2.calls == []
    # Second run made exactly one call: the pre-flight GET.
    assert len(admin.calls) == calls_after_first_run + 1
    assert admin.calls[-1] == ("GET", _USERS_PATH)


# --- dedicated-account-only invariant -------------------------------------


def test_unrelated_existing_admin_account_is_never_touched():
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=0, name="admin", priv=frozenset({"page-all"}))

    result, _ = _provision(admin)

    assert result.outcome is ProvisioningOutcome.COMPLETED
    # The pre-existing admin account's privileges are byte-for-byte unchanged.
    assert admin.users[0]["priv"] == ["page-all"]


def test_ambiguous_username_match_fails_closed_instead_of_picking_one():
    """Handover self-review finding: two accounts sharing the target
    name must never be silently resolved to "the first one found" --
    that would risk provisioning or reporting on the wrong account.
    pfSense usernames are expected to be unique, so this can only
    reflect an untrustworthy read; the engine must refuse rather than
    guess."""

    admin = _FakeAdminTransport()
    admin.seed_user(user_id=7, name="pfsense_mcp_svc", priv=_EXPECTED_READ_PRIVS)
    admin.seed_user(user_id=8, name="pfsense_mcp_svc", priv=frozenset())

    result, self_transport = _provision(admin)

    assert result.outcome is ProvisioningOutcome.FAILED
    assert "ambiguous account state" in result.detail
    assert self_transport.calls == []
    # No mutation was attempted against either same-named account.
    assert [c for c in admin.calls if c[0] in ("POST", "PATCH")] == []
    assert admin.users[7]["priv"] == sorted(_EXPECTED_READ_PRIVS)
    assert admin.users[8]["priv"] == []
