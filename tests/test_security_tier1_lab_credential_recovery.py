"""Tests for `pfsense_mcp.security_tier1_lab_credential_recovery` --
the narrow, statically-bound Tier1 LAB credential recovery ceremony.
Exercised entirely against deterministic, in-memory fake transports
(`_FakeAdminTransport`/`_FakeSelfServiceTransport` below, mirroring
`tests/test_security_bootstrap_engine.py`'s own established pattern),
never a real pfSense appliance. Zero live LAB contact anywhere in this
file.
"""

from __future__ import annotations

import json
import stat

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.security_bootstrap_transaction import BOOTSTRAP_ONLY_PRIVILEGE, BootstrapState
from pfsense_mcp.security_tier1_lab_credential_recovery import (
    EXPECTED_STARTING_PRIVILEGES,
    EXPECTED_USER_DESCR,
    EXPECTED_USERNAME,
    FINAL_PRIVILEGES,
    TARGET_LABEL,
    TEMPORARY_PRIVILEGES,
    RecoveryOutcome,
    recover_tier1_lab_credential,
)
from pfsense_mcp.transport.base import TransportResponse

_USERS_PATH = "/api/v2/users"
_USER_PATH = "/api/v2/user"
_AUTH_KEY_PATH = "/api/v2/auth/key"

_SENTINEL_PASSWORD = "correct-horse-battery-staple-SENTINEL-DO-NOT-LEAK"
_SENTINEL_KEY = "TOP-SECRET-MINTED-KEY-DO-NOT-LEAK"


class _FakeAdminTransport:
    """Models GET/PATCH on the `/user(s)` resource -- enough to drive
    the recovery ceremony through every checkpoint, including
    mid-sequence failures at each named step. `fail_on` maps an
    operation key ("GET_users" | "PATCH_user") to a 1-indexed call
    ordinal (scoped to that key) that should return a synthetic error
    instead of succeeding. `corrupt_patch_ordinal`, if set, makes that
    PATCH_user call succeed at the HTTP layer but silently apply a
    *different* privilege set than requested -- simulating a server
    that lies, distinct from a hard HTTP failure."""

    def __init__(self) -> None:
        self.users: dict[int, dict] = {}
        self.calls: list[tuple[str, str]] = []
        self.request_bodies: list[bytes | None] = []
        self._call_counts: dict[str, int] = {}
        self.fail_on: dict[str, int] = {}
        self.corrupt_patch_ordinal: int | None = None

    def seed_user(
        self, *, user_id: int, name: str, priv: frozenset[str], disabled: bool = False, descr: str = EXPECTED_USER_DESCR
    ) -> None:
        self.users[user_id] = {
            "id": user_id,
            "name": name,
            "descr": descr,
            "priv": sorted(priv),
            "disabled": disabled,
        }

    def _maybe_fail(self, key: str) -> TransportResponse | None:
        self._call_counts[key] = self._call_counts.get(key, 0) + 1
        if self.fail_on.get(key) == self._call_counts[key]:
            return TransportResponse(500, json.dumps({"message": "synthetic failure"}))
        return None

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        self.request_bodies.append(body)

        if method == "GET" and path == _USERS_PATH:
            failure = self._maybe_fail("GET_users")
            if failure is not None:
                return failure
            return TransportResponse(200, json.dumps({"data": list(self.users.values())}))

        if method == "PATCH" and path == _USER_PATH:
            ordinal = self._call_counts.get("PATCH_user", 0) + 1
            failure = self._maybe_fail("PATCH_user")
            if failure is not None:
                return failure
            payload = json.loads(body)
            record = self.users[payload["id"]]
            if "priv" in payload:
                if self.corrupt_patch_ordinal == ordinal:
                    record["priv"] = ["some-other-unexpected-privilege"]
                else:
                    record["priv"] = payload["priv"]
            # "password" field: accepted, never persisted/echoed -- this
            # fake models pfSense's own behavior of never returning the
            # password in any response body.
            return TransportResponse(200, json.dumps({"data": record}))

        raise AssertionError(f"_FakeAdminTransport received an unexpected call: {method} {path}")


class _FakeSelfServiceTransport:
    def __init__(self, *, status_code: int = 200, key_value: str = _SENTINEL_KEY) -> None:
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
                        "username": EXPECTED_USERNAME,
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
        assert username == EXPECTED_USERNAME
        assert password == _SENTINEL_PASSWORD
        return self_transport

    return _build


def _seed_valid_starting_user(admin: _FakeAdminTransport) -> None:
    admin.seed_user(user_id=1, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES)


def _recover(admin, tmp_path, *, self_transport=None, target_label=TARGET_LABEL, output_name="new-key"):
    self_transport = self_transport or _FakeSelfServiceTransport()
    return recover_tier1_lab_credential(
        target_label=target_label,
        admin_transport=admin,
        self_service_transport_factory=_factory(self_transport),
        api_version=ApiVersion.V2,
        new_key_output_path=tmp_path / output_name,
        password_factory=lambda: _SENTINEL_PASSWORD,
    )


# --- Happy path -------------------------------------------------------------


def test_full_ceremony_succeeds_and_writes_the_new_key_file(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.COMPLETED
    assert result.transaction is not None
    assert result.transaction.state is BootstrapState.VERIFIED
    assert result.transaction.privileges == FINAL_PRIVILEGES
    assert admin.users[1]["priv"] == sorted(FINAL_PRIVILEGES)
    assert result.api_key is not None
    assert result.api_key.reveal() == _SENTINEL_KEY

    key_path = tmp_path / "new-key"
    assert key_path.read_text(encoding="utf-8") == _SENTINEL_KEY
    mode = stat.S_IMODE(key_path.stat().st_mode)
    assert mode == 0o600


def test_ceremony_call_sequence_is_exactly_as_designed(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    self_transport = _FakeSelfServiceTransport()

    _recover(admin, tmp_path, self_transport=self_transport)

    assert admin.calls == [
        ("GET", _USERS_PATH),  # A: pre-flight observation
        ("PATCH", _USER_PATH),  # B: password reset
        ("PATCH", _USER_PATH),  # C: temporary bootstrap-privilege grant
        ("GET", _USERS_PATH),  # post-grant reread
        ("PATCH", _USER_PATH),  # G: final privilege set
        ("GET", _USERS_PATH),  # H: post-finalization reread
    ]
    assert self_transport.calls == [("POST", _AUTH_KEY_PATH)]


# --- A: exact pre-state refusal ---------------------------------------------


def test_refuses_when_account_does_not_exist(tmp_path):
    admin = _FakeAdminTransport()
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "does not exist" in result.detail
    assert admin.calls == [("GET", _USERS_PATH)]


def test_refuses_on_user_id_mismatch(tmp_path):
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=999, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES)
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "user id mismatch" in result.detail


def test_refuses_on_description_mismatch(tmp_path):
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=1, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES, descr="wrong descr")
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "description mismatch" in result.detail


def test_refuses_when_account_is_disabled(tmp_path):
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=1, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES, disabled=True)
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "disabled" in result.detail


@pytest.mark.parametrize(
    "priv",
    [
        frozenset(),
        EXPECTED_STARTING_PRIVILEGES - {"api-v2-status-system-get"},
        EXPECTED_STARTING_PRIVILEGES | {"page-all"},
        EXPECTED_STARTING_PRIVILEGES | {BOOTSTRAP_ONLY_PRIVILEGE},
    ],
    ids=["empty", "missing-one", "extra-one", "already-has-bootstrap-priv"],
)
def test_refuses_on_starting_privilege_set_mismatch(tmp_path, priv):
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=1, name=EXPECTED_USERNAME, priv=priv)
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "starting privilege set mismatch" in result.detail
    # Fail-closed: no mutation is ever attempted once pre-state disagrees.
    assert all(method == "GET" for method, _ in admin.calls)


def test_ambiguous_account_state_is_reported_as_failed_not_silently_resolved(tmp_path):
    admin = _FakeAdminTransport()
    admin.seed_user(user_id=1, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES)
    admin.seed_user(user_id=2, name=EXPECTED_USERNAME, priv=EXPECTED_STARTING_PRIVILEGES)
    result = _recover(admin, tmp_path)
    assert result.outcome is RecoveryOutcome.FAILED
    assert "ambiguous" in result.detail


# --- Target-identity refusal -------------------------------------------------


def test_refuses_on_wrong_target_label_before_any_network_call(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    result = _recover(admin, tmp_path, target_label="pfsense_production")
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "target_label mismatch" in result.detail
    assert admin.calls == []


# --- No-overwrite behavior ---------------------------------------------------


def test_refuses_to_write_to_the_forbidden_stale_filename_before_any_network_call(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    result = _recover(admin, tmp_path, output_name="api-key-scoped-tier1")
    assert result.outcome is RecoveryOutcome.PRESTATE_MISMATCH
    assert "api-key-scoped-tier1" in result.detail
    assert admin.calls == []


def test_never_overwrites_an_existing_file_at_the_new_key_output_path(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    collision_path = tmp_path / "already-exists"
    collision_path.write_text("PRE-EXISTING-CONTENT", encoding="utf-8")

    result = recover_tier1_lab_credential(
        target_label=TARGET_LABEL,
        admin_transport=admin,
        self_service_transport_factory=_factory(_FakeSelfServiceTransport()),
        api_version=ApiVersion.V2,
        new_key_output_path=collision_path,
        password_factory=lambda: _SENTINEL_PASSWORD,
    )

    assert result.outcome is RecoveryOutcome.FAILED
    assert collision_path.read_text(encoding="utf-8") == "PRE-EXISTING-CONTENT"
    # A usable key was minted but not written -- bootstrap privilege and
    # transient password are left behind, precisely reported, never
    # silently rolled back.
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]
    assert result.transaction is not None
    assert result.transaction.state is BootstrapState.FAILED
    assert "not written to any file" in result.detail


# --- Temporary-privilege-left-behind / never-auto-compensate reporting -----


def test_password_reset_failure_leaves_no_privilege_change_and_reports_precisely(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["PATCH_user"] = 1  # the password-reset PATCH itself

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "password reset failed" in result.detail
    assert admin.users[1]["priv"] == sorted(EXPECTED_STARTING_PRIVILEGES)
    assert BOOTSTRAP_ONLY_PRIVILEGE not in admin.users[1]["priv"]


def test_temporary_privilege_grant_failure_reports_the_password_was_already_reset(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["PATCH_user"] = 2  # the temporary-privilege-grant PATCH

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "bootstrap-privilege grant failed" in result.detail
    assert "password was already reset" in result.detail
    assert BOOTSTRAP_ONLY_PRIVILEGE not in admin.users[1]["priv"]


def test_post_grant_verification_failure_is_reported_never_assumed_clean(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["GET_users"] = 2  # the reread immediately after the grant

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "post-grant verification failed" in result.detail
    # The grant itself DID succeed server-side -- this is exactly the
    # "cannot independently verify clean" case the mission requires be
    # reported, not silently treated as safe.
    assert admin.users[1]["priv"] == sorted(TEMPORARY_PRIVILEGES)


def test_key_creation_failure_reports_bootstrap_privilege_left_behind(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    self_transport = _FakeSelfServiceTransport(status_code=403)

    result = _recover(admin, tmp_path, self_transport=self_transport)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "API-key creation failed" in result.detail
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]
    assert result.transaction is not None
    assert result.transaction.state is BootstrapState.FAILED
    assert not (tmp_path / "new-key").exists()


def test_final_privilege_application_failure_reports_bootstrap_privilege_left_behind(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["PATCH_user"] = 3  # the final-privilege-set PATCH

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "final-privilege-set application failed" in result.detail
    assert BOOTSTRAP_ONLY_PRIVILEGE in admin.users[1]["priv"]
    # The key WAS already minted and written -- report says so rather
    # than implying total failure.
    assert (tmp_path / "new-key").read_text(encoding="utf-8") == _SENTINEL_KEY


def test_post_finalization_read_failure_treats_bootstrap_privilege_as_still_present(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["GET_users"] = 3  # the final reread

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "post-finalization verification failed" in result.detail
    assert "treat the temporary privilege as still present" in result.detail


def test_final_privilege_set_negative_verification_when_server_silently_applies_a_different_set(tmp_path):
    """The PATCH itself succeeds (HTTP 200) but the server-side result
    does not actually equal the requested final set -- proves the
    independent re-read, not the mutating call's own echo, is what
    decides success."""

    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.corrupt_patch_ordinal = 3  # the final-privilege-set PATCH

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.FAILED
    assert "post-finalization verification failed" in result.detail


# --- Secret redaction ---------------------------------------------------


def test_transient_password_never_appears_in_any_failure_detail_or_repr(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["PATCH_user"] = 2  # fail after the password was already set

    result = _recover(admin, tmp_path)

    assert _SENTINEL_PASSWORD not in result.detail
    assert _SENTINEL_PASSWORD not in repr(result)
    assert result.transaction is not None
    assert _SENTINEL_PASSWORD not in repr(result.transaction)
    assert _SENTINEL_PASSWORD not in (result.transaction.failure_detail or "")


def test_minted_key_never_appears_in_any_failure_detail_or_repr_after_final_patch_failure(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)
    admin.fail_on["PATCH_user"] = 3

    result = _recover(admin, tmp_path)

    assert _SENTINEL_KEY not in result.detail
    assert _SENTINEL_KEY not in repr(result)
    # Only a COMPLETED result carries `api_key` forward -- a FAILED
    # result never re-exposes a secret that was already durably written
    # to disk by an earlier step.
    assert result.api_key is None
    assert (tmp_path / "new-key").read_text(encoding="utf-8") == _SENTINEL_KEY


def test_successful_result_repr_does_not_leak_the_minted_key(tmp_path):
    admin = _FakeAdminTransport()
    _seed_valid_starting_user(admin)

    result = _recover(admin, tmp_path)

    assert result.outcome is RecoveryOutcome.COMPLETED
    assert _SENTINEL_KEY not in repr(result)
    assert result.api_key is not None
    assert result.api_key.reveal() == _SENTINEL_KEY
