"""Offline adversarial tests for the two closed ADR-033 recovery actions."""

from __future__ import annotations

import json
from collections import defaultdict, deque
from pathlib import Path

import pytest

from pfsense_mcp.errors import BootstrapProvisioningError
from pfsense_mcp.security_bootstrap_recovery import (
    RECOVERY_KEY_DESCRIPTION,
    RECOVERY_USER_DESCRIPTION,
    RECOVERY_USERNAME,
    delete_dedicated_recovery_user,
    identify_dedicated_recovery_user_candidate,
    identify_orphan_api_key_candidate,
    revoke_failed_bootstrap_api_key,
)
from pfsense_mcp.security_privileges import (
    distinct_ok_privileges,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)
from pfsense_mcp.transport.base import TransportResponse

_FIXTURE = Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
_USERS = "/api/v2/users"
_USER = "/api/v2/user"
_KEYS = "/api/v2/auth/keys?limit=100"
_KEY = "/api/v2/auth/key"


class SequenceTransport:
    def __init__(self) -> None:
        self.responses: dict[tuple[str, str], deque[TransportResponse]] = defaultdict(deque)
        self.calls: list[tuple[str, str]] = []
        self.bodies: list[bytes | None] = []

    def register(self, method: str, path: str, *bodies: dict[str, object], status: int = 200) -> None:
        for body in bodies:
            self.responses[(method, path)].append(TransportResponse(status, json.dumps(body)))

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        self.bodies.append(body)
        queue = self.responses[(method, path)]
        if not queue:
            raise AssertionError(f"unexpected or repeated request: {method} {path}")
        return queue.popleft()


def _schema() -> dict[str, object]:
    return json.loads(_FIXTURE.read_text(encoding="utf-8"))


def _target() -> frozenset[str]:
    return distinct_ok_privileges(resolve_profile_privileges(_schema(), write_protected_profile_requirements()))


def _key(key_id: int = 7, *, username: str | None = RECOVERY_USERNAME, descr: str = RECOVERY_KEY_DESCRIPTION):
    return {
        "id": key_id,
        "username": username,
        "descr": descr,
        "hash_algo": "sha256",
        "length_bytes": 32,
    }


def _user(
    user_id: int = 9,
    *,
    name: str = RECOVERY_USERNAME,
    descr: str = RECOVERY_USER_DESCRIPTION,
    priv: frozenset[str] | None = None,
    disabled: bool = False,
    scope: str = "user",
):
    return {
        "id": user_id,
        "name": name,
        "descr": descr,
        "priv": sorted(_target() if priv is None else priv),
        "disabled": disabled,
        "scope": scope,
    }


def _data_list(*items: dict[str, object]) -> dict[str, object]:
    return {"data": list(items)}


def _deleted(item: dict[str, object]) -> dict[str, object]:
    return {"data": item}


def test_revoke_exact_orphan_key_once_and_preserve_unrelated_key():
    transport = SequenceTransport()
    mutation = SequenceTransport()
    selected = _key()
    unrelated = _key(3, username="other-service", descr="unrelated")
    transport.register(
        "GET", _KEYS, _data_list(unrelated, selected), _data_list(unrelated, selected), _data_list(unrelated)
    )
    mutation.register("DELETE", _KEY, _deleted(selected))

    evidence = revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=mutation)

    assert evidence.verified_absent and evidence.unrelated_objects_preserved
    assert transport.calls == [("GET", _KEYS), ("GET", _KEYS), ("GET", _KEYS)]
    assert mutation.calls == [("DELETE", _KEY)]
    assert json.loads(mutation.bodies[0]) == {"id": 7}


@pytest.mark.parametrize("matches", [(), (_key(), _key(8))])
def test_revoke_refuses_zero_or_ambiguous_match_without_delete(matches):
    transport = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(*matches))

    with pytest.raises(BootstrapProvisioningError, match="exactly one"):
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=SequenceTransport())

    assert transport.calls == [("GET", _KEYS)]


def test_revoke_refuses_changed_stable_identity_before_delete():
    transport = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(_key()), _data_list(_key(8)))

    with pytest.raises(BootstrapProvisioningError, match="identity changed"):
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=SequenceTransport())

    assert all(method == "GET" for method, _ in transport.calls)


def test_revoke_postcondition_failure_does_not_retry_delete():
    transport = SequenceTransport()
    mutation = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(_key()), _data_list(_key()), _data_list(_key()))
    mutation.register("DELETE", _KEY, _deleted(_key()))

    with pytest.raises(BootstrapProvisioningError, match="remains present"):
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=mutation)

    assert mutation.calls == [("DELETE", _KEY)]


def test_revoke_http_failure_is_sanitized_and_never_retried():
    canary = "SECRET-CANARY"
    transport = SequenceTransport()
    mutation = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(_key()), _data_list(_key()))
    mutation.register("DELETE", _KEY, {"data": {"secret": canary}}, status=500)

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=mutation)

    assert canary not in str(excinfo.value)
    assert mutation.calls == [("DELETE", _KEY)]


def test_list_key_malformed_or_secret_bearing_data_fails_closed_without_retaining_secret():
    transport = SequenceTransport()
    malformed = _key()
    malformed["id"] = "7"
    malformed["key"] = "SECRET-CANARY"
    transport.register("GET", _KEYS, _data_list(malformed))

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=SequenceTransport())

    assert "SECRET-CANARY" not in str(excinfo.value)
    assert all(method == "GET" for method, _ in transport.calls)


def test_initial_key_read_http_failure_is_sanitized_without_delete():
    transport = SequenceTransport()
    transport.register("GET", _KEYS, {"data": {"secret": "SECRET-CANARY"}}, status=503)

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=SequenceTransport())

    assert "SECRET-CANARY" not in str(excinfo.value)
    assert transport.calls == [("GET", _KEYS)]


def _register_successful_user_deletion(transport: SequenceTransport, *, unrelated: dict[str, object] | None = None):
    selected = _user()
    before = [selected] if unrelated is None else [unrelated, selected]
    after = [] if unrelated is None else [unrelated]
    transport.register("GET", _USERS, _data_list(*before), _data_list(*before), _data_list(*after))
    transport.register("GET", _KEYS, _data_list(), _data_list(), _data_list())
    transport.register("DELETE", _USER, _deleted(selected))
    return selected


def test_delete_exact_dedicated_user_once_and_preserve_unrelated_user():
    transport = SequenceTransport()
    selected = _register_successful_user_deletion(transport, unrelated=_user(2, name="human", descr="Human"))

    evidence = delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert evidence.verified_absent and evidence.unrelated_objects_preserved
    assert json.loads(transport.bodies[4]) == {"id": selected["id"]}
    assert [call for call in transport.calls if call[0] == "DELETE"] == [("DELETE", _USER)]


@pytest.mark.parametrize("users", [(), (_user(), _user(10))])
def test_delete_user_refuses_zero_or_duplicate_name_without_delete(users):
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(*users))

    with pytest.raises(BootstrapProvisioningError, match="exactly one"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert transport.calls == [("GET", _USERS)]


@pytest.mark.parametrize(
    "user",
    [
        _user(descr="Human account"),
        _user(priv=frozenset({"page-all"})),
        _user(disabled=True),
        _user(scope="system"),
    ],
)
def test_delete_user_refuses_wrong_description_profile_or_enabled_state(user):
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(user))

    with pytest.raises(BootstrapProvisioningError, match="identity or least-privilege"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert all(method == "GET" for method, _ in transport.calls)


def test_delete_user_refuses_any_remaining_owned_key():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(_key(descr="another key")))

    with pytest.raises(BootstrapProvisioningError, match="still owns"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert all(method == "GET" for method, _ in transport.calls)


def test_delete_user_refuses_unknown_key_ownership():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(_key(username=None, descr="unknown owner")))

    with pytest.raises(BootstrapProvisioningError, match="ownership was unavailable"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert all(method == "GET" for method, _ in transport.calls)


def test_delete_user_refuses_id_reuse_or_stale_identity_before_delete():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()), _data_list(_user(user_id=10)))
    transport.register("GET", _KEYS, _data_list())

    with pytest.raises(BootstrapProvisioningError, match="identity changed"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert all(method == "GET" for method, _ in transport.calls)


def test_delete_user_postcondition_failure_never_retries():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()), _data_list(_user()), _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(), _data_list())
    transport.register("DELETE", _USER, _deleted(_user()))

    with pytest.raises(BootstrapProvisioningError, match="remains present"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert [call for call in transport.calls if call[0] == "DELETE"] == [("DELETE", _USER)]


def test_delete_user_http_failure_is_sanitized_and_never_retried():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()), _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(), _data_list())
    transport.register("DELETE", _USER, {"data": {"secret": "SECRET-CANARY"}}, status=500)

    with pytest.raises(BootstrapProvisioningError) as excinfo:
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert "SECRET-CANARY" not in str(excinfo.value)
    assert [call for call in transport.calls if call[0] == "DELETE"] == [("DELETE", _USER)]


def test_delete_user_verification_read_failure_never_retries():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()), _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(), _data_list())
    transport.register("DELETE", _USER, _deleted(_user()))
    transport.register("GET", _USERS, {"data": []}, status=500)

    with pytest.raises(BootstrapProvisioningError):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert [call for call in transport.calls if call[0] == "DELETE"] == [("DELETE", _USER)]


def test_delete_user_rejects_malformed_authoritative_collection_before_delete():
    transport = SequenceTransport()
    transport.register("GET", _USERS, {"data": [_user(), "malformed"]})

    with pytest.raises(BootstrapProvisioningError, match="non-object"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert transport.calls == [("GET", _USERS)]


def test_duplicate_stable_ids_fail_closed_before_delete():
    transport = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(_key(), _key()))

    with pytest.raises(BootstrapProvisioningError, match="duplicate object IDs"):
        revoke_failed_bootstrap_api_key(admin_transport=transport, key_revocation_transport=SequenceTransport())

    assert all(method == "GET" for method, _ in transport.calls)


def test_delete_user_refuses_unrelated_user_change_after_delete():
    transport = SequenceTransport()
    unrelated = _user(2, name="human", descr="Human")
    changed = _user(2, name="human", descr="Changed")
    transport.register(
        "GET", _USERS, _data_list(unrelated, _user()), _data_list(unrelated, _user()), _data_list(changed)
    )
    transport.register("GET", _KEYS, _data_list(), _data_list())
    transport.register("DELETE", _USER, _deleted(_user()))

    with pytest.raises(BootstrapProvisioningError, match="unrelated account"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())


def test_delete_user_refuses_unrelated_key_change_after_delete():
    transport = SequenceTransport()
    unrelated = _key(3, username="other-service", descr="unrelated")
    changed = _key(3, username="other-service", descr="changed")
    transport.register("GET", _USERS, _data_list(_user()), _data_list(_user()), _data_list())
    transport.register("GET", _KEYS, _data_list(unrelated), _data_list(unrelated), _data_list(changed))
    transport.register("DELETE", _USER, _deleted(_user()))

    with pytest.raises(BootstrapProvisioningError, match="unrelated key"):
        delete_dedicated_recovery_user(admin_transport=transport, schema=_schema())

    assert [call for call in transport.calls if call[0] == "DELETE"] == [("DELETE", _USER)]


def test_delete_user_malformed_schema_fails_before_network():
    transport = SequenceTransport()
    with pytest.raises(BootstrapProvisioningError, match="source-cross-checked"):
        delete_dedicated_recovery_user(admin_transport=transport, schema={})
    assert transport.calls == []


def test_identify_orphan_api_key_candidate_matches_revoke_selection_and_never_mutates():
    transport = SequenceTransport()
    unrelated = _key(3, username="other-service", descr="unrelated")
    selected = _key()
    transport.register("GET", _KEYS, _data_list(unrelated, selected))

    candidate = identify_orphan_api_key_candidate(admin_transport=transport)

    assert candidate.id == selected["id"]
    assert transport.calls == [("GET", _KEYS)]


def test_identify_orphan_api_key_candidate_refuses_zero_or_ambiguous_match():
    transport = SequenceTransport()
    transport.register("GET", _KEYS, _data_list(_key(), _key(8)))

    with pytest.raises(BootstrapProvisioningError, match="exactly one"):
        identify_orphan_api_key_candidate(admin_transport=transport)


def test_identify_dedicated_recovery_user_candidate_matches_delete_selection_and_never_mutates():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()))
    transport.register("GET", _KEYS, _data_list())

    candidate = identify_dedicated_recovery_user_candidate(admin_transport=transport, schema=_schema())

    assert candidate.id == _user()["id"]
    assert transport.calls == [("GET", _USERS), ("GET", _KEYS)]


def test_identify_dedicated_recovery_user_candidate_refuses_when_key_still_owned():
    transport = SequenceTransport()
    transport.register("GET", _USERS, _data_list(_user()))
    transport.register("GET", _KEYS, _data_list(_key()))

    with pytest.raises(BootstrapProvisioningError, match="still owns"):
        identify_dedicated_recovery_user_candidate(admin_transport=transport, schema=_schema())


def test_identify_dedicated_recovery_user_candidate_malformed_schema_fails_before_network():
    transport = SequenceTransport()
    with pytest.raises(BootstrapProvisioningError, match="source-cross-checked"):
        identify_dedicated_recovery_user_candidate(admin_transport=transport, schema={})
    assert transport.calls == []
