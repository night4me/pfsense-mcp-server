"""Unit tests for security_recovery_confirmation.py -- pure, deterministic,
no transport/network/journal dependency."""

from __future__ import annotations

from pfsense_mcp.security_bootstrap_client import ObservedApiKey, ObservedUser
from pfsense_mcp.security_bootstrap_recovery import UnprovisionedIncidentEvidence
from pfsense_mcp.security_operation_journal import RecoveryAction
from pfsense_mcp.security_recovery_confirmation import (
    RecoveryIncidentBinding,
    confirmation_token_matches,
    derive_confirmation_token,
    object_fingerprint,
)

_KEY = b"k" * 32
_OTHER_KEY = b"j" * 32

_API_KEY = ObservedApiKey(
    id=7, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
)
_USER = ObservedUser(
    id=9,
    name="pfsense-mcp",
    descr="Dedicated service account",
    priv=frozenset({"a", "b"}),
    disabled=False,
    scope="user",
)


def _binding(**overrides: object) -> RecoveryIncidentBinding:
    defaults: dict[str, object] = {
        "target_origin": "https://pfsense.example",
        "target_identity": "admin",
        "recovery_action": RecoveryAction.REVOKE_ORPHAN_KEY,
        "object_fingerprint": object_fingerprint(_API_KEY),
        "incident_operation_id": "op-1",
        "incident_record_mac": "mac-1",
    }
    defaults.update(overrides)
    return RecoveryIncidentBinding(**defaults)  # type: ignore[arg-type]


def test_fingerprint_is_deterministic_and_order_independent_for_priv():
    a = ObservedUser(id=1, name="x", descr="d", priv=frozenset({"z", "a"}), disabled=False, scope="user")
    b = ObservedUser(id=1, name="x", descr="d", priv=frozenset({"a", "z"}), disabled=False, scope="user")
    assert object_fingerprint(a) == object_fingerprint(b)


def test_fingerprint_differs_on_any_field_change():
    base = object_fingerprint(_API_KEY)
    changed_id = object_fingerprint(
        ObservedApiKey(
            id=8,
            username="pfsense-mcp",
            descr="pfsense-mcp-server primary API key",
            hash_algo="sha256",
            length_bytes=32,
        )
    )
    changed_descr = object_fingerprint(
        ObservedApiKey(id=7, username="pfsense-mcp", descr="different", hash_algo="sha256", length_bytes=32)
    )
    assert base != changed_id
    assert base != changed_descr


def test_fingerprint_differs_between_key_and_user_kinds():
    # Same id, deliberately different object types -- must never collide.
    key = ObservedApiKey(id=1, username="x", descr="d", hash_algo="sha256", length_bytes=32)
    user = ObservedUser(id=1, name="x", descr="d", priv=frozenset(), disabled=False, scope="user")
    assert object_fingerprint(key) != object_fingerprint(user)


def test_fingerprint_is_deterministic_for_unprovisioned_incident_evidence():
    a = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp", account_confirmed_absent=True, no_owned_key_confirmed=True,
        users_checked=3, keys_checked=1,
    )
    b = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp", account_confirmed_absent=True, no_owned_key_confirmed=True,
        users_checked=3, keys_checked=1,
    )
    assert object_fingerprint(a) == object_fingerprint(b)


def test_fingerprint_for_unprovisioned_incident_evidence_differs_on_any_field_change():
    base = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp", account_confirmed_absent=True, no_owned_key_confirmed=True,
        users_checked=3, keys_checked=1,
    )
    changed_users_checked = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp", account_confirmed_absent=True, no_owned_key_confirmed=True,
        users_checked=4, keys_checked=1,
    )
    changed_username = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp-readonly", account_confirmed_absent=True, no_owned_key_confirmed=True,
        users_checked=3, keys_checked=1,
    )
    assert object_fingerprint(base) != object_fingerprint(changed_users_checked)
    assert object_fingerprint(base) != object_fingerprint(changed_username)


def test_fingerprint_differs_between_unprovisioned_incident_evidence_and_key_or_user_kinds():
    evidence = UnprovisionedIncidentEvidence(
        account_username="x",
        account_confirmed_absent=True,
        no_owned_key_confirmed=True,
        users_checked=1,
        keys_checked=1,
    )
    key = ObservedApiKey(id=1, username="x", descr="d", hash_algo="sha256", length_bytes=32)
    user = ObservedUser(id=1, name="x", descr="d", priv=frozenset(), disabled=False, scope="user")
    assert object_fingerprint(evidence) != object_fingerprint(key)
    assert object_fingerprint(evidence) != object_fingerprint(user)


def test_derive_is_deterministic():
    binding = _binding()
    assert derive_confirmation_token(binding, integrity_key=_KEY) == derive_confirmation_token(
        binding, integrity_key=_KEY
    )


def test_matches_the_token_it_derives():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert confirmation_token_matches(token, binding, integrity_key=_KEY)


def test_rejects_wrong_key():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token, binding, integrity_key=_OTHER_KEY)


def test_rejects_cross_target_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other_target = _binding(target_origin="https://other.example")
    assert not confirmation_token_matches(token, other_target, integrity_key=_KEY)


def test_rejects_cross_target_identity_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other = _binding(target_identity="someone-else")
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_action_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    other_action = _binding(
        recovery_action=RecoveryAction.DELETE_DEDICATED_USER, object_fingerprint=object_fingerprint(_USER)
    )
    assert not confirmation_token_matches(token, other_action, integrity_key=_KEY)


def test_rejects_cross_object_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    different_key = ObservedApiKey(
        id=999, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
    )
    other = _binding(object_fingerprint=object_fingerprint(different_key))
    assert not confirmation_token_matches(token, other, integrity_key=_KEY)


def test_rejects_cross_incident_token_same_object_and_action():
    # Same target/action/object, but a *different* originating incident
    # (a later, unrelated bootstrap failure that happens to name the same
    # orphan-key action) must not be authorized by an older token.
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    later_incident = _binding(incident_operation_id="op-2", incident_record_mac="mac-2")
    assert not confirmation_token_matches(token, later_incident, integrity_key=_KEY)


def test_rejects_cross_incident_token_same_operation_id_different_mac():
    # Belt-and-suspenders: even if operation_id somehow collided, the
    # incident record's own MAC must independently gate the token too.
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    tampered = _binding(incident_record_mac="mac-tampered")
    assert not confirmation_token_matches(token, tampered, integrity_key=_KEY)


def test_rejects_malformed_token_none():
    binding = _binding()
    assert not confirmation_token_matches(None, binding, integrity_key=_KEY)  # type: ignore[arg-type]


def test_rejects_malformed_token_empty_string():
    binding = _binding()
    assert not confirmation_token_matches("", binding, integrity_key=_KEY)


def test_rejects_malformed_token_wrong_type():
    binding = _binding()
    assert not confirmation_token_matches(12345, binding, integrity_key=_KEY)  # type: ignore[arg-type]


def test_rejects_truncated_token():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token[:-4], binding, integrity_key=_KEY)


def test_rejects_token_with_trailing_garbage():
    binding = _binding()
    token = derive_confirmation_token(binding, integrity_key=_KEY)
    assert not confirmation_token_matches(token + "00", binding, integrity_key=_KEY)


def test_rejects_non_ascii_candidate_without_crashing():
    """Regression: `hmac.compare_digest()` raises `TypeError` outright
    for a `str` candidate containing non-ASCII characters. `candidate`
    is untrusted operator input (an `--execute --confirm` value) and
    must never crash the comparison -- it must cleanly return `False`."""

    binding = _binding()
    assert not confirmation_token_matches("emoji😀not-a-real-token", binding, integrity_key=_KEY)


def test_rejects_candidate_with_invalid_utf8_surrogate_without_crashing():
    """Regression: argv on POSIX is decoded with `surrogateescape`, so
    a `--confirm` value containing an invalid byte sequence can reach
    this function as a `str` with a lone surrogate. Must not crash."""

    binding = _binding()
    assert not confirmation_token_matches("bad\udcffbyte", binding, integrity_key=_KEY)
