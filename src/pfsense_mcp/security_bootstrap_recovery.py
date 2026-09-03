"""Closed, owner-directed ADR-033 recovery for one dedicated account.

This module is deliberately narrower than the bootstrap engine.  It exposes
exactly two independent actions: revoke the one unambiguously identified
orphan key from the failed LAB ceremony, and delete the one fixed disposable
service account after proving no key remains.  Neither action chains into the
other, retries, provisions, or invokes the bootstrap engine.

The pfSense v2 API identifies both REST API keys and users by mutable-list
integer IDs and offers no revision/CAS token.  Each action therefore performs
two authoritative reads before its one DELETE, requires the selected object's
complete non-secret identity to remain unchanged, and compares the complete
post-read collection against the final pre-delete collection minus that exact
object.  An exclusive administrative window remains required to cover the
unavoidable final-read-to-DELETE interval.

Nothing imports this module from CLI, application, MCP tools, or normal runtime.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .security_bootstrap_client import BootstrapProvisioningClient, ObservedApiKey, ObservedUser
from .security_privileges import (
    EvidenceClass,
    distinct_ok_privileges,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)
from .transport.base import Transport

RECOVERY_USERNAME = "pfsense-mcp"
RECOVERY_USER_DESCRIPTION = "Dedicated service account for pfsense-mcp-server"
RECOVERY_KEY_DESCRIPTION = "pfsense-mcp-server primary API key"

_ObservedObject = TypeVar("_ObservedObject", ObservedApiKey, ObservedUser)


@dataclass(frozen=True)
class RecoveryDeletionEvidence:
    """Sanitized proof of one verified deletion; contains no credential."""

    object_kind: str
    selected_id: int
    objects_before: int
    objects_after: int
    verified_absent: bool
    unrelated_objects_preserved: bool


@dataclass(frozen=True)
class UnprovisionedIncidentEvidence:
    """Sanitized proof that the fixed dedicated account was never created
    and owns no orphan key, as of two independent, freshly-taken reads.
    Contains no credential. `RECOVER_UNPROVISIONED_INCIDENT`'s own
    read-only counterpart to `RecoveryDeletionEvidence` -- proves an
    absence rather than a verified deletion."""

    account_username: str
    account_confirmed_absent: bool
    no_owned_key_confirmed: bool
    users_checked: int
    keys_checked: int


def _derive_exact_target(schema: dict[str, object]) -> frozenset[str]:
    resolved = resolve_profile_privileges(schema, write_protected_profile_requirements())
    if not resolved or any(
        not item.ok or item.evidence_class is not EvidenceClass.SOURCE_CROSS_CHECKED for item in resolved
    ):
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: target privilege derivation was not fully source-cross-checked."
        )
    target = distinct_ok_privileges(resolved)
    if not target:
        raise BootstrapProvisioningError("delete_dedicated_recovery_user: target privilege set was empty.")
    return target


def _matching_recovery_keys(keys: tuple[ObservedApiKey, ...]) -> tuple[ObservedApiKey, ...]:
    return tuple(key for key in keys if key.username == RECOVERY_USERNAME and key.descr == RECOVERY_KEY_DESCRIPTION)


def _matching_recovery_users(users: tuple[ObservedUser, ...]) -> tuple[ObservedUser, ...]:
    return tuple(user for user in users if user.name == RECOVERY_USERNAME)


def _by_unique_id(objects: tuple[_ObservedObject, ...], *, operation: str) -> dict[int, _ObservedObject]:
    mapped = {item.id: item for item in objects}
    if len(mapped) != len(objects):
        raise BootstrapProvisioningError(f"{operation}: authoritative response contained duplicate object IDs.")
    return mapped


def _select_orphan_api_key(keys: tuple[ObservedApiKey, ...], *, operation: str) -> ObservedApiKey:
    _by_unique_id(keys, operation=operation)
    matches = _matching_recovery_keys(keys)
    if len(matches) != 1:
        raise BootstrapProvisioningError(
            f"{operation}: expected exactly one matching orphan key; no mutation performed."
        )
    return matches[0]


def _select_dedicated_recovery_user(
    users: tuple[ObservedUser, ...], *, expected_privileges: frozenset[str], operation: str
) -> ObservedUser:
    _by_unique_id(users, operation=operation)
    matches = _matching_recovery_users(users)
    if len(matches) != 1:
        raise BootstrapProvisioningError(f"{operation}: expected exactly one matching account; no mutation performed.")
    selected = matches[0]
    if (
        selected.descr != RECOVERY_USER_DESCRIPTION
        or selected.disabled
        or selected.scope != "user"
        or selected.priv != expected_privileges
        or "page-all" in selected.priv
    ):
        raise BootstrapProvisioningError(
            f"{operation}: account identity or least-privilege profile mismatch; no mutation performed."
        )
    return selected


def _check_no_owned_key(keys: tuple[ObservedApiKey, ...], *, operation: str) -> None:
    _by_unique_id(keys, operation=operation)
    if any(key.username is None for key in keys):
        raise BootstrapProvisioningError(f"{operation}: API-key ownership was unavailable; no mutation performed.")
    if any(key.username == RECOVERY_USERNAME for key in keys):
        raise BootstrapProvisioningError(
            f"{operation}: account still owns one or more API keys; no mutation performed."
        )


def _check_account_absent(users: tuple[ObservedUser, ...], *, operation: str) -> None:
    _by_unique_id(users, operation=operation)
    if _matching_recovery_users(users):
        raise BootstrapProvisioningError(f"{operation}: the fixed dedicated account exists; no resolution performed.")


def identify_orphan_api_key_candidate(
    *, admin_transport: Transport, api_version: ApiVersion = ApiVersion.V2
) -> ObservedApiKey:
    """Read-only: identify the exact orphan key `revoke_failed_bootstrap_api_key()`
    would select, without mutating anything -- shares `_select_orphan_api_key()`
    with that function's own first-read step, so there is exactly one
    implementation of "what counts as the orphan key", never duplicated.
    Raises `BootstrapProvisioningError` under precisely the same condition
    that function's first read would refuse to proceed under. Never makes
    a mutating call."""

    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    keys = client._list_auth_keys_for_recovery()
    return _select_orphan_api_key(keys, operation="identify_orphan_api_key_candidate")


def identify_dedicated_recovery_user_candidate(
    *, admin_transport: Transport, schema: dict[str, object], api_version: ApiVersion = ApiVersion.V2
) -> ObservedUser:
    """Read-only: identify the exact account `delete_dedicated_recovery_user()`
    would select, including the same "does it still own a key" precondition
    that function's own first-read phase checks -- shared, not duplicated.
    Never makes a mutating call."""

    expected_privileges = _derive_exact_target(schema)
    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    users = client.list_users()
    selected = _select_dedicated_recovery_user(
        users, expected_privileges=expected_privileges, operation="identify_dedicated_recovery_user_candidate"
    )
    keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(keys, operation="identify_dedicated_recovery_user_candidate")
    return selected


def revoke_failed_bootstrap_api_key(
    *,
    admin_transport: Transport,
    key_revocation_transport: Transport,
    api_version: ApiVersion = ApiVersion.V2,
) -> RecoveryDeletionEvidence:
    """Revoke exactly one fixed-identity orphan key, once, with rereads.

    Upstream v2.10 fixes the singular ``/auth/key`` endpoint to Basic
    Auth.  ``admin_transport`` owns the authoritative list reads;
    ``key_revocation_transport`` must therefore be a separately
    constructed, single-use administrator Basic-Auth transport.  It is
    used for only the one DELETE and cannot be reused for a retry.
    """

    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    initial = client._list_auth_keys_for_recovery()
    selected = _select_orphan_api_key(initial, operation="revoke_failed_bootstrap_api_key")

    fresh = client._list_auth_keys_for_recovery()
    fresh_by_id = _by_unique_id(fresh, operation="revoke_failed_bootstrap_api_key")
    fresh_matches = _matching_recovery_keys(fresh)
    if len(fresh_matches) != 1 or fresh_matches[0] != selected:
        raise BootstrapProvisioningError(
            "revoke_failed_bootstrap_api_key: authoritative key identity changed before deletion; "
            "no mutation performed."
        )

    mutation_client = BootstrapProvisioningClient(key_revocation_transport, api_version=api_version)
    mutation_client._revoke_auth_key_for_recovery(key_id=selected.id)
    after = client._list_auth_keys_for_recovery()
    after_by_id = _by_unique_id(after, operation="revoke_failed_bootstrap_api_key")
    if any(key.id == selected.id for key in after):
        raise BootstrapProvisioningError(
            "revoke_failed_bootstrap_api_key: postcondition failed; selected key remains present."
        )
    expected_after = {key_id: key for key_id, key in fresh_by_id.items() if key_id != selected.id}
    if after_by_id != expected_after:
        raise BootstrapProvisioningError(
            "revoke_failed_bootstrap_api_key: postcondition failed; unrelated key metadata changed."
        )
    return RecoveryDeletionEvidence(
        object_kind="api_key",
        selected_id=selected.id,
        objects_before=len(fresh),
        objects_after=len(after),
        verified_absent=True,
        unrelated_objects_preserved=True,
    )


def delete_dedicated_recovery_user(
    *,
    admin_transport: Transport,
    schema: dict[str, object],
    api_version: ApiVersion = ApiVersion.V2,
) -> RecoveryDeletionEvidence:
    """Delete exactly the fixed disposable user after proving no key remains."""

    expected_privileges = _derive_exact_target(schema)
    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    initial_users = client.list_users()
    selected = _select_dedicated_recovery_user(
        initial_users, expected_privileges=expected_privileges, operation="delete_dedicated_recovery_user"
    )
    initial_keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(initial_keys, operation="delete_dedicated_recovery_user")

    fresh_users = client.list_users()
    fresh_users_by_id = _by_unique_id(fresh_users, operation="delete_dedicated_recovery_user")
    fresh_matches = _matching_recovery_users(fresh_users)
    if len(fresh_matches) != 1 or fresh_matches[0] != selected:
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: authoritative account identity changed before deletion; "
            "no mutation performed."
        )
    fresh_keys = client._list_auth_keys_for_recovery()
    fresh_keys_by_id = _by_unique_id(fresh_keys, operation="delete_dedicated_recovery_user")
    if any(key.username is None for key in fresh_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: API-key ownership became unavailable before deletion; "
            "no mutation performed."
        )
    if any(key.username == RECOVERY_USERNAME for key in fresh_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: account acquired an API key before deletion; no mutation performed."
        )

    client._delete_user_for_recovery(user_id=selected.id)
    after_users = client.list_users()
    after_users_by_id = _by_unique_id(after_users, operation="delete_dedicated_recovery_user")
    if any(user.id == selected.id or user.name == RECOVERY_USERNAME for user in after_users):
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: postcondition failed; selected account remains present."
        )
    expected_after = {user_id: user for user_id, user in fresh_users_by_id.items() if user_id != selected.id}
    if after_users_by_id != expected_after:
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: postcondition failed; unrelated account metadata changed."
        )
    after_keys = client._list_auth_keys_for_recovery()
    after_keys_by_id = _by_unique_id(after_keys, operation="delete_dedicated_recovery_user")
    if any(key.username is None or key.username == RECOVERY_USERNAME for key in after_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: postcondition failed; account-owned key remains present."
        )
    if after_keys_by_id != fresh_keys_by_id:
        raise BootstrapProvisioningError(
            "delete_dedicated_recovery_user: postcondition failed; unrelated key metadata changed."
        )
    return RecoveryDeletionEvidence(
        object_kind="user",
        selected_id=selected.id,
        objects_before=len(fresh_users),
        objects_after=len(after_users),
        verified_absent=True,
        unrelated_objects_preserved=True,
    )


def identify_unprovisioned_incident_evidence(
    *, admin_transport: Transport, api_version: ApiVersion = ApiVersion.V2
) -> UnprovisionedIncidentEvidence:
    """Read-only: prove, from two independent fresh reads, that the fixed
    dedicated account was never created and owns no orphan key. Raises
    `BootstrapProvisioningError` (never returns a "maybe") if the account
    exists, if any read is ambiguous (duplicate IDs, unavailable key
    ownership), or if the two reads disagree -- the exact same
    fail-closed discipline `revoke_failed_bootstrap_api_key()`/
    `delete_dedicated_recovery_user()` already apply to their own
    candidate-identification reads. Never makes a mutating call."""

    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)

    first_users = client.list_users()
    _check_account_absent(first_users, operation="identify_unprovisioned_incident_evidence")
    first_keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(first_keys, operation="identify_unprovisioned_incident_evidence")

    second_users = client.list_users()
    _check_account_absent(second_users, operation="identify_unprovisioned_incident_evidence")
    second_keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(second_keys, operation="identify_unprovisioned_incident_evidence")

    if _by_unique_id(first_users, operation="identify_unprovisioned_incident_evidence") != _by_unique_id(
        second_users, operation="identify_unprovisioned_incident_evidence"
    ):
        raise BootstrapProvisioningError(
            "identify_unprovisioned_incident_evidence: authoritative user collection changed between reads; "
            "no resolution performed."
        )
    if _by_unique_id(first_keys, operation="identify_unprovisioned_incident_evidence") != _by_unique_id(
        second_keys, operation="identify_unprovisioned_incident_evidence"
    ):
        raise BootstrapProvisioningError(
            "identify_unprovisioned_incident_evidence: authoritative key collection changed between reads; "
            "no resolution performed."
        )

    return UnprovisionedIncidentEvidence(
        account_username=RECOVERY_USERNAME,
        account_confirmed_absent=True,
        no_owned_key_confirmed=True,
        users_checked=len(second_users),
        keys_checked=len(second_keys),
    )
