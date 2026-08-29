"""Closed, owner-directed recovery for the dedicated `read_only` managed
service account -- the READ-only counterpart of
`security_bootstrap_recovery.py`.

**Why a separate module rather than a parametrized one** (POST-v1.0
MANAGED READ-ONLY DEFENSE IN DEPTH mission, 2026-08-29): every private
selection helper in `security_bootstrap_recovery.py`
(`_matching_recovery_keys()`, `_matching_recovery_users()`,
`_select_dedicated_recovery_user()`, `_check_no_owned_key()`) matches
against that module's own hardcoded `RECOVERY_USERNAME`/
`RECOVERY_USER_DESCRIPTION`/`RECOVERY_KEY_DESCRIPTION` constants, not a
parameter. Threading a profile/account discriminant through every one
of those helpers would touch already-reviewed, live-LAB-verified
deletion logic whose entire safety property rests on "exactly one
fixed username, never negotiable." A full, independent duplicate with
its own fixed `READONLY_RECOVERY_USERNAME` is safer: it is
structurally impossible for this module's orphan-key/duplicate-account
detection to ever match `security_bootstrap_recovery.py`'s
`write_protected` account, or vice versa, and a bug fix to one
ceremony's deletion logic can never silently change the other's
behavior. This mirrors this codebase's own established precedent for
isolated security subsystems (`pfsense_mcp.tier1.authorization_
consumption_store`'s own docstring: "Duplicated rather than shared").

Exposes exactly two independent actions, structurally identical in
every respect to the `write_protected` recovery module except which
fixed account they target: revoke the one unambiguously identified
orphan key from a failed READ-only bootstrap ceremony, and delete the
one fixed disposable READ-only service account after proving no key
remains. Neither action chains into the other, retries, provisions, or
invokes the bootstrap engine.

Nothing imports this module from CLI, application, MCP tools, or
normal runtime -- only `security_recovery_orchestration.py` may.
"""

from __future__ import annotations

from typing import TypeVar

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .security_bootstrap_client import BootstrapProvisioningClient, ObservedApiKey, ObservedUser
from .security_bootstrap_recovery import RecoveryDeletionEvidence
from .security_privileges import (
    EvidenceClass,
    distinct_ok_privileges,
    read_profile_requirements,
    resolve_profile_privileges,
)
from .transport.base import Transport

READONLY_RECOVERY_USERNAME = "pfsense-mcp-readonly"
READONLY_RECOVERY_USER_DESCRIPTION = "Dedicated READ-only service account for pfsense-mcp-server"
READONLY_RECOVERY_KEY_DESCRIPTION = "pfsense-mcp-server read-only API key"

_ObservedObject = TypeVar("_ObservedObject", ObservedApiKey, ObservedUser)

#: Reused verbatim from `security_bootstrap_recovery.py` -- a pure data
#: shape (object_kind/selected_id/objects_before/objects_after/
#: verified_absent/unrelated_objects_preserved) with no account/profile
#: identity baked in, so sharing the type carries none of the risk that
#: motivated duplicating the *selection logic* in this module (see this
#: module's own docstring). Also keeps `_FixedMutationComponents`'s
#: `revoke_orphan_key_call`/`delete_dedicated_user_call` field types
#: satisfied without widening them.
ReadonlyRecoveryDeletionEvidence = RecoveryDeletionEvidence


def _derive_exact_target(schema: dict[str, object]) -> frozenset[str]:
    resolved = resolve_profile_privileges(schema, read_profile_requirements())
    if not resolved or any(
        not item.ok or item.evidence_class is not EvidenceClass.SOURCE_CROSS_CHECKED for item in resolved
    ):
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: target privilege derivation was not fully source-cross-checked."
        )
    target = distinct_ok_privileges(resolved)
    if not target:
        raise BootstrapProvisioningError("delete_dedicated_readonly_recovery_user: target privilege set was empty.")
    return target


def _matching_recovery_keys(keys: tuple[ObservedApiKey, ...]) -> tuple[ObservedApiKey, ...]:
    return tuple(
        key
        for key in keys
        if key.username == READONLY_RECOVERY_USERNAME and key.descr == READONLY_RECOVERY_KEY_DESCRIPTION
    )


def _matching_recovery_users(users: tuple[ObservedUser, ...]) -> tuple[ObservedUser, ...]:
    return tuple(user for user in users if user.name == READONLY_RECOVERY_USERNAME)


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
        selected.descr != READONLY_RECOVERY_USER_DESCRIPTION
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
    if any(key.username == READONLY_RECOVERY_USERNAME for key in keys):
        raise BootstrapProvisioningError(
            f"{operation}: account still owns one or more API keys; no mutation performed."
        )


def identify_orphan_readonly_api_key_candidate(
    *, admin_transport: Transport, api_version: ApiVersion = ApiVersion.V2
) -> ObservedApiKey:
    """Read-only: identify the exact orphan key
    `revoke_failed_readonly_bootstrap_api_key()` would select, without
    mutating anything -- shares `_select_orphan_api_key()` with that
    function's own first-read step, so there is exactly one
    implementation of "what counts as the orphan key", never
    duplicated. Never makes a mutating call."""

    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    keys = client._list_auth_keys_for_recovery()
    return _select_orphan_api_key(keys, operation="identify_orphan_readonly_api_key_candidate")


def identify_dedicated_readonly_recovery_user_candidate(
    *, admin_transport: Transport, schema: dict[str, object], api_version: ApiVersion = ApiVersion.V2
) -> ObservedUser:
    """Read-only: identify the exact account
    `delete_dedicated_readonly_recovery_user()` would select, including
    the same "does it still own a key" precondition that function's own
    first-read phase checks -- shared, not duplicated. Never makes a
    mutating call."""

    expected_privileges = _derive_exact_target(schema)
    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    users = client.list_users()
    selected = _select_dedicated_recovery_user(
        users, expected_privileges=expected_privileges, operation="identify_dedicated_readonly_recovery_user_candidate"
    )
    keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(keys, operation="identify_dedicated_readonly_recovery_user_candidate")
    return selected


def revoke_failed_readonly_bootstrap_api_key(
    *,
    admin_transport: Transport,
    key_revocation_transport: Transport,
    api_version: ApiVersion = ApiVersion.V2,
) -> ReadonlyRecoveryDeletionEvidence:
    """Revoke exactly one fixed-identity orphan key, once, with rereads.

    `key_revocation_transport` must be a separately constructed,
    single-use administrator Basic-Auth transport, used for only the
    one DELETE -- cannot be reused for a retry.
    """

    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    initial = client._list_auth_keys_for_recovery()
    selected = _select_orphan_api_key(initial, operation="revoke_failed_readonly_bootstrap_api_key")

    fresh = client._list_auth_keys_for_recovery()
    fresh_by_id = _by_unique_id(fresh, operation="revoke_failed_readonly_bootstrap_api_key")
    fresh_matches = _matching_recovery_keys(fresh)
    if len(fresh_matches) != 1 or fresh_matches[0] != selected:
        raise BootstrapProvisioningError(
            "revoke_failed_readonly_bootstrap_api_key: authoritative key identity changed before deletion; "
            "no mutation performed."
        )

    mutation_client = BootstrapProvisioningClient(key_revocation_transport, api_version=api_version)
    mutation_client._revoke_auth_key_for_recovery(key_id=selected.id)
    after = client._list_auth_keys_for_recovery()
    after_by_id = _by_unique_id(after, operation="revoke_failed_readonly_bootstrap_api_key")
    if any(key.id == selected.id for key in after):
        raise BootstrapProvisioningError(
            "revoke_failed_readonly_bootstrap_api_key: postcondition failed; selected key remains present."
        )
    expected_after = {key_id: key for key_id, key in fresh_by_id.items() if key_id != selected.id}
    if after_by_id != expected_after:
        raise BootstrapProvisioningError(
            "revoke_failed_readonly_bootstrap_api_key: postcondition failed; unrelated key metadata changed."
        )
    return ReadonlyRecoveryDeletionEvidence(
        object_kind="api_key",
        selected_id=selected.id,
        objects_before=len(fresh),
        objects_after=len(after),
        verified_absent=True,
        unrelated_objects_preserved=True,
    )


def delete_dedicated_readonly_recovery_user(
    *,
    admin_transport: Transport,
    schema: dict[str, object],
    api_version: ApiVersion = ApiVersion.V2,
) -> ReadonlyRecoveryDeletionEvidence:
    """Delete exactly the fixed disposable READ-only user after proving
    no key remains."""

    expected_privileges = _derive_exact_target(schema)
    client = BootstrapProvisioningClient(admin_transport, api_version=api_version)
    initial_users = client.list_users()
    selected = _select_dedicated_recovery_user(
        initial_users, expected_privileges=expected_privileges, operation="delete_dedicated_readonly_recovery_user"
    )
    initial_keys = client._list_auth_keys_for_recovery()
    _check_no_owned_key(initial_keys, operation="delete_dedicated_readonly_recovery_user")

    fresh_users = client.list_users()
    fresh_users_by_id = _by_unique_id(fresh_users, operation="delete_dedicated_readonly_recovery_user")
    fresh_matches = _matching_recovery_users(fresh_users)
    if len(fresh_matches) != 1 or fresh_matches[0] != selected:
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: authoritative account identity changed before deletion; "
            "no mutation performed."
        )
    fresh_keys = client._list_auth_keys_for_recovery()
    fresh_keys_by_id = _by_unique_id(fresh_keys, operation="delete_dedicated_readonly_recovery_user")
    if any(key.username is None for key in fresh_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: API-key ownership became unavailable before deletion; "
            "no mutation performed."
        )
    if any(key.username == READONLY_RECOVERY_USERNAME for key in fresh_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: account acquired an API key before deletion; "
            "no mutation performed."
        )

    client._delete_user_for_recovery(user_id=selected.id)
    after_users = client.list_users()
    after_users_by_id = _by_unique_id(after_users, operation="delete_dedicated_readonly_recovery_user")
    if any(user.id == selected.id or user.name == READONLY_RECOVERY_USERNAME for user in after_users):
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: postcondition failed; selected account remains present."
        )
    expected_after = {user_id: user for user_id, user in fresh_users_by_id.items() if user_id != selected.id}
    if after_users_by_id != expected_after:
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: postcondition failed; unrelated account metadata changed."
        )
    after_keys = client._list_auth_keys_for_recovery()
    after_keys_by_id = _by_unique_id(after_keys, operation="delete_dedicated_readonly_recovery_user")
    if any(key.username is None or key.username == READONLY_RECOVERY_USERNAME for key in after_keys):
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: postcondition failed; account-owned key remains present."
        )
    if after_keys_by_id != fresh_keys_by_id:
        raise BootstrapProvisioningError(
            "delete_dedicated_readonly_recovery_user: postcondition failed; unrelated key metadata changed."
        )
    return ReadonlyRecoveryDeletionEvidence(
        object_kind="user",
        selected_id=selected.id,
        objects_before=len(fresh_users),
        objects_after=len(after_users),
        verified_absent=True,
        unrelated_objects_preserved=True,
    )
