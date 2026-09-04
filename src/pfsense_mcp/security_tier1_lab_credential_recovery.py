"""Tier1 LAB credential recovery -- a single, narrow, statically-bound
ceremony for exactly one already-existing pfSense identity:
`pfsense_mcp_tier1_lab` on the dedicated LAB appliance
(`pfsense-test.lab.invalid`, 2026-08-16 SLICE6 provisioning ceremony).

**This is not a generic account-recovery tool.** Every expected value
(hostname label, user id, username, description, starting privilege
set, temporary privilege set, final privilege set) is a module-level
constant, not a caller-supplied parameter -- `recover_tier1_lab_
credential()` refuses to proceed (`RecoveryOutcome.PRESTATE_MISMATCH`)
if live pre-state or the caller's own `target_label` disagree with any
of them. There is no code path that can be redirected at a different
account or a different appliance by caller input alone.

## Why this exists

`api-key-scoped-tier1` (the locally-held key for this account) fails
authentication while the account itself remains live, enabled, and
correctly privileged (confirmed by a live, read-only LAB assessment
2026-09-03/04) -- the local key file is stale relative to whatever
pfSense actually holds. This module resets the account's password,
briefly grants `BOOTSTRAP_ONLY_PRIVILEGE` (pfSense's REST API key model
is self-service-only -- see `security_bootstrap_client.py`'s own
docstring), self-authenticates to mint a brand-new key, writes it to a
**new** file (never overwriting the stale one), then immediately
restores the account to its intended final privilege set with the
temporary privilege removed.

## Reuse, not reinvention

Every HTTP operation goes through `BootstrapProvisioningClient`
(`security_bootstrap_client.py`) -- this module never calls a
`Transport`'s own request method itself (`scripts/get_only_check.py`'s
allow-list does not, and must not, include this file). State tracking
reuses
`BootstrapTransaction`/`BootstrapState`/`check_invariants` unmodified
from `security_bootstrap_transaction.py`. The state labels were named
for the *create* ceremony (`USER_CREATED`, etc.); here they mark the
equivalent checkpoint in a *reset* ceremony for an account that already
exists -- see the inline comment at the first `transition()` call.

## Failure philosophy (unchanged from `security_bootstrap_engine.py`)

**Never attempts an automatic compensating mutation after a failure.**
If a step fails after the temporary bootstrap privilege has been
granted, the transaction moves to `BootstrapState.FAILED` with an
explicit `failure_detail` naming exactly what is left behind and what
manual/operator-reviewed remediation is required -- exactly the
discipline `_provision_new_account()` already established. This module
does not invent a second, different "try to clean up automatically"
mechanism; an automatic action taken after an already-failed,
partially-observed state is itself a new risk, not a mitigation.

## Secret handling

The transient password is generated with the same `secrets.
token_urlsafe(32)` pattern `security_bootstrap_engine.py` uses,
held only in a local variable, and explicitly `del`eted in a `finally`
block. The minted API key is returned only as a `ProvisionedApiKey`
(`security_bootstrap_client.py`) -- reachable only via its own explicit
`.reveal()` method -- and is written to disk (exclusive-create, mode
0600) by this module's own `_write_new_key_file()`, never logged or
included in any exception message.

**Authorized for offline design/test only in this build.** Nothing in
this module is imported by `application.py`, `server.py`, `factory.py`,
`security_cli.py`, `security_doctor.py`, `security_setup_apply.py`, or
any tool under `tools/` (see `tests/test_security_tier1_lab_credential_
recovery_isolation.py`) -- the only way to invoke `recover_tier1_lab_
credential()` in this build is a direct Python import, exactly like
`security_bootstrap_engine.py`'s own `provision_service_account()`.

No `pfsense_mcp.tier1` import in any form.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .api_version import ApiVersion
from .errors import BootstrapProvisioningError
from .security_bootstrap_client import (
    BootstrapProvisioningClient,
    ObservedUser,
    ProvisionedApiKey,
)
from .security_bootstrap_transaction import (
    BOOTSTRAP_ONLY_PRIVILEGE,
    BootstrapState,
    BootstrapTransaction,
    InvariantViolation,
)
from .transport.base import Transport, TransportError

#: The one appliance this module will ever address. `recover_tier1_lab_
#: credential()` requires the caller to pass this exact string as
#: `target_label` -- a static, symmetric cross-check that a caller
#: cannot satisfy by accident with a `Transport` built for any other
#: appliance (in particular, production).
TARGET_LABEL = "pfsense_lab1"
TARGET_HOSTNAME = "pfsense-test.lab.invalid"

#: Static identity this ceremony refuses to proceed without observing
#: exactly, per the 2026-08-16 SLICE6 provisioning ceremony and the
#: live, read-only 2026-09-03/04 LAB assessment that reconfirmed it.
EXPECTED_USER_ID = 1
EXPECTED_USERNAME = "pfsense_mcp_tier1_lab"
EXPECTED_USER_DESCR = "Tier1 scoped WRITE credential for pfsense-mcp-server alias-description workflow"

#: The exact 4 privileges the account is expected to hold before this
#: ceremony touches it. Any deviation (missing, extra, or the temporary
#: bootstrap privilege already present) refuses the whole ceremony.
EXPECTED_STARTING_PRIVILEGES: frozenset[str] = frozenset(
    {
        "api-v2-firewall-aliases-get",
        "api-v2-firewall-alias-patch",
        "api-v2-status-system-get",
        "api-v2-system-hasync-get",
    }
)

#: Starting set plus the temporary self-service-key-minting privilege.
TEMPORARY_PRIVILEGES: frozenset[str] = EXPECTED_STARTING_PRIVILEGES | {BOOTSTRAP_ONLY_PRIVILEGE}

#: The exact 12-privilege steady-state set this ceremony leaves the
#: account in: the original 4, plus 4 new READ and 4 new WRITE
#: privileges for the 5 ADR-037 Batch 1 capabilities (LOG_DISPLAY_
#: PREFERENCES and LOG_RETENTION_SETTINGS share one READ/one WRITE
#: privilege -- both operate on the same `/status/logs/settings`
#: resource). Derived from live evidence, not guessed -- see the
#: 2026-09-04 recovery-preparation report.
FINAL_PRIVILEGES: frozenset[str] = EXPECTED_STARTING_PRIVILEGES | {
    "api-v2-services-ntp-time-servers-get",
    "api-v2-services-ntp-settings-get",
    "api-v2-status-logs-settings-get",
    "api-v2-system-timezone-get",
    "api-v2-services-ntp-time-server-patch",
    "api-v2-services-ntp-settings-patch",
    "api-v2-status-logs-settings-patch",
    "api-v2-system-timezone-patch",
}

#: The one file this ceremony must never overwrite -- the stale,
#: broken local credential this recovery replaces. `_write_new_key_file()`
#: refuses any output path with this exact basename, in addition to its
#: own exclusive-create (`O_EXCL`) file write.
_FORBIDDEN_OUTPUT_BASENAME = "api-key-scoped-tier1"

_PASSWORD_ENTROPY_BYTES = 32
_DEFAULT_KEY_DESCR = "pfsense-mcp Tier1 LAB recovery key (post-2026-09-04 recovery)"


class RecoveryOutcome(str, Enum):
    #: `target_label` or live pre-state (id/name/descr/disabled/starting
    #: privilege set) did not exactly match the static expectations
    #: above. No mutation was performed.
    PRESTATE_MISMATCH = "prestate_mismatch"
    #: The full ceremony completed: password reset, temporary privilege
    #: granted and later revoked, new key minted and written, final
    #: 12-privilege set independently re-verified.
    COMPLETED = "completed"
    #: A step in the ceremony failed. See `transaction.failure_detail`
    #: for exactly which step and what (if anything) was left behind.
    FAILED = "failed"


@dataclass(frozen=True)
class RecoveryResult:
    outcome: RecoveryOutcome
    detail: str
    transaction: BootstrapTransaction | None = None
    api_key: ProvisionedApiKey | None = None


def _sanitize_client_error(exc: BootstrapProvisioningError) -> str:
    return str(exc)


def _failed_result(transaction: BootstrapTransaction) -> RecoveryResult:
    return RecoveryResult(RecoveryOutcome.FAILED, transaction.failure_detail or "", transaction=transaction)


def _find_user(users: tuple[ObservedUser, ...], username: str) -> ObservedUser | None:
    matches = [user for user in users if user.name == username]
    if len(matches) > 1:
        raise BootstrapProvisioningError(
            f"ambiguous account state: {len(matches)} accounts share the name {username!r} -- "
            "refusing to guess which one is the dedicated target account"
        )
    return matches[0] if matches else None


def _prestate_mismatch_detail(user: ObservedUser) -> str | None:
    """Returns `None` if `user` matches every static expectation
    exactly; otherwise a precise, single-cause description. Checked in
    a fixed order so the *first* real mismatch is always the one
    reported, never a downstream symptom of it."""

    if user.id != EXPECTED_USER_ID:
        return f"user id mismatch: expected {EXPECTED_USER_ID}, observed {user.id}"
    if user.name != EXPECTED_USERNAME:
        return f"user name mismatch: expected {EXPECTED_USERNAME!r}, observed {user.name!r}"
    if user.descr != EXPECTED_USER_DESCR:
        return f"user description mismatch: expected {EXPECTED_USER_DESCR!r}, observed {user.descr!r}"
    if user.disabled:
        return "account is disabled; refusing to proceed"
    if user.priv != EXPECTED_STARTING_PRIVILEGES:
        return (
            f"starting privilege set mismatch: expected exactly {sorted(EXPECTED_STARTING_PRIVILEGES)}, "
            f"observed {sorted(user.priv)}"
        )
    return None


def _reread_and_check(
    admin_client: BootstrapProvisioningClient,
    *,
    expected_priv: frozenset[str],
    expected_id: int,
    expected_descr: str,
) -> ObservedUser | None:
    """Independent re-read + exact-match check -- never trusts a
    mutating call's own response echo alone. Mirrors `security_
    bootstrap_engine.py`'s own `_reread_and_check()` exactly (that
    helper is module-private there and not reusable directly)."""

    try:
        users = admin_client.list_users()
        user = _find_user(users, EXPECTED_USERNAME)
    except BootstrapProvisioningError:
        return None
    if (
        user is None
        or user.id != expected_id
        or user.descr != expected_descr
        or user.disabled
        or user.priv != expected_priv
    ):
        return None
    return user


def _write_new_key_file(path: Path, secret: str) -> None:
    """Exclusive-create, mode 0600, never the forbidden stale filename.
    Raises `FileExistsError` if `path` already exists -- this module
    never overwrites any file, new or stale."""

    if path.name == _FORBIDDEN_OUTPUT_BASENAME:
        raise ValueError(
            f"refusing to write the new key to {_FORBIDDEN_OUTPUT_BASENAME!r} -- "
            "this ceremony must never overwrite the existing stale credential"
        )
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, secret.encode("utf-8"))
    finally:
        os.close(fd)


def recover_tier1_lab_credential(
    *,
    target_label: str,
    admin_transport: Transport,
    self_service_transport_factory: Callable[[str, str], Transport],
    api_version: ApiVersion,
    new_key_output_path: Path,
    password_factory: Callable[[], str] | None = None,
    key_descr: str = _DEFAULT_KEY_DESCR,
) -> RecoveryResult:
    """Runs the full A-K recovery ceremony (this module's own docstring)
    against the one statically-known `pfsense_mcp_tier1_lab` LAB
    identity. `target_label` must equal `TARGET_LABEL` exactly -- a
    caller-supplied cross-check refusing any accidental use against a
    differently-labeled `Transport` (in particular, production)."""

    if target_label != TARGET_LABEL:
        return RecoveryResult(
            RecoveryOutcome.PRESTATE_MISMATCH,
            f"target_label mismatch: this ceremony is statically bound to {TARGET_LABEL!r}, "
            f"caller supplied {target_label!r}. Refusing to proceed.",
        )
    if new_key_output_path.name == _FORBIDDEN_OUTPUT_BASENAME:
        return RecoveryResult(
            RecoveryOutcome.PRESTATE_MISMATCH,
            f"new_key_output_path must not be named {_FORBIDDEN_OUTPUT_BASENAME!r} -- "
            "this ceremony must never overwrite the existing stale credential. Refusing to proceed.",
        )

    admin_client = BootstrapProvisioningClient(admin_transport, api_version=api_version)

    try:
        existing_users = admin_client.list_users()
        existing = _find_user(existing_users, EXPECTED_USERNAME)
    except BootstrapProvisioningError as exc:
        return RecoveryResult(RecoveryOutcome.FAILED, f"pre-flight observation failed: {_sanitize_client_error(exc)}")

    if existing is None:
        return RecoveryResult(
            RecoveryOutcome.PRESTATE_MISMATCH,
            f"account {EXPECTED_USERNAME!r} does not exist on this target. Refusing to proceed.",
        )

    mismatch = _prestate_mismatch_detail(existing)
    if mismatch is not None:
        return RecoveryResult(RecoveryOutcome.PRESTATE_MISMATCH, f"pre-state verification failed: {mismatch}")

    return _run_ceremony(
        admin_client,
        self_service_transport_factory,
        api_version=api_version,
        existing=existing,
        new_key_output_path=new_key_output_path,
        key_descr=key_descr,
        password_factory=password_factory or (lambda: secrets.token_urlsafe(_PASSWORD_ENTROPY_BYTES)),
    )


def _run_ceremony(
    admin_client: BootstrapProvisioningClient,
    self_service_transport_factory: Callable[[str, str], Transport],
    *,
    api_version: ApiVersion,
    existing: ObservedUser,
    new_key_output_path: Path,
    key_descr: str,
    password_factory: Callable[[], str],
) -> RecoveryResult:
    transaction = BootstrapTransaction(state=BootstrapState.NOT_STARTED, privileges=existing.priv)
    password = password_factory()

    try:
        # Step B/C: reset the transient password, then grant exactly the
        # temporary bootstrap privilege on top of the confirmed starting
        # set. Two separate PATCHes (password has no re-readable
        # confirmation of its own; the privilege PATCH does).
        try:
            admin_client.update_user_password(user_id=existing.id, password=password)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(f"password reset failed: {_sanitize_client_error(exc)}")
            return _failed_result(transaction)

        try:
            admin_client.update_user_privileges(user_id=existing.id, priv=TEMPORARY_PRIVILEGES)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(
                f"temporary bootstrap-privilege grant failed: {_sanitize_client_error(exc)}. The account's "
                "password was already reset to a new, undisclosed transient value -- this requires "
                "manual/operator-reviewed remediation before the account can be used again."
            )
            return _failed_result(transaction)

        verified = _reread_and_check(
            admin_client,
            expected_priv=TEMPORARY_PRIVILEGES,
            expected_id=existing.id,
            expected_descr=EXPECTED_USER_DESCR,
        )
        if verified is None:
            transaction = transaction.fail(
                "post-grant verification failed: account does not hold exactly the expected starting "
                "privileges plus the temporary bootstrap privilege. The account's password was already reset "
                "to a new, undisclosed transient value -- this requires manual/operator-reviewed remediation."
            )
            return _failed_result(transaction)

        # Reused verbatim from security_bootstrap_transaction.py: this
        # state machine's labels were named for the *create* ceremony
        # (`_provision_new_account()`); here `USER_CREATED` marks the
        # equivalent checkpoint for a *reset* ceremony on an account that
        # already existed -- "the account is now in its known-good
        # starting configuration, ready for the bootstrap-privilege
        # dance," exactly like a freshly created one would be.
        try:
            transaction = transaction.transition(BootstrapState.USER_CREATED, privileges=EXPECTED_STARTING_PRIVILEGES)
            transaction = transaction.transition(
                BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, privileges=TEMPORARY_PRIVILEGES
            )
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after bootstrap-privilege grant: {exc}")
            return _failed_result(transaction)

        # Step D/E: authenticate as the account itself and self-mint.
        try:
            self_transport = self_service_transport_factory(EXPECTED_USERNAME, password)
            self_client = BootstrapProvisioningClient(self_transport, api_version=api_version)
            api_key = self_client.create_auth_key(descr=key_descr)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(
                f"API-key creation failed: {_sanitize_client_error(exc)}. The account currently holds the "
                f"temporary bootstrap privilege {BOOTSTRAP_ONLY_PRIVILEGE!r} and a new, undisclosed transient "
                "password -- this was NOT automatically reverted and requires manual/operator-reviewed "
                "remediation."
            )
            return _failed_result(transaction)
        except TransportError:
            transaction = transaction.fail(
                "API-key creation transport failed. The account currently holds the temporary bootstrap "
                f"privilege {BOOTSTRAP_ONLY_PRIVILEGE!r} and a new, undisclosed transient password -- this was "
                "NOT automatically reverted and requires manual/operator-reviewed remediation."
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(BootstrapState.KEY_GENERATED, privileges=TEMPORARY_PRIVILEGES)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after key generation: {exc}")
            return _failed_result(transaction)

        # Step F: write the new key to a NEW file before touching
        # privileges further -- if the write fails, the minted key is
        # still valid and the failure detail says so explicitly rather
        # than implying the key itself is unusable.
        try:
            _write_new_key_file(new_key_output_path, api_key.reveal())
        except (OSError, ValueError) as exc:
            reason = "the target file already exists" if isinstance(exc, FileExistsError) else str(exc)
            transaction = transaction.fail(
                f"writing the new API key file failed ({reason}). A usable API key was already minted for "
                f"this account and the account still holds the temporary bootstrap privilege "
                f"{BOOTSTRAP_ONLY_PRIVILEGE!r} and the new transient password -- this requires "
                "manual/operator-reviewed remediation. The minted key was not written to any file by this "
                "process and is now unrecoverable from this run."
            )
            return _failed_result(transaction)

        # Step G: restore the account to the exact final 12-privilege
        # set in one PATCH (full-replace semantics), removing the
        # temporary bootstrap privilege in the same call.
        try:
            admin_client.update_user_privileges(user_id=existing.id, priv=FINAL_PRIVILEGES)
        except BootstrapProvisioningError as exc:
            transaction = transaction.fail(
                f"final-privilege-set application failed: {_sanitize_client_error(exc)}. The account currently "
                f"holds the temporary bootstrap privilege {BOOTSTRAP_ONLY_PRIVILEGE!r} -- this requires "
                "manual/operator-reviewed remediation. A usable API key was already minted and written to "
                f"{new_key_output_path}."
            )
            return _failed_result(transaction)

        # Step H: independent re-read, exact equality required.
        verified = _reread_and_check(
            admin_client,
            expected_priv=FINAL_PRIVILEGES,
            expected_id=existing.id,
            expected_descr=EXPECTED_USER_DESCR,
        )
        if verified is None:
            transaction = transaction.fail(
                "post-finalization verification failed: cannot confirm the account holds exactly the final "
                "12-privilege set with the temporary bootstrap privilege removed -- treat the temporary "
                "privilege as still present until manually confirmed. A usable API key was already minted and "
                f"written to {new_key_output_path}."
            )
            return _failed_result(transaction)

        try:
            transaction = transaction.transition(
                BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, privileges=FINAL_PRIVILEGES
            )
            transaction = transaction.transition(BootstrapState.VERIFIED, privileges=FINAL_PRIVILEGES)
        except InvariantViolation as exc:
            transaction = transaction.fail(f"internal invariant violation after finalization verification: {exc}")
            return _failed_result(transaction)

        return RecoveryResult(
            RecoveryOutcome.COMPLETED,
            f"account {EXPECTED_USERNAME!r} recovered: new API key minted and written to "
            f"{new_key_output_path}, account holds exactly the {len(FINAL_PRIVILEGES)}-privilege final set.",
            transaction=transaction,
            api_key=api_key,
        )
    finally:
        del password
