"""ADR-033 CLI Integration Slice 3 -- journal-aware bootstrap orchestration.

This is the single, narrow gateway between a CLI (or any future caller)
and the already-implemented, already-reviewed security-bootstrap stack:
`security_admin_composition.py` (fixed context, lock, journal, mutation
closures), `security_bootstrap_engine.py` (`provision_service_account()`),
and `security_operation_journal.py` (crash-safe journal + lock + restart
classification). It does not reimplement any business logic from those
modules -- it only sequences them.

`security_cli.py` must import *only* this module, never
`security_admin_composition`/`security_bootstrap_engine`/
`security_bootstrap_client`/`security_bootstrap_recovery`/
`security_auth_transition` directly -- `tests/test_security_bootstrap_engine_isolation.py`
enforces that those module names never appear in any shipped runtime
entry point's source text (`server.py`, `application.py`, `factory.py`,
`security_cli.py`, `security_doctor.py`). This module is the one place
allowed to bridge that boundary, and it is itself never imported by any
of those five entry points except `security_cli.py`.

## Control flow

1. `context.status.classify(authoritative=None)` -- read-only, no lock,
   no journal write. The CLI's offline default always passes
   `authoritative=None` (this slice performs no live pfSense call), so
   per `classify_restart()`'s own documented, existing behavior, any
   pre-existing journal is conservatively treated as needing recovery
   attention -- this is not a gap this slice needs to fix.
   - `CLEAN_NO_OPERATION` -> proceed to provisioning.
   - `CLEAN_COMPLETED` -> nothing to do; report success without
     touching the lock or journal.
   - anything else -> refuse to start; surface the classification and
     (if present) `recovery_action` for a human to act on. This slice
     never attempts automatic recovery (`security_bootstrap_recovery.py`
     stays a separate, explicitly-invoked concern).
2. Acquire the lock. Lock contention (including the "stale or ambiguous
   active metadata" case, which `ExclusiveOperationLock.acquire()`
   already refuses to silently resolve) is reported distinctly.
3. Create the journal (`CREATED`), append `PRE_SEND_READY`
   (mutation_index=1), then append `MUTATION_INTENT_RECORDED`
   unconditionally, *before* calling the engine -- the engine's single
   blocking call can perform anywhere from zero to several real HTTP
   mutations, and this orchestration cannot know in advance which. A
   crash during the engine call leaves the journal at
   `MUTATION_INTENT_RECORDED` and the lock `ACTIVE_STALE`; the next
   `classify()` call (still offline, `authoritative=None`) reports
   `RECOVERY_REQUIRED` before any further action is possible --
   requirement already satisfied by the existing journal/lock design,
   with no new code needed for the crash case itself.
4. Call `context._mutation_components.bootstrap_call()` inside a single
   `try/except Exception`. Any exception escaping the engine (whether a
   documented failure mode or not) is treated exactly like a returned
   `FAILED` outcome: the journal is closed at `MUTATION_RESULT_UNKNOWN`
   and the lock is deliberately **not** released, forcing a human to
   look before any further bootstrap attempt against this target/binding
   can proceed.
5. On a normal return, branch on `ProvisioningOutcome`:
   - `ALREADY_SATISFIED`, `ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES`,
     `PRIVILEGES_SYNCED`, `COMPLETED` -- verified success. Journal
     advances through `FINAL_VERIFICATION_PENDING` to `COMPLETED`, lock
     released. For `COMPLETED` specifically (a brand-new account and a
     freshly generated API key), the revealed key is persisted to the
     existing, already-validated `PFSENSE_SERVICE_API_KEY_FILE` custody
     path *before* the journal is closed -- required so that a later
     `classify()` call's local-artifact check
     (`test_custody_artifact_is_observed_internally_and_cannot_be_hidden`
     / `test_completed_operation_never_silently_reopens_bootstrap` in
     `tests/test_security_admin_composition.py`) sees a custody artifact
     that is properly accounted for by a matching completed journal,
     rather than an orphaned key file with no journal to explain it.
   - `DERIVATION_FAILED`, `BLOCKED_EXISTING_PARTIAL`, `FAILED` -- not a
     clean success. Journal closed at `MUTATION_RESULT_UNKNOWN`, lock
     **not** released. `DERIVATION_FAILED` gets its own
     `BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED` value
     (the engine proves zero HTTP activity occurred, which is useful
     diagnostic information at the CLI/exit-code level) but is
     journaled identically to a real engine failure: this target's
     journal path is fixed by its namespace, and `classify_restart()`
     treats *any* pre-existing journal as `RECOVERY_REQUIRED` whenever
     no live `authoritative` observation is supplied (this offline
     slice's CLI default), so closing it any other way would not
     actually let an offline retry proceed automatically -- a human (or
     a future live-authorized slice) must look before any further
     attempt against this namespace, regardless of how safely this run
     ended.

The custody-file write uses the same exclusive-creation-only,
owner-only-permission, atomic-on-failure discipline as
`pfsense_mcp.tier1.artifact_exchange.write_secure_new()` -- but is its
own, independent implementation rather than importing that function:
`tests/tier1/test_isolation.py` enforces that nothing outside the
`pfsense_mcp.tier1` package (short of a short, reviewed bridge-module
exemption list this module deliberately does not join) imports
`pfsense_mcp.tier1` in any form, matching this codebase's established
precedent of duplicating this exact descriptor discipline per isolated
subsystem rather than sharing it (see e.g.
`pfsense_mcp.tier1.authorization_consumption_store`'s own docstring:
"Duplicated rather than shared").
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path

from .errors import PfSenseMCPError
from .security_admin_composition import (
    AdminCompositionError,
    AdministrativeContext,
    PfRestReadOnlyStatus,
    build_admin_context,
    locate_bootstrap_chain_frontier,
)
from .security_bootstrap_client import ProvisionedApiKey
from .security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from .security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    AuthoritativeRestartObservation,
    AuthoritativeServerState,
    DurableOperationState,
    OperationJournalError,
    OperationLockError,
    RestartClassification,
    RestartDecision,
)
from .security_readonly_admin_composition import build_readonly_admin_context

__all__ = [
    "BootstrapOrchestrationError",
    "BootstrapOrchestrationOutcome",
    "BootstrapOrchestrationResult",
    "build_authoritative_restart_observation",
    "run_bootstrap",
    "run_bootstrap_from_environment",
    "run_readonly_bootstrap_from_environment",
]


class BootstrapOrchestrationError(PfSenseMCPError):
    """Raised only for programmer-error-shaped misuse of this module
    (e.g. a caller-supplied timestamp/operation-id factory that itself
    raises). Never raised for an ordinary provisioning failure -- those
    are reported via `BootstrapOrchestrationResult`, not an exception."""


class BootstrapOrchestrationOutcome(str, Enum):
    """Exhaustive, CLI-mappable result category. Deliberately does not
    collapse every failure into one generic value -- see Section 7 of
    the ADR-033 CLI Integration Slice 3 task."""

    #: A clean journal already exists for this target/binding recording a
    #: fully verified prior completion; nothing new was attempted.
    ALREADY_COMPLETE = "already_complete"
    #: This run performed (or confirmed) the intended provisioning state
    #: and the journal is now cleanly closed.
    COMPLETED = "completed"
    #: `build_admin_context()` itself refused this environment/configuration
    #: (missing/invalid env var, insecure file permissions, malformed
    #: package-version format, schema not fully `SOURCE_CROSS_CHECKED`,
    #: insecure TLS mode, etc.) -- no lock or journal was ever touched.
    BLOCKED_CONFIGURATION_ERROR = "blocked_configuration_error"
    #: Another live process currently holds the local operation lock.
    BLOCKED_LOCK_CONTENTION = "blocked_lock_contention"
    #: A prior operation's journal/lock state requires human recovery
    #: attention before a new bootstrap may start. See `restart_decision`.
    BLOCKED_PRIOR_OPERATION = "blocked_prior_operation"
    #: Local journal/lock/custody-artifact state is corrupt, unauthenticated,
    #: or internally inconsistent. See `restart_decision`.
    BLOCKED_CORRUPT_LOCAL_STATE = "blocked_corrupt_local_state"
    #: The engine refused before any HTTP call (unsupported package version,
    #: or privilege derivation that is not fully `SOURCE_CROSS_CHECKED`).
    #: Proven zero network activity, but this does *not* by itself unblock
    #: a subsequent offline attempt against the same target -- see
    #: `run_bootstrap()`'s module docstring for why.
    PREFLIGHT_DERIVATION_FAILED = "preflight_derivation_failed"
    #: pfSense's own global REST API "Read Only" mode was confirmed
    #: enabled, or its status could not be authoritatively verified,
    #: *before* any journal record was created for this attempt -- zero
    #: POST/PATCH/DELETE was ever sent. Unlike every other blocked
    #: outcome above, local state is left exactly as it was before this
    #: call (no journal created, lock released), so this outcome is
    #: always naturally, immediately retryable: once the owner manually
    #: disables Read Only in WebConfigurator (this module never does so
    #: itself, and never will), the next bootstrap attempt against this
    #: same namespace is a completely fresh CLEAN_NO_OPERATION start. See
    #: `_run_locked()`'s own docstring for the exact journal-boundary
    #: reasoning.
    BLOCKED_READ_ONLY_MODE = "blocked_read_only_mode"
    #: The engine ran, performed at least one authoritative read (and
    #: possibly a mutation), and did not reach a verified successful
    #: state, or an unexpected exception escaped the engine call. Local
    #: state is left `MUTATION_RESULT_UNKNOWN` and the lock is held for
    #: human review.
    PROVISIONING_FAILED = "provisioning_failed"


@dataclass(frozen=True)
class BootstrapOrchestrationResult:
    """Structured, secret-free outcome of one `run_bootstrap()` call.

    Never carries an API key, password, or any other secret value --
    `provisioning_detail` and `detail` come only from
    `ProvisioningResult.detail`/`failure_detail`-style strings, which
    are themselves already sanitized by `security_bootstrap_engine.py`."""

    outcome: BootstrapOrchestrationOutcome
    detail: str
    operation_id: str | None = None
    restart_decision: RestartDecision | None = None
    provisioning_outcome: ProvisioningOutcome | None = None
    provisioning_detail: str | None = None


_CLEAN_SUCCESS_OUTCOMES = frozenset(
    {
        ProvisioningOutcome.ALREADY_SATISFIED,
        ProvisioningOutcome.ALREADY_SATISFIED_WITH_EXTRA_PRIVILEGES,
        ProvisioningOutcome.PRIVILEGES_SYNCED,
        ProvisioningOutcome.COMPLETED,
    }
)


def _default_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_operation_id() -> str:
    return secrets.token_hex(16)


def run_bootstrap(
    context: AdministrativeContext,
    *,
    authoritative: AuthoritativeRestartObservation | None = None,
    now: Callable[[], str] = _default_now,
    operation_id_factory: Callable[[], str] = _default_operation_id,
) -> BootstrapOrchestrationResult:
    """Run exactly one bootstrap attempt against `context`'s fixed
    target/account/profile, or refuse and report why.

    `authoritative` defaults to `None`, matching this slice's offline-only
    execution mode: the real CLI never supplies a live server observation
    here. Tests inject a synthetic `AuthoritativeRestartObservation` to
    exercise classification branches that would otherwise require a real
    pfSense appliance.

    `now`/`operation_id_factory` are injectable for deterministic tests;
    production callers use the defaults.
    """

    decision = context.status.classify(authoritative=authoritative)

    if decision.classification is RestartClassification.CLEAN_COMPLETED:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.ALREADY_COMPLETE,
            "A prior bootstrap operation for this target/account/profile is already recorded complete.",
            operation_id=decision.operation_id,
            restart_decision=decision,
        )

    if decision.classification is RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            "Local journal, lock, or custody-artifact state is corrupt or untrusted; refusing to start.",
            operation_id=decision.operation_id,
            restart_decision=decision,
        )

    if decision.classification is not RestartClassification.CLEAN_NO_OPERATION:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION,
            f"A prior operation's state ({decision.classification.value}) requires attention before a new "
            "bootstrap may start.",
            operation_id=decision.operation_id,
            restart_decision=decision,
        )

    operation_id = operation_id_factory()
    timestamp = now()
    try:
        context._lock.acquire(operation_id, timestamp=timestamp)
    except OperationLockError as exc:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION,
            str(exc),
        )

    try:
        return _run_locked(context, operation_id=operation_id, timestamp=timestamp, now=now)
    except OperationJournalError as exc:
        # Journal-level failure while establishing/advancing our own
        # operation's records. Do not attempt to release the lock through
        # a possibly-broken journal state; leave it for human recovery.
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            f"Operation journal error: {exc}",
            operation_id=operation_id,
        )


#: Exact wording required by the pfREST global Read Only pre-flight
#: security invariant: pfsense-mcp-server may *detect* Read Only, but
#: must never disable, bypass, or instruct any other path to disable it
#: -- only the owner, manually, in WebConfigurator. See `_run_locked()`'s
#: own docstring for the journal-boundary guarantee this pairs with.
_READ_ONLY_BLOCKED_DETAIL = (
    "WRITE blocked — owner must disable Read Only in WebConfigurator. pfREST reports its global REST "
    "API Read Only setting is enabled; pfsense-mcp-server will never disable this automatically. Retry "
    "bootstrap once the owner has disabled it."
)
_READ_ONLY_UNVERIFIABLE_DETAIL = (
    "WRITE blocked — pfREST Read Only status could not be authoritatively verified before "
    "provisioning; treated as blocked (fail closed). Resolve connectivity/configuration to the target and "
    "retry."
)


def _run_locked(
    context: AdministrativeContext,
    *,
    operation_id: str,
    timestamp: str,
    now: Callable[[], str],
) -> BootstrapOrchestrationResult:
    """`operation_id`/`timestamp` are only consumed once the read-only
    pre-flight check below has already confirmed the target is writable
    -- see this function's own read-only branch for why the check must
    run *before* `context._journal.create()`, not merely before the
    mutating call itself.

    ## Read-only pre-flight journal boundary (Mission II Mission B)

    pfSense's own global REST API "Read Only" mode rejects every
    non-GET request with HTTP 405 at the server, before any model/write
    logic runs -- a condition fully discoverable via one GET, cheaper
    and more precise than discovering it via a failed mutating call.
    This check therefore runs as the *first* thing inside the acquired
    lock, strictly before any journal record exists for this attempt
    (`context._journal.create()` has not yet been called). If the check
    reports anything other than `WRITABLE`, this function releases the
    lock it is holding and returns immediately -- **no journal is ever
    created**, so `context.journal_path` remains exactly as it was
    before this call.

    This is deliberately different from every other blocked outcome in
    this module (`PREFLIGHT_DERIVATION_FAILED`, `PROVISIONING_FAILED`),
    which all leave a journal behind specifically so a human must look
    before any further attempt (see this module's own top-level
    docstring). A read-only-mode rejection carries no such ambiguity --
    it proves definitively that zero mutation was attempted, so leaving
    no local trace at all is not merely convenient but the *correct*
    representation of what happened: `classify_restart()`'s own
    documented behavior means any existing journal, even one that never
    reached a mutating state, is treated as `RECOVERY_REQUIRED` once
    `authoritative=None` (this CLI's default) -- creating one here would
    silently convert an environmental, always-retryable condition into a
    permanently-blocking incident requiring `recover`, which would be
    incorrect. A subsequent bootstrap attempt against this exact
    namespace, once the owner has manually disabled Read Only, is
    therefore a completely fresh `CLEAN_NO_OPERATION` start with no
    recovery action required."""

    read_only_status = context._mutation_components.check_pfrest_read_only_call()
    if read_only_status is not PfRestReadOnlyStatus.WRITABLE:
        context._lock.release(timestamp=now())
        detail = (
            _READ_ONLY_BLOCKED_DETAIL
            if read_only_status is PfRestReadOnlyStatus.BLOCKED_READ_ONLY
            else _READ_ONLY_UNVERIFIABLE_DETAIL
        )
        return BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_READ_ONLY_MODE, detail)

    binding = context.new_operation_binding(
        operation_id=operation_id, operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    context._journal.create(binding, timestamp=timestamp)
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=now(),
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=now(),
    )

    try:
        result = context._mutation_components.bootstrap_call()
    except Exception as exc:  # deliberately broad: any escape from the engine is treated as ambiguous
        context._journal.append(
            operation_id=operation_id,
            state=DurableOperationState.MUTATION_RESULT_UNKNOWN,
            transaction_state=AdministrativeTransactionState.NOT_STARTED,
            mutation_index=1,
            timestamp=now(),
        )
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.PROVISIONING_FAILED,
            f"An unexpected error occurred during provisioning ({type(exc).__name__}); "
            "the operation lock is held pending manual investigation.",
            operation_id=operation_id,
        )

    if result.outcome in _CLEAN_SUCCESS_OUTCOMES:
        if result.outcome is ProvisioningOutcome.COMPLETED and result.api_key is not None:
            _persist_service_api_key(context, result.api_key)
        context._journal.append(
            operation_id=operation_id,
            state=DurableOperationState.FINAL_VERIFICATION_PENDING,
            transaction_state=_derive_transaction_state(result),
            mutation_index=1,
            timestamp=now(),
        )
        context._journal.append(
            operation_id=operation_id,
            state=DurableOperationState.COMPLETED,
            transaction_state=_derive_transaction_state(result),
            mutation_index=1,
            timestamp=now(),
        )
        context._lock.release(timestamp=now())
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.COMPLETED,
            result.detail,
            operation_id=operation_id,
            provisioning_outcome=result.outcome,
            provisioning_detail=result.detail,
        )

    # DERIVATION_FAILED, BLOCKED_EXISTING_PARTIAL, or FAILED: not a clean
    # success. Journaled uniformly at MUTATION_RESULT_UNKNOWN with the lock
    # held -- even DERIVATION_FAILED, which the engine proves involved zero
    # HTTP activity, cannot be closed as a retry-enabling COMPLETED: this
    # target/account/profile's journal path is fixed by its namespace, and
    # `classify_restart()` treats *any* pre-existing journal as
    # RECOVERY_REQUIRED whenever no live `authoritative` observation is
    # supplied (this offline slice's CLI default) -- so a "safe to retry
    # immediately" journal state would not actually unblock an offline
    # retry, and pretending otherwise would misrepresent what this slice
    # can prove. A human (or a future live-authorized slice) must look
    # before any further attempt against this namespace.
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.MUTATION_RESULT_UNKNOWN,
        transaction_state=_derive_transaction_state(result),
        mutation_index=1,
        timestamp=now(),
    )
    outcome = (
        BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED
        if result.outcome is ProvisioningOutcome.DERIVATION_FAILED
        else BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    )
    return BootstrapOrchestrationResult(
        outcome,
        result.detail,
        operation_id=operation_id,
        provisioning_outcome=result.outcome,
        provisioning_detail=result.detail,
    )


def _derive_transaction_state(result: ProvisioningResult) -> AdministrativeTransactionState:
    """Best-effort, informational-only mapping (the journal does not
    validate `transaction_state` as part of transition legality -- only
    `state` is safety-critical). `BootstrapState.FAILED` has no
    equivalent `AdministrativeTransactionState` value and the engine's
    own transaction model does not preserve which checkpoint preceded a
    failure, so it maps to `NOT_STARTED` rather than guessing."""

    if result.transaction is not None:
        try:
            return AdministrativeTransactionState(result.transaction.state.value)
        except ValueError:
            return AdministrativeTransactionState.NOT_STARTED
    if result.outcome in _CLEAN_SUCCESS_OUTCOMES:
        return AdministrativeTransactionState.VERIFIED
    return AdministrativeTransactionState.NOT_STARTED


def _write_custody_key_exclusive(path: Path, value: bytes) -> None:
    """Exclusive-creation-only, owner-only-permission, atomic-on-failure
    write. Refuses to overwrite an existing file -- a second write
    attempt fails rather than discarding the first. Any failure after
    creation removes the incomplete file rather than leaving a
    partially-written one a later reader could misinterpret. Same
    discipline as (but an independent implementation of, not an import
    from) `pfsense_mcp.tier1.artifact_exchange.write_secure_new()` --
    see this module's own docstring for why."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise BootstrapOrchestrationError(f"secure custody file could not be created: {path}") from exc
    complete = False
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise BootstrapOrchestrationError(f"secure custody file could not be written: {path}")
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete:
            with suppress(OSError):
                path.unlink()


def _persist_service_api_key(context: AdministrativeContext, api_key: ProvisionedApiKey) -> None:
    """Persist a freshly generated service-account API key to the
    already-validated custody path so a later restart-classification
    check finds a custody artifact properly accounted for by this
    completed journal, rather than an orphaned key file."""

    try:
        _write_custody_key_exclusive(context.config.service_api_key_file, api_key.reveal().encode("utf-8"))
    except BootstrapOrchestrationError as exc:
        raise BootstrapOrchestrationError(
            "Provisioning succeeded but the generated service API key could not be persisted to its custody "
            "path; treat this as a completed-but-unrecorded key and follow manual recovery guidance."
        ) from exc


def build_authoritative_restart_observation(context: AdministrativeContext) -> AuthoritativeRestartObservation | None:
    """Read-only. Builds a *fresh* `AuthoritativeRestartObservation` from
    live evidence only -- never from the journal, never a guess.

    Every binding-identity field (`target_identity`/`target_origin`/
    `account_identity`/`approved_profile`/`schema_version`/
    `schema_evidence_digest`) is taken from `context.binding`, which
    `build_admin_context()` itself freshly (re)computes from the
    *current* configuration on every call -- not copied from any prior
    journal record. `classify_restart()` performs the actual comparison
    against the journal's own recorded binding; this function only ever
    supplies "what is true of the current configuration and the current
    live target right now."

    `server_state` is the one field genuinely derived from a live read
    (`context._mutation_components.observe_restart_state_call()`, a
    GET-only call reusing `provision_service_account()`'s own privilege
    derivation and drift comparison) -- `EXPECTED_COMPLETED` only when
    the dedicated account exists, is enabled, carries the expected
    description, holds *exactly* the expected steady-state privileges,
    and does not hold the temporary bootstrap privilege; `UNKNOWN` for
    every other observed shape, including the account not existing at
    all. `UNKNOWN` is deliberately never treated as proof of anything by
    `classify_restart()` -- only `EXPECTED_COMPLETED` combined with a
    matching binding can ever produce `CLEAN_COMPLETED`.

    Returns `None` on *any* error, transport failure, or ambiguity --
    including a duplicate-named account, a schema that can no longer be
    derived, or a network/TLS failure -- so the caller falls through to
    the existing, conservative `RECOVERY_REQUIRED` default. Never
    raises; a live read failing is exactly the case this function exists
    to fail closed on, not to propagate."""

    try:
        account, auth_methods = context._mutation_components.observe_restart_state_call()
    except Exception:  # deliberately broad: any escape from the live read is treated as "cannot verify"
        return None

    if (
        account.exists
        and account.enabled
        and account.matches_expected_description
        and account.has_exact_expected_privileges
        and not account.has_temporary_bootstrap_privilege
    ):
        server_state = AuthoritativeServerState.EXPECTED_COMPLETED
    else:
        server_state = AuthoritativeServerState.UNKNOWN

    return AuthoritativeRestartObservation(
        target_identity=context.binding.target_identity,
        target_origin=context.binding.target_origin,
        account_identity=context.binding.account_identity,
        approved_profile=context.binding.approved_profile,
        schema_version=context.binding.schema_version,
        schema_evidence_digest=context.binding.schema_evidence_digest,
        auth_methods=tuple(sorted(auth_methods)),
        server_state=server_state,
        final_verification_complete=True,
    )


def run_bootstrap_from_environment(
    env: Mapping[str, str] | None = None,
    *,
    authoritative: AuthoritativeRestartObservation | None = None,
    now: Callable[[], str] = _default_now,
    operation_id_factory: Callable[[], str] = _default_operation_id,
) -> BootstrapOrchestrationResult:
    """The one function a CLI needs: builds the fixed `AdministrativeContext`
    from `env` (defaulting to `os.environ`, matching this codebase's other
    `security_cli.py`-facing entry points, e.g. `discover_security_posture()`)
    and runs `run_bootstrap()` against it.

    This is the *only* function in this module that constructs an
    `AdministrativeContext` -- `security_cli.py` must never import
    `security_admin_composition`/`build_admin_context` directly (see this
    module's own docstring on the isolation boundary `security_cli.py`
    must preserve). A configuration/composition failure
    (`AdminCompositionError`) is caught here and reported as
    `BLOCKED_CONFIGURATION_ERROR` rather than propagating -- no lock or
    journal is ever touched in that case, since construction itself
    already failed.

    When `authoritative` is not explicitly supplied (the normal CLI
    case) *and* a local journal already exists for this target/account/
    profile (`context.journal_path.exists()`), a fresh live
    `AuthoritativeRestartObservation` is built and used -- this is the
    only way a genuinely completed prior operation can ever be
    recognized as such after a process restart (see
    `build_authoritative_restart_observation()`). A brand-new target
    with no local journal at all never triggers this extra live read --
    behavior for that case remains exactly what it always was, since
    `classify_restart()` never even inspects `authoritative` when no
    journal exists.
    """

    source = env if env is not None else os.environ
    try:
        context = build_admin_context(source)
    except AdminCompositionError as exc:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR,
            str(exc),
        )
    # `locate_bootstrap_chain_frontier()` walks forward (offline,
    # `authoritative=None`) through however many RESOLVE_UNPROVISIONED_
    # INCIDENT generations are already resolved and returns the frontier
    # -- generation 0 itself (this function's prior, unchanged behavior)
    # whenever nothing has ever been resolved. `run_bootstrap()` below
    # re-classifies `context` itself (cheap, pure, no network call), so
    # this is not a second decision source; it only decides which
    # context that second classification runs against. See that
    # function's own docstring for the full hop contract.
    frontier = locate_bootstrap_chain_frontier(context, source=source, build_context=build_admin_context)
    context = frontier.context
    if authoritative is None and context.journal_path.exists():
        authoritative = build_authoritative_restart_observation(context)
    return run_bootstrap(
        context,
        authoritative=authoritative,
        now=now,
        operation_id_factory=operation_id_factory,
    )


def run_readonly_bootstrap_from_environment(
    env: Mapping[str, str] | None = None,
    *,
    authoritative: AuthoritativeRestartObservation | None = None,
    now: Callable[[], str] = _default_now,
    operation_id_factory: Callable[[], str] = _default_operation_id,
) -> BootstrapOrchestrationResult:
    """The `read_only`-profile counterpart of `run_bootstrap_from_
    environment()` -- provisions/verifies the dedicated `pfsense-mcp-
    readonly` service account instead of the `write_protected`
    `pfsense-mcp` one (POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH
    mission, 2026-08-29).

    Deliberately as small a diff against the existing function as
    possible: `run_bootstrap()` itself is already fully generic over
    `AdministrativeContext` (it operates only on `context.binding`/
    `context._mutation_components`, never on any write_protected-
    specific assumption), so this function differs from `run_bootstrap_
    from_environment()` in exactly one line -- which context builder it
    calls. Every journal/lock/restart-classification/failure-handling
    property `run_bootstrap_from_environment()`'s own docstring
    documents applies here identically, against the read_only account's
    own, entirely separate namespace/journal/lock (see
    `security_readonly_admin_composition.py`'s own docstring for why a
    separate, fixed `_ACCOUNT_NAME` makes the two ceremonies'
    journals/locks/custody artifacts structurally incapable of
    colliding)."""

    source = env if env is not None else os.environ
    try:
        context = build_readonly_admin_context(source)
    except AdminCompositionError as exc:
        return BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR,
            str(exc),
        )
    frontier = locate_bootstrap_chain_frontier(context, source=source, build_context=build_readonly_admin_context)
    context = frontier.context
    if authoritative is None and context.journal_path.exists():
        authoritative = build_authoritative_restart_observation(context)
    return run_bootstrap(
        context,
        authoritative=authoritative,
        now=now,
        operation_id_factory=operation_id_factory,
    )
