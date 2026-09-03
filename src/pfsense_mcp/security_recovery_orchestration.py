"""ADR-033 recovery-execution orchestration -- the CLI-facing gateway for
`pfsense-mcp-security recover`, mirroring `security_bootstrap_orchestration.py`'s
own design exactly: the single, narrow bridge between a CLI and the
already-implemented, already-reviewed recovery stack
(`security_admin_composition.py`, `security_bootstrap_recovery.py`,
`security_operation_journal.py`, `security_recovery_confirmation.py`). It
does not reimplement any of their logic -- it only sequences it.

`security_cli.py` must import *only* this module for `recover`, never the
lower-level modules directly -- the same isolation discipline
`security_bootstrap_orchestration.py`'s own docstring documents for
`bootstrap`, extended here to this module's own sources.

## Why recovery uses a second, separate journal

`RECOVERY_REQUIRED` is a deliberately terminal `DurableOperationState`
(`security_operation_journal.py`'s own `_ALLOWED` map permits no further
transition out of it) -- once a bootstrap operation reaches it, that
journal remains a permanent, immutable incident record, never continued.
`AdministrativeOperationType.RECOVER_ORPHAN_KEY`/`RECOVER_DEDICATED_USER`
exist specifically so a recovery attempt gets its **own fresh journal**
(`build_admin_context(source, operation_type=...)`, composed with
`security_admin_composition.py`'s namespace extension), which drives the
identical `CREATED -> PRE_SEND_READY -> MUTATION_INTENT_RECORDED ->
FINAL_VERIFICATION_PENDING -> COMPLETED` chain `bootstrap` already uses --
already legal under the existing state machine, requiring zero change to
it. The original incident journal is only ever read here
(`.status.classify()`, `._journal.load()`), never appended to or locked.

## Two-phase control flow

**Inspect** (`execute_action=None`, the CLI's default/bare invocation):
read-only. Classifies the *bootstrap* journal; if `RECOVERY_REQUIRED`,
classifies the *recovery-typed* journal (never attempted / already
complete / ambiguous), and if never attempted, performs one authoritative
**read** (via `identify_orphan_key_candidate`/`identify_dedicated_user_candidate`
-- read-only by construction, see `security_bootstrap_recovery.py`) to
resolve the current candidate object and derive the confirmation token
this exact incident/object/target/action combination requires. Makes no
mutating call under any circumstance.

**Execute** (`execute_action` + `confirm_token` both given): re-derives
the same read-only classification and candidate resolution as inspect,
compares `execute_action` against the required action and `confirm_token`
against the freshly re-derived expected token -- **both checks happen
before the lock is acquired and before any mutating call** -- then drives
the recovery-typed journal through its own state machine around exactly
one call to `context._mutation_components.revoke_orphan_key_call()` or
`.delete_dedicated_user_call()`. A crash mid-call leaves the journal at
`MUTATION_INTENT_RECORDED` and the lock held, exactly mirroring
`run_bootstrap()`'s own crash behavior -- no auto-retry, no automatic
resumption; a subsequent inspect reports `BLOCKED_AMBIGUOUS_RECOVERY_STATE`
and requires direct operator intervention.

The confirmation token itself never weakens, replaces, or is consulted by
any of `revoke_failed_bootstrap_api_key()`/`delete_dedicated_recovery_user()`'s
own existing identity/ownership/reread/postcondition checks -- both still
run unconditionally, unchanged, on every execution.
"""

from __future__ import annotations

import os
import secrets
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import Enum

from .errors import PfSenseMCPError
from .security_admin_composition import AdminCompositionError, AdministrativeContext, build_admin_context
from .security_bootstrap_client import ObservedApiKey, ObservedUser
from .security_bootstrap_recovery import RecoveryDeletionEvidence, UnprovisionedIncidentEvidence
from .security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    DurableOperationState,
    OperationJournalError,
    OperationLockError,
    RecoveryAction,
    RestartClassification,
    derive_resolution_operation_id,
)
from .security_readonly_admin_composition import build_readonly_admin_context
from .security_recovery_confirmation import (
    RecoveryIncidentBinding,
    confirmation_token_matches,
    derive_confirmation_token,
    object_fingerprint,
)

__all__ = [
    "RecoveryAction",
    "RecoveryOrchestrationError",
    "RecoveryOrchestrationOutcome",
    "RecoveryOrchestrationResult",
    #: Re-exported so security_cli.py (which must never import
    #: security_bootstrap_recovery.py directly) can distinguish this
    #: `RecoveryOrchestrationResult.evidence` shape from
    #: `RecoveryDeletionEvidence`'s when formatting output.
    "UnprovisionedIncidentEvidence",
    "run_recovery_from_environment",
]


class RecoveryOrchestrationError(PfSenseMCPError):
    """Raised only for programmer-error-shaped misuse of this module
    (e.g. a caller-supplied now/operation-id factory that itself raises).
    Never raised for an ordinary recovery outcome -- those are reported
    via `RecoveryOrchestrationResult`, not an exception."""


class RecoveryOrchestrationOutcome(str, Enum):
    """Exhaustive, CLI-mappable result category -- mirrors
    `BootstrapOrchestrationOutcome`'s own deliberately non-collapsing
    design."""

    #: No recovery action is currently recorded; nothing to do.
    NO_RECOVERY_NEEDED = "no_recovery_needed"
    #: Recovery is required and has never been attempted. Inspection-only
    #: result: the required action, the candidate object, and a fresh
    #: confirmation token are reported. No mutation was made.
    RECOVERY_NEEDED = "recovery_needed"
    #: This exact incident's recovery action already completed and
    #: verified; re-running inspection is idempotent.
    RECOVERY_ALREADY_COMPLETE = "recovery_already_complete"
    #: A prior recovery attempt for this incident is itself in a
    #: non-terminal state (crashed, ambiguous, or otherwise incomplete).
    #: No automatic retry is ever attempted; manual review is required.
    BLOCKED_AMBIGUOUS_RECOVERY_STATE = "blocked_ambiguous_recovery_state"
    #: The read-only candidate-identification read found zero or more
    #: than one matching object (or another closed-primitive precondition
    #: failed) -- refused before any token was issued or any mutation
    #: attempted.
    BLOCKED_CANDIDATE_NOT_IDENTIFIABLE = "blocked_candidate_not_identifiable"
    #: `build_admin_context()` itself refused this environment/configuration.
    BLOCKED_CONFIGURATION_ERROR = "blocked_configuration_error"
    #: `--execute <ACTION>` does not match the action this incident
    #: actually requires -- refused before any HTTP call.
    EXECUTE_ACTION_MISMATCH = "execute_action_mismatch"
    #: The supplied confirmation token is missing, malformed, or does not
    #: match what this exact target/action/object/incident currently
    #: requires -- refused before any HTTP call.
    EXECUTE_TOKEN_INVALID = "execute_token_invalid"  # nosec B105 -- an outcome enum value, not a credential
    #: Another operation (bootstrap or a concurrent recovery attempt for
    #: this same action) holds the recovery-typed lock.
    BLOCKED_LOCK_CONTENTION = "blocked_lock_contention"
    #: Local journal/lock state for the recovery-typed operation is
    #: corrupt or unauthenticated.
    BLOCKED_CORRUPT_LOCAL_STATE = "blocked_corrupt_local_state"
    #: Execution was attempted (all gates passed) and the underlying
    #: recovery primitive raised -- no mutation was performed, per that
    #: primitive's own fail-closed contract. The lock is held pending
    #: manual review.
    RECOVERY_EXECUTION_FAILED = "recovery_execution_failed"
    #: Verified success.
    RECOVERY_COMPLETED = "recovery_completed"


@dataclass(frozen=True)
class RecoveryOrchestrationResult:
    """Structured, secret-free outcome of one `run_recovery_from_environment()`
    call. Never carries an API key, password, or any other secret --
    `confirmation_token` is a derived confirmation artifact, not a
    credential, and `evidence` (when present) is already the sanitized
    `RecoveryDeletionEvidence` the underlying primitive returns."""

    outcome: RecoveryOrchestrationOutcome
    detail: str
    operation_id: str | None = None
    recovery_action: RecoveryAction | None = None
    confirmation_token: str | None = None
    evidence: RecoveryDeletionEvidence | UnprovisionedIncidentEvidence | None = None


_ACTION_TO_OPERATION_TYPE = {
    RecoveryAction.REVOKE_ORPHAN_KEY: AdministrativeOperationType.RECOVER_ORPHAN_KEY,
    RecoveryAction.DELETE_DEDICATED_USER: AdministrativeOperationType.RECOVER_DEDICATED_USER,
    RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT: AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT,
}


def _default_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _default_operation_id() -> str:
    return secrets.token_hex(16)


def run_recovery_from_environment(
    env: Mapping[str, str] | None = None,
    *,
    target_profile: str = "write_protected",
    execute_action: RecoveryAction | None = None,
    confirm_token: str | None = None,
    now: Callable[[], str] = _default_now,
    operation_id_factory: Callable[[], str] = _default_operation_id,
) -> RecoveryOrchestrationResult:
    """The one function a CLI needs. `env` defaults to `os.environ`,
    matching `run_bootstrap_from_environment()`'s own convention.

    `target_profile` (`"write_protected"` or `"read_only"`, mirroring
    `pfsense-mcp-security bootstrap --target-profile`) selects which of
    the two, entirely separate, namespaced administrative contexts
    (`build_admin_context()` for the ADR-033 `pfsense-mcp` account,
    `build_readonly_admin_context()` for `pfsense-mcp-readonly`) this
    call inspects/recovers -- both builders return the same
    `AdministrativeContext` shape, so every line below this point is
    unchanged regardless of which was built (`security_readonly_admin_
    composition.py`'s own docstring on why the two accounts'
    journals/locks/custody artifacts are structurally incapable of
    colliding). Added for the POST-v1.0 MANAGED READ-ONLY WIZARD
    INTEGRATION mission (2026-08-29): before this, a managed read_only
    `setup apply` hitting `BLOCKED_PRIOR_OPERATION` had no correct way
    to inline-inspect its own account's incident -- calling this
    function unparameterized would have silently inspected the
    unrelated `pfsense-mcp` (write_protected) journal instead, which
    would have been actively misleading.

    `execute_action=None` (the default) is inspection-only: no lock is
    acquired, no journal is written, no mutating call is ever made.
    Passing `execute_action` without a matching, currently-valid
    `confirm_token` always fails closed at `EXECUTE_TOKEN_INVALID`,
    before any mutating call.
    """

    source = env if env is not None else os.environ
    build_context = build_readonly_admin_context if target_profile == "read_only" else build_admin_context
    try:
        bootstrap_context = build_context(source)
    except AdminCompositionError as exc:
        return RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))

    decision = bootstrap_context.status.classify(authoritative=None)
    if decision.classification is RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            "Local journal, lock, or custody-artifact state for the incident is corrupt or untrusted; "
            "refusing to inspect or execute recovery.",
            operation_id=decision.operation_id,
        )
    if decision.classification is not RestartClassification.RECOVERY_REQUIRED:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED,
            "No ADR-033 recovery action is currently recorded for this target/account/profile.",
            operation_id=decision.operation_id,
        )
    recovery_action = decision.recovery_action
    if recovery_action is None:
        # classify_restart() reports RECOVERY_REQUIRED whenever no fresh
        # authoritative observation is available, for *any* pre-existing
        # journal -- not only one whose own DurableOperationState reached
        # the terminal RECOVERY_REQUIRED state (see classify_restart()'s
        # own docstring/branches). When the journal never reached that
        # terminal state (e.g. it failed during pre-flight observation,
        # before any mutation was ever attempted), `recovery_action` is
        # correctly `None` -- there is no closed orphan-key/dedicated-user
        # primitive to name, because nothing was created.
        #
        # This is exactly the class of incident RESOLVE_UNPROVISIONED_
        # INCIDENT exists for -- but naming it here is only a hypothesis,
        # never a conclusion: the evidence-gathering read below
        # (`identify_unprovisioned_incident_evidence_call()`) is the actual
        # gate. If the intended account or an orphan key turns out to
        # still exist, or any read is ambiguous, that call raises and this
        # falls through to `BLOCKED_CANDIDATE_NOT_IDENTIFIABLE` a few lines
        # down -- never silently reinterpreted as "no recovery needed" or
        # "resolved" without fresh proof. This must never contradict
        # classify_restart()'s own conservative intent, nor let
        # `bootstrap`'s independent restart check (which blocks on this
        # exact classification) disagree with what `recover` concludes here.
        recovery_action = RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
    incident_operation_id = decision.operation_id
    if incident_operation_id is None:
        # classify_restart() never returns RECOVERY_REQUIRED without an
        # operation_id -- defensive, not reachable via any known path.
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            "Recovery is required but no incident operation id was recorded.",
            recovery_action=recovery_action,
        )

    try:
        incident_snapshot = bootstrap_context._journal.load()
    except OperationJournalError as exc:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            f"Could not re-read the incident journal to bind a confirmation token: {exc}",
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )
    incident_record_mac = incident_snapshot.latest.mac

    operation_type = _ACTION_TO_OPERATION_TYPE[recovery_action]
    try:
        recovery_context = build_context(source, operation_type=operation_type)
    except AdminCompositionError as exc:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR,
            str(exc),
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    recovery_decision = recovery_context.status.classify(authoritative=None)
    if recovery_decision.classification is not RestartClassification.CLEAN_NO_OPERATION:
        # A recovery-typed journal already exists. classify_restart() is
        # deliberately conservative when authoritative=None (this CLI's
        # only mode): it reports RECOVERY_REQUIRED for *any* pre-existing
        # journal, completed or not -- the same documented limitation
        # already accepted for `bootstrap` itself (see
        # security_bootstrap_orchestration.py's own module docstring).
        # Determine precisely whether *this* journal actually reached
        # COMPLETED by reading it directly -- a narrower, more specific
        # check this orchestration layer owns, not a change to
        # classify_restart()'s own shared, tested logic.
        try:
            recovery_snapshot = recovery_context._journal.load()
        except OperationJournalError as exc:
            return RecoveryOrchestrationResult(
                RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
                f"Could not re-read the recovery journal: {exc}",
                operation_id=incident_operation_id,
                recovery_action=recovery_action,
            )
        if recovery_snapshot.latest.state is DurableOperationState.COMPLETED:
            return RecoveryOrchestrationResult(
                RecoveryOrchestrationOutcome.RECOVERY_ALREADY_COMPLETE,
                f"The {recovery_action.value} recovery action for this incident is already recorded complete.",
                operation_id=incident_operation_id,
                recovery_action=recovery_action,
            )
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_AMBIGUOUS_RECOVERY_STATE,
            f"A prior {recovery_action.value} recovery attempt's own state "
            f"({recovery_snapshot.latest.state.value}) requires manual review before any further attempt.",
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    try:
        candidate: ObservedApiKey | ObservedUser | UnprovisionedIncidentEvidence
        if recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY:
            candidate = recovery_context._mutation_components.identify_orphan_key_candidate()
        elif recovery_action is RecoveryAction.DELETE_DEDICATED_USER:
            candidate = recovery_context._mutation_components.identify_dedicated_user_candidate()
        else:
            candidate = recovery_context._mutation_components.identify_unprovisioned_incident_evidence_call()
    except Exception as exc:  # deliberately broad: any escape (including a transport-level
        # failure like a DNS/connect error, not only BootstrapProvisioningError) is treated as
        # ambiguous rather than propagating uncaught -- matching _run_recovery_locked()'s own
        # "deliberately broad" mutation-call catch a few lines below, for the identical reason:
        # this is a read-only network call and every caller of this function (including
        # security_setup_apply.py's inline recovery delegation) must always get back a
        # structured RecoveryOrchestrationResult, never an unhandled exception.
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE,
            str(exc),
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    binding = RecoveryIncidentBinding(
        target_origin=bootstrap_context.binding.target_origin,
        target_identity=bootstrap_context.binding.target_identity,
        recovery_action=recovery_action,
        object_fingerprint=object_fingerprint(candidate),
        incident_operation_id=incident_operation_id,
        incident_record_mac=incident_record_mac,
    )
    integrity_key = recovery_context._mutation_components.journal_integrity_key
    expected_token = derive_confirmation_token(binding, integrity_key=integrity_key)

    if execute_action is None:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_NEEDED,
            f"Recovery action needed: {recovery_action.value}.",
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
            confirmation_token=expected_token,
        )

    if execute_action is not recovery_action:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.EXECUTE_ACTION_MISMATCH,
            f"--execute {execute_action.value} does not match the required action {recovery_action.value}; "
            "refusing before any mutation.",
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    if not confirmation_token_matches(confirm_token, binding, integrity_key=integrity_key):
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID,
            "Confirmation token is missing, malformed, stale, or does not match the current target/action/"
            "object/incident; refusing before any mutation.",
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    # RESOLVE_UNPROVISIONED_INCIDENT's own resolution journal must use the
    # *deterministic* operation_id derived from the incident it resolves
    # (`derive_resolution_operation_id()`), never a random one -- that
    # deterministic binding is exactly what lets a bootstrap retry later
    # prove, from the resolution journal's own operation_id alone, that it
    # was computed for *this* incident and no other. The two pre-existing
    # recovery actions have no such retry-binding requirement (see
    # `security_bootstrap_recovery.py`'s own docstring on why neither ever
    # unblocks a bootstrap retry), so they keep using a fresh random id.
    operation_id = (
        derive_resolution_operation_id(
            incident_operation_id=incident_operation_id, incident_record_mac=incident_record_mac
        )
        if recovery_action is RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
        else operation_id_factory()
    )
    timestamp = now()
    try:
        recovery_context._lock.acquire(operation_id, timestamp=timestamp)
    except OperationLockError as exc:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_LOCK_CONTENTION,
            str(exc),
            operation_id=incident_operation_id,
            recovery_action=recovery_action,
        )

    try:
        return _run_recovery_locked(
            recovery_context, recovery_action=recovery_action, operation_id=operation_id, timestamp=timestamp, now=now
        )
    except OperationJournalError as exc:
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
            f"Operation journal error: {exc}",
            operation_id=operation_id,
            recovery_action=recovery_action,
        )


def _run_recovery_locked(
    context: AdministrativeContext,
    *,
    recovery_action: RecoveryAction,
    operation_id: str,
    timestamp: str,
    now: Callable[[], str],
) -> RecoveryOrchestrationResult:
    operation_type = _ACTION_TO_OPERATION_TYPE[recovery_action]
    binding = context.new_operation_binding(operation_id=operation_id, operation_type=operation_type)
    context._journal.create(binding, timestamp=timestamp)
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.RECOVERY_OBJECT_IDENTIFIED,
        mutation_index=1,
        timestamp=now(),
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
        mutation_index=1,
        timestamp=now(),
    )

    call: Callable[[], RecoveryDeletionEvidence] | Callable[[], UnprovisionedIncidentEvidence]
    if recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY:
        call = context._mutation_components.revoke_orphan_key_call
    elif recovery_action is RecoveryAction.DELETE_DEDICATED_USER:
        call = context._mutation_components.delete_dedicated_user_call
    else:
        # Not a pfSense-side mutation -- a fresh, independent re-read of
        # the same two-reads-agree evidence the inspect path already
        # gathered once. Re-verifying immediately before COMPLETED (rather
        # than trusting the earlier read) matches the same "reread before
        # committing" discipline `revoke_failed_bootstrap_api_key()`/
        # `delete_dedicated_recovery_user()` already apply internally.
        call = context._mutation_components.identify_unprovisioned_incident_evidence_call
    try:
        evidence = call()
    except Exception as exc:  # deliberately broad: any escape is treated as ambiguous, matching run_bootstrap()
        context._journal.append(
            operation_id=operation_id,
            state=DurableOperationState.MUTATION_RESULT_UNKNOWN,
            transaction_state=AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
            mutation_index=1,
            timestamp=now(),
        )
        return RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED,
            f"An unexpected error occurred during {recovery_action.value} recovery ({type(exc).__name__}); "
            "the operation lock is held pending manual investigation.",
            operation_id=operation_id,
            recovery_action=recovery_action,
        )

    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.FINAL_VERIFICATION_PENDING,
        transaction_state=AdministrativeTransactionState.RECOVERY_VERIFIED,
        mutation_index=1,
        timestamp=now(),
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.COMPLETED,
        transaction_state=AdministrativeTransactionState.RECOVERY_VERIFIED,
        mutation_index=1,
        timestamp=now(),
    )
    context._lock.release(timestamp=now())
    return RecoveryOrchestrationResult(
        RecoveryOrchestrationOutcome.RECOVERY_COMPLETED,
        f"{recovery_action.value} recovery completed and verified.",
        operation_id=operation_id,
        recovery_action=recovery_action,
        evidence=evidence,
    )
