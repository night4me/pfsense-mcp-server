"""ADR-033 recovery-execution orchestration test matrix.

Reuses `security_admin_composition.py`'s real, fully-validated
`AdministrativeContext` composition (real journal/lock files under
`tmp_path`, no network) but stubs the recovery-typed context's
`_mutation_components.identify_orphan_key_candidate`/
`identify_dedicated_user_candidate`/`revoke_orphan_key_call`/
`delete_dedicated_user_call` closures to synthetic values -- the
underlying HTTP-level recovery primitives already have their own
dedicated adversarial test suite (`test_security_bootstrap_recovery.py`)
and are not re-tested here. This file focuses on what the orchestration
layer itself adds: two-journal sequencing, confirmation-token gating,
crash/idempotency handling, and secret-safety.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import AdministrativeContext, build_admin_context
from pfsense_mcp.security_bootstrap_client import ObservedApiKey, ObservedUser
from pfsense_mcp.security_bootstrap_recovery import RecoveryDeletionEvidence, UnprovisionedIncidentEvidence
from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    DurableOperationState,
    RecoveryAction,
    derive_resolution_operation_id,
)
from pfsense_mcp.security_recovery_orchestration import (
    RecoveryOrchestrationOutcome,
    run_recovery_from_environment,
)

T0 = "2026-08-23T00:00:00Z"


class _Clock:
    def __init__(self) -> None:
        self._seconds = 0

    def __call__(self) -> str:
        self._seconds += 1
        hour, remainder = divmod(self._seconds, 3600)
        minute, second = divmod(remainder, 60)
        return f"2026-08-23T{hour:02d}:{minute:02d}:{second:02d}Z"


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


@pytest.fixture
def now() -> _Clock:
    return _Clock()


@pytest.fixture
def admin_env(tmp_path: Path) -> dict[str, str]:
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    custody = tmp_path / "custody"
    custody.mkdir(mode=0o700)
    schema = tmp_path / "schema.json"
    fixture = Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
    _write_secure(schema, fixture.read_bytes())
    _write_secure(tmp_path / "admin-api-key", b"synthetic-admin-key\n")
    _write_secure(tmp_path / "admin-password", b"synthetic-admin-password\n")
    _write_secure(tmp_path / "journal-key", b"j" * 32)
    _write_secure(tmp_path / "ca.pem", b"synthetic-ca", mode=0o644)
    return {
        "PFSENSE_API_URL": "https://lab.example.invalid",
        "PFSENSE_IDENTITY": "lab-appliance-one",
        "PFSENSE_API_KEY_FILE": str(tmp_path / "admin-api-key"),
        "PFSENSE_TLS_MODE": "auto",
        "PFSENSE_TLS_CA_FILE": str(tmp_path / "ca.pem"),
        "PFSENSE_API_VERSION": "v2",
        "PFSENSE_ADMIN_USERNAME": "admin",
        "PFSENSE_ADMIN_PASSWORD_FILE": str(tmp_path / "admin-password"),
        "PFSENSE_SERVICE_API_KEY_FILE": str(custody / "pfsense-mcp.key"),
        "PFSENSE_ADMIN_STATE_DIR": str(state),
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE": str(tmp_path / "journal-key"),
        "PFSENSE_ADMIN_SCHEMA_FILE": str(schema),
        "PFSENSE_ADMIN_SCHEMA_VERSION": "restapi-v2.10",
        "PFSENSE_RESTAPI_PACKAGE_VERSION": "2.10.0",
    }


_KEY = ObservedApiKey(
    id=7, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
)
_USER = ObservedUser(
    id=9,
    name="pfsense-mcp",
    descr="Dedicated service account for pfsense-mcp-server",
    priv=frozenset({"p"}),
    disabled=False,
    scope="user",
)


def _create_bootstrap_incident(
    context: AdministrativeContext, *, recovery_action: RecoveryAction, operation_id: str = "incident-1"
) -> None:
    """Drive `context`'s (bootstrap-typed) journal to RECOVERY_REQUIRED,
    exactly matching the shape `run_bootstrap()` itself would leave behind
    on a failed run."""

    binding = context.new_operation_binding(
        operation_id=operation_id, operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    context._journal.create(binding, timestamp=T0)
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:01Z",
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:02Z",
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.RECOVERY_REQUIRED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:03Z",
        recovery_action=recovery_action,
    )


@dataclass(frozen=True)
class _RaisingCounter:
    exc: Exception

    def __call__(self):
        raise self.exc


def _rig(
    monkeypatch,
    admin_env: dict[str, str],
    *,
    recovery_action: RecoveryAction | None,
    identify_orphan_key_candidate=lambda: _KEY,
    identify_dedicated_user_candidate=lambda: _USER,
    revoke_orphan_key_call=None,
    delete_dedicated_user_call=None,
):
    """Build real bootstrap + recovery contexts (real journal/lock files,
    no network), optionally prime the bootstrap journal to
    RECOVERY_REQUIRED for `recovery_action`, stub the recovery context's
    HTTP-level closures, and monkeypatch `build_admin_context` (as
    imported into the orchestration module) to hand back these two
    doctored contexts based on the requested operation_type -- exactly
    the same real-context/faked-closure pattern
    `test_security_bootstrap_orchestration.py` already establishes."""

    bootstrap_context = build_admin_context(admin_env)
    if recovery_action is not None and not bootstrap_context.journal_path.exists():
        _create_bootstrap_incident(bootstrap_context, recovery_action=recovery_action)

    operation_type = (
        {
            RecoveryAction.REVOKE_ORPHAN_KEY: AdministrativeOperationType.RECOVER_ORPHAN_KEY,
            RecoveryAction.DELETE_DEDICATED_USER: AdministrativeOperationType.RECOVER_DEDICATED_USER,
        }[recovery_action]
        if recovery_action is not None
        else AdministrativeOperationType.RECOVER_ORPHAN_KEY
    )
    recovery_context = build_admin_context(admin_env, operation_type=operation_type)
    components = replace(
        recovery_context._mutation_components,
        identify_orphan_key_candidate=identify_orphan_key_candidate,
        identify_dedicated_user_candidate=identify_dedicated_user_candidate,
        revoke_orphan_key_call=revoke_orphan_key_call or (lambda: pytest.fail("unexpected revoke call")),
        delete_dedicated_user_call=delete_dedicated_user_call or (lambda: pytest.fail("unexpected delete call")),
    )
    recovery_context = replace(recovery_context, _mutation_components=components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP):
        return bootstrap_context if operation_type is AdministrativeOperationType.BOOTSTRAP else recovery_context

    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_admin_context", fake_build)
    return bootstrap_context, recovery_context


# --- No recovery needed ------------------------------------------------------


def test_no_recovery_needed_when_bootstrap_journal_is_clean(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=None)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED
    assert result.confirmation_token is None


def test_recovery_required_classification_with_no_recovery_action_is_blocked_not_silently_cleared(
    admin_env, monkeypatch, now
):
    """Reproduces the exact disagreement observed against production
    (operation_id a41c6a538c60ecd1bcba2dbb97df5152): a bootstrap attempt
    that fails during pre-flight observation -- before any transition
    past CREATED -- leaves a journal whose *own* DurableOperationState
    never reaches RECOVERY_REQUIRED, so its `recovery_action` is
    legitimately `None`. `classify_restart(authoritative=None)` still
    reports `RestartClassification.RECOVERY_REQUIRED` for this journal
    (its own documented conservative behavior: any pre-existing journal,
    with no fresh authoritative evidence, requires attention) -- exactly
    the same call `bootstrap`'s own restart check makes, which blocks
    (`blocked_prior_operation`). Before the original fix, `run_recovery_
    from_environment()` silently collapsed this exact combination into
    `NO_RECOVERY_NEEDED`, directly contradicting `bootstrap`'s own
    blocking decision for the identical journal.

    Since RESOLVE_UNPROVISIONED_INCIDENT was added, this exact
    `recovery_action is None` combination is no longer an automatic dead
    end -- it is the one case that action exists for. But it must still
    never be treated as automatically resolvable: the fresh evidence-
    gathering read is the real gate. Here it fails (representing the
    fixed dedicated account still existing on the target), so the result
    must be a fail-closed BLOCKED_CANDIDATE_NOT_IDENTIFIABLE -- still
    never `NO_RECOVERY_NEEDED`, and never a fabricated success."""

    bootstrap_context = build_admin_context(admin_env)
    binding = bootstrap_context.new_operation_binding(
        operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    bootstrap_context._journal.create(binding, timestamp=T0)

    resolution_context = build_admin_context(
        admin_env, operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT
    )
    from pfsense_mcp.errors import BootstrapProvisioningError

    def _raise_still_provisioned():
        raise BootstrapProvisioningError(
            "identify_unprovisioned_incident_evidence: the fixed dedicated account exists; no resolution performed."
        )

    components = replace(
        resolution_context._mutation_components,
        identify_unprovisioned_incident_evidence_call=_raise_still_provisioned,
    )
    resolution_context = replace(resolution_context, _mutation_components=components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP):
        if operation_type is AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT:
            return resolution_context
        return bootstrap_context

    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_admin_context", fake_build)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE
    assert result.operation_id == "incident-1"
    assert result.recovery_action is RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
    assert result.confirmation_token is None
    assert "the fixed dedicated account exists" in result.detail


# --- Inspect (surface-only) ---------------------------------------------------


def test_inspect_reports_orphan_key_recovery_needed_and_issues_a_token_without_mutating(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert result.recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY
    assert result.confirmation_token is not None
    assert result.evidence is None


def test_inspect_reports_dedicated_user_recovery_needed_and_issues_a_token_without_mutating(
    admin_env, monkeypatch, now
):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.DELETE_DEDICATED_USER)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert result.recovery_action is RecoveryAction.DELETE_DEDICATED_USER
    assert result.confirmation_token is not None


def test_inspect_never_touches_the_recovery_journal_or_lock(admin_env, monkeypatch, now):
    _, recovery_context = _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    run_recovery_from_environment(admin_env, now=now)

    assert not recovery_context.journal_path.exists()
    assert not recovery_context.lock_path.exists()


def test_inspect_refuses_when_candidate_is_not_identifiable(admin_env, monkeypatch, now):
    def _raise():
        from pfsense_mcp.errors import BootstrapProvisioningError

        raise BootstrapProvisioningError("identify_orphan_api_key_candidate: expected exactly one matching orphan key.")

    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY, identify_orphan_key_candidate=_raise)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE
    assert result.confirmation_token is None


# --- Configuration errors -----------------------------------------------------


def test_blocked_configuration_error_on_malformed_environment(now):
    result = run_recovery_from_environment({}, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR


# --- Journal corruption -------------------------------------------------------
#
# `build_admin_context()` already catches file-level journal corruption at
# construction time (see test_corrupt_journal_and_lock_fail_during_composition
# in test_security_admin_composition.py) and raises AdminCompositionError --
# routed here to BLOCKED_CONFIGURATION_ERROR, not BLOCKED_CORRUPT_LOCAL_STATE.
# BLOCKED_CORRUPT_LOCAL_STATE exists for the narrower case this orchestration
# layer's own direct `._journal.load()` calls can independently fail on
# (a TOCTOU-style race between successful construction and a later read) --
# exercised directly here since fabricating a real race is not reproducible.


def test_blocked_corrupt_local_state_when_incident_journal_reread_fails(admin_env, monkeypatch, now):
    from pfsense_mcp.security_operation_journal import OperationJournalError

    bootstrap_context, _ = _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    def raise_on_load():
        raise OperationJournalError("journal corrupted between construction and read")

    monkeypatch.setattr(bootstrap_context._journal, "load", raise_on_load)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE


def test_blocked_corrupt_local_state_when_recovery_journal_reread_fails(admin_env, monkeypatch, now):
    from pfsense_mcp.security_operation_journal import OperationJournalError

    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: _evidence("api_key"),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)
    run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    def raise_on_load():
        raise OperationJournalError("journal corrupted between construction and read")

    monkeypatch.setattr(recovery_context._journal, "load", raise_on_load)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE


# --- Execution gating: action mismatch / token invalid ------------------------


def test_execute_refuses_action_mismatch_before_any_mutation(admin_env, monkeypatch, now):
    calls: list[str] = []
    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        delete_dedicated_user_call=lambda: calls.append("delete") or pytest.fail("must not be called"),
    )

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.DELETE_DEDICATED_USER, confirm_token="whatever", now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_ACTION_MISMATCH
    assert calls == []


def test_execute_refuses_missing_token(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=None, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID


def test_execute_refuses_wrong_token(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token="0" * 64, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID


def test_execute_refuses_malformed_token(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token="not-a-hex-token", now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID


def test_execute_refuses_token_from_a_different_target(admin_env, monkeypatch, now, tmp_path):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)
    inspect_result = run_recovery_from_environment(admin_env, now=now)
    stolen_token = inspect_result.confirmation_token

    other_env = dict(admin_env)
    other_env["PFSENSE_API_URL"] = "https://other.example.invalid"
    _rig(monkeypatch, other_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)

    result = run_recovery_from_environment(
        other_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=stolen_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID


def test_execute_refuses_token_when_the_object_changed_since_inspection(admin_env, monkeypatch, now):
    _rig(monkeypatch, admin_env, recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY)
    inspect_result = run_recovery_from_environment(admin_env, now=now)
    stale_token = inspect_result.confirmation_token

    changed_key = ObservedApiKey(
        id=8, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
    )
    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        identify_orphan_key_candidate=lambda: changed_key,
    )

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=stale_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID


def test_no_mutation_call_is_made_when_execution_gates_fail(admin_env, monkeypatch, now):
    calls: list[str] = []
    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: calls.append("revoke") or pytest.fail("must not be called"),
    )

    run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token="bad", now=now
    )

    assert calls == []


# --- Successful execution -----------------------------------------------------


def _evidence(kind: str) -> RecoveryDeletionEvidence:
    return RecoveryDeletionEvidence(
        object_kind=kind,
        selected_id=1,
        objects_before=2,
        objects_after=1,
        verified_absent=True,
        unrelated_objects_preserved=True,
    )


def test_execute_succeeds_for_revoke_orphan_key_and_closes_its_own_journal(admin_env, monkeypatch, now):
    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: _evidence("api_key"),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_COMPLETED
    assert result.evidence is not None
    assert result.evidence.object_kind == "api_key"
    snapshot = recovery_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.COMPLETED
    assert snapshot.latest.transaction_state is AdministrativeTransactionState.RECOVERY_VERIFIED
    assert recovery_context._lock.inspect().state.value == "released"


def test_execute_succeeds_for_delete_dedicated_user(admin_env, monkeypatch, now):
    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.DELETE_DEDICATED_USER,
        delete_dedicated_user_call=lambda: _evidence("user"),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)

    result = run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.DELETE_DEDICATED_USER,
        confirm_token=inspect.confirmation_token,
        now=now,
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_COMPLETED
    assert result.evidence.object_kind == "user"


def test_original_incident_journal_is_never_modified_by_a_successful_recovery(admin_env, monkeypatch, now):
    bootstrap_context, _ = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: _evidence("api_key"),
    )
    before = bootstrap_context._journal.load()

    inspect = run_recovery_from_environment(admin_env, now=now)
    run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    after = bootstrap_context._journal.load()
    assert after == before
    assert after.latest.state is DurableOperationState.RECOVERY_REQUIRED


# --- Execution failure ---------------------------------------------------------


def test_execute_failure_leaves_lock_held_and_journal_at_mutation_result_unknown(admin_env, monkeypatch, now):
    from pfsense_mcp.errors import BootstrapProvisioningError

    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=_RaisingCounter(BootstrapProvisioningError("postcondition failed")),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED
    snapshot = recovery_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN
    # Still held by this same process/lock object (never released on
    # failure, by design) -- a fresh inspect() from the *same* process
    # correctly reports active_held (its own open descriptor still holds
    # the flock), not active_stale (which only appears once the holding
    # process has actually exited and the OS has released the flock).
    assert recovery_context._lock.inspect().state.value == "active_held"


def test_unexpected_exception_during_execution_is_treated_like_any_other_failure(admin_env, monkeypatch, now):
    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=_RaisingCounter(RuntimeError("boom")),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED
    assert "boom" not in result.detail
    snapshot = recovery_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN


# --- Idempotency / recovery-of-recovery (fail-closed, no auto-retry) ----------


def test_rerun_after_completed_recovery_is_idempotent(admin_env, monkeypatch, now):
    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: _evidence("api_key"),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)
    run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_ALREADY_COMPLETE
    assert result.confirmation_token is None


def test_rerun_after_ambiguous_recovery_state_requires_manual_review_not_auto_retry(admin_env, monkeypatch, now):
    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=_RaisingCounter(RuntimeError("crash mid-call")),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)
    run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_AMBIGUOUS_RECOVERY_STATE
    assert result.confirmation_token is None
    # The journal was not silently cleaned up or retried into a new attempt.
    snapshot = recovery_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN


def test_lock_contention_between_two_concurrent_recovery_attempts(admin_env, monkeypatch, now):
    from pfsense_mcp.security_operation_journal import OperationLockError

    _, recovery_context = _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=lambda: _evidence("api_key"),
    )
    inspect = run_recovery_from_environment(admin_env, now=now)

    # Simulate a genuinely concurrent second recovery attempt racing to
    # acquire the same recovery-typed lock -- exercised directly at the
    # acquire() call (the exact seam run_recovery_from_environment()
    # itself calls), rather than by fabricating an orphaned lock-without-
    # journal state, which classify_restart() would (correctly, by its
    # own existing design) instead flag as CORRUPT_OR_UNTRUSTED_LOCAL_STATE
    # -- a different, already-covered scenario, not lock contention.
    def raise_contention(operation_id, *, timestamp):
        raise OperationLockError("Another ADR-033 administrative operation holds the local lock")

    monkeypatch.setattr(recovery_context._lock, "acquire", raise_contention)

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_LOCK_CONTENTION


# --- Secret-safety --------------------------------------------------------------


def test_no_secret_leaks_into_any_result_detail_across_the_matrix(admin_env, monkeypatch, now):
    canary = "SECRET-CANARY-DO-NOT-LEAK"

    def _raise_with_canary():
        raise RuntimeError(f"failed near {canary}")

    _rig(
        monkeypatch,
        admin_env,
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
        revoke_orphan_key_call=_raise_with_canary,
    )
    inspect = run_recovery_from_environment(admin_env, now=now)
    assert canary not in (inspect.detail or "")

    result = run_recovery_from_environment(
        admin_env, execute_action=RecoveryAction.REVOKE_ORPHAN_KEY, confirm_token=inspect.confirmation_token, now=now
    )
    assert canary not in (result.detail or "")


# --- RESOLVE_UNPROVISIONED_INCIDENT ------------------------------------------


def _rig_unprovisioned(monkeypatch, admin_env, *, identify_unprovisioned_incident_evidence_call):
    """Mirrors `_rig()`'s real-context/faked-closure pattern, but for the
    one recovery action whose triggering condition is a bootstrap journal
    that never reaches its own terminal RECOVERY_REQUIRED state at all
    (so `_create_bootstrap_incident()` -- which requires a closed
    `recovery_action` to write that terminal record -- does not apply)."""

    bootstrap_context = build_admin_context(admin_env)
    binding = bootstrap_context.new_operation_binding(
        operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    bootstrap_context._journal.create(binding, timestamp=T0)

    resolution_context = build_admin_context(
        admin_env, operation_type=AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT
    )
    components = replace(
        resolution_context._mutation_components,
        identify_unprovisioned_incident_evidence_call=identify_unprovisioned_incident_evidence_call,
    )
    resolution_context = replace(resolution_context, _mutation_components=components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP):
        if operation_type is AdministrativeOperationType.RECOVER_UNPROVISIONED_INCIDENT:
            return resolution_context
        return bootstrap_context

    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_admin_context", fake_build)
    return bootstrap_context, resolution_context


def test_execute_succeeds_for_resolve_unprovisioned_incident_and_closes_its_own_journal(admin_env, monkeypatch, now):
    evidence = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp",
        account_confirmed_absent=True,
        no_owned_key_confirmed=True,
        users_checked=3,
        keys_checked=1,
    )
    bootstrap_context, resolution_context = _rig_unprovisioned(
        monkeypatch, admin_env, identify_unprovisioned_incident_evidence_call=lambda: evidence
    )

    inspect = run_recovery_from_environment(admin_env, now=now)
    assert inspect.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert inspect.recovery_action is RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
    assert inspect.confirmation_token is not None

    result = run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect.confirmation_token,
        now=now,
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_COMPLETED
    assert result.evidence == evidence
    snapshot = resolution_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.COMPLETED
    assert snapshot.latest.transaction_state is AdministrativeTransactionState.RECOVERY_VERIFIED
    assert resolution_context._lock.inspect().state.value == "released"

    # The resolution journal's own operation_id is deterministically bound
    # to the exact incident it resolves -- not a random token -- so a
    # later bootstrap retry can verify the binding from the journal alone.
    incident_snapshot = bootstrap_context._journal.load()
    expected_id = derive_resolution_operation_id(
        incident_operation_id="incident-1", incident_record_mac=incident_snapshot.latest.mac
    )
    assert snapshot.latest.binding.operation_id == expected_id


def test_execute_for_resolve_unprovisioned_incident_fails_closed_if_account_reappears_before_commit(
    admin_env, monkeypatch, now
):
    """The evidence-gathering read at inspect time is not trusted forever
    -- execute re-verifies fresh, immediately before COMPLETED. If the
    account has since been (re-)created, the fresh check must fail and no
    COMPLETED record may ever be written."""

    from pfsense_mcp.errors import BootstrapProvisioningError

    calls = {"n": 0}
    absent_evidence = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp",
        account_confirmed_absent=True,
        no_owned_key_confirmed=True,
        users_checked=2,
        keys_checked=0,
    )

    def flaky_identify():
        calls["n"] += 1
        if calls["n"] <= 2:
            # Call 1: the inspect-path read, before any token is issued.
            # Call 2: execute's own re-derivation of the current
            # candidate/binding, performed before comparing the supplied
            # token -- both still see the account absent.
            return absent_evidence
        # Call 3: _run_recovery_locked()'s own fresh re-verification,
        # immediately before COMPLETED would be written -- the account
        # has since reappeared.
        raise BootstrapProvisioningError(
            "identify_unprovisioned_incident_evidence: the fixed dedicated account exists; no resolution performed."
        )

    _, resolution_context = _rig_unprovisioned(
        monkeypatch, admin_env, identify_unprovisioned_incident_evidence_call=flaky_identify
    )

    inspect = run_recovery_from_environment(admin_env, now=now)
    assert inspect.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED

    result = run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect.confirmation_token,
        now=now,
    )

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED
    snapshot = resolution_context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN
    assert resolution_context._lock.inspect().state.value == "active_held"


def test_inspect_for_resolve_unprovisioned_incident_refuses_when_account_still_exists(admin_env, monkeypatch, now):
    from pfsense_mcp.errors import BootstrapProvisioningError

    def _raise():
        raise BootstrapProvisioningError(
            "identify_unprovisioned_incident_evidence: the fixed dedicated account exists; no resolution performed."
        )

    _rig_unprovisioned(monkeypatch, admin_env, identify_unprovisioned_incident_evidence_call=_raise)

    result = run_recovery_from_environment(admin_env, now=now)

    assert result.outcome is RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE
    assert result.recovery_action is RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT
    assert result.confirmation_token is None


def test_resolve_unprovisioned_incident_does_not_touch_the_original_incident_journal(admin_env, monkeypatch, now):
    evidence = UnprovisionedIncidentEvidence(
        account_username="pfsense-mcp",
        account_confirmed_absent=True,
        no_owned_key_confirmed=True,
        users_checked=1,
        keys_checked=0,
    )
    bootstrap_context, _ = _rig_unprovisioned(
        monkeypatch, admin_env, identify_unprovisioned_incident_evidence_call=lambda: evidence
    )
    before = bootstrap_context._journal.load()

    inspect = run_recovery_from_environment(admin_env, now=now)
    run_recovery_from_environment(
        admin_env,
        execute_action=RecoveryAction.RESOLVE_UNPROVISIONED_INCIDENT,
        confirm_token=inspect.confirmation_token,
        now=now,
    )

    after = bootstrap_context._journal.load()
    assert after == before
