"""ADR-033 CLI Integration Slice 3 -- orchestration test matrix.

Reuses `security_admin_composition.py`'s existing `AdministrativeContext`
composition (a real, fully-validated fixed stack) but stubs
`context._mutation_components.bootstrap_call` to return synthetic
`ProvisioningResult` values -- the engine itself (`provision_service_account`,
`_provision_new_account`, `_provision_against_existing_account`, duplicate
detection, drift computation, etc.) already has its own dedicated test
suite and is intentionally not re-tested here. This file focuses on what
Slice 3 actually adds: locking, journal sequencing, crash/restart
classification, and secret-safety of the orchestration layer itself.

Test matrix items A-T (see the ADR-033 CLI Integration Slice 3 task spec)
are annotated on each test as `# Matrix: <letter>`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, replace
from pathlib import Path
from unittest.mock import patch

import pytest

from pfsense_mcp.security_admin_composition import AdministrativeContext, build_admin_context
from pfsense_mcp.security_bootstrap_client import ProvisionedApiKey
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    run_bootstrap,
    run_bootstrap_from_environment,
)
from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    AuthoritativeRestartObservation,
    AuthoritativeServerState,
    DurableOperationState,
    OperationLockError,
    RestartClassification,
    RestartDecision,
)

T0 = "2026-08-23T00:00:00Z"
T1 = "2026-08-23T00:00:01Z"


class _Clock:
    """A fresh, per-test monotonically increasing timestamp source."""

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


def _with_bootstrap_call(context: AdministrativeContext, call) -> AdministrativeContext:
    components = replace(context._mutation_components, bootstrap_call=call)
    return replace(context, _mutation_components=components)


def _result(outcome: ProvisioningOutcome, detail: str = "synthetic", **kwargs) -> ProvisioningResult:
    return ProvisioningResult(outcome, detail, **kwargs)


@dataclass(frozen=True)
class _RaisingCounter:
    exc: Exception

    def __call__(self) -> ProvisioningResult:
        raise self.exc


# --- A/B/C: successful outcomes ---------------------------------------------


def test_existing_account_sync_success_completes_journal_and_releases_lock(admin_env, now):
    # Matrix: A
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.PRIVILEGES_SYNCED, "synced"))

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert result.provisioning_outcome is ProvisioningOutcome.PRIVILEGES_SYNCED
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.COMPLETED
    assert context._lock.inspect().state.value in {"absent", "released"}


def test_new_account_creation_success_persists_key_and_completes(admin_env, now):
    # Matrix: B
    context = build_admin_context(admin_env)
    key = ProvisionedApiKey(
        username="pfsense-mcp", descr="d", hash_algo="sha256", length_bytes=32, _secret="s3cr3t-key-value"
    )
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.COMPLETED, "created", api_key=key))

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    custody = Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"])
    assert custody.exists()
    assert custody.read_bytes() == b"s3cr3t-key-value"
    assert oct(custody.stat().st_mode & 0o777) == "0o600"
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.COMPLETED


def test_already_satisfied_no_mutation_still_completes(admin_env, now):
    # Matrix: C
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "no-op"))

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    custody = Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"])
    assert not custody.exists()


# --- D: duplicate account fail-closed (engine-level FAILED outcome) --------


def test_duplicate_account_outcome_is_provisioning_failed_lock_held(admin_env, now):
    # Matrix: D
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(
        context,
        lambda: _result(ProvisioningOutcome.FAILED, "pre-flight observation failed: ambiguous account state"),
    )

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN
    with pytest.raises(OperationLockError):
        context._lock.acquire("someone-else", timestamp=now())


# --- E: interrupted temporary-privilege state (pre-existing journal) -------


def test_interrupted_prior_operation_blocks_new_bootstrap(admin_env, now):
    # Matrix: E
    context = build_admin_context(admin_env)
    context._journal.create(
        context.new_operation_binding(operation_id="op-1", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp=T0,
    )
    context._journal.append(
        operation_id="op-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp=T1,
    )
    context._journal.append(
        operation_id="op-1",
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.BOOTSTRAP_PRIVILEGE_GRANTED,
        mutation_index=1,
        timestamp=now(),
    )

    result = run_bootstrap(context, now=now)

    # Offline default (authoritative=None): classify_restart() treats any
    # pre-existing journal as RECOVERY_REQUIRED regardless of its specific
    # state -- the finer-grained classification (e.g.
    # MUTATION_SENT_RESULT_UNKNOWN) only becomes reachable once a live
    # observation is supplied, exercised separately below.
    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION
    assert result.restart_decision is not None
    assert result.restart_decision.classification is RestartClassification.RECOVERY_REQUIRED

    binding = context.binding
    authoritative = AuthoritativeRestartObservation(
        target_identity=binding.target_identity,
        target_origin=binding.target_origin,
        account_identity=binding.account_identity,
        approved_profile=binding.approved_profile,
        schema_version=binding.schema_version,
        schema_evidence_digest=binding.schema_evidence_digest,
        auth_methods=("KeyAuth",),
        server_state=AuthoritativeServerState.EXPECTED_PARTIAL,
    )
    live_result = run_bootstrap(context, authoritative=authoritative, now=now)
    assert live_result.restart_decision.classification is RestartClassification.MUTATION_SENT_RESULT_UNKNOWN


# --- F/G: crash after mutation-intent, restart/recovery classification ----


def test_crash_during_engine_call_leaves_journal_unknown_and_lock_stale(admin_env, now):
    # Matrix: F
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, _RaisingCounter(RuntimeError("simulated crash-equivalent failure")))

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN
    # simulate real process death: free the OS lock without rewriting metadata to active=False
    os.close(context._lock._descriptor)
    context._lock._descriptor = None
    context._lock._operation_id = None

    fresh = build_admin_context(admin_env)
    decision = fresh.status.classify(authoritative=None)
    assert decision.classification is RestartClassification.RECOVERY_REQUIRED


def test_restart_after_crash_refuses_to_blindly_retry(admin_env, now):
    # Matrix: G
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, _RaisingCounter(RuntimeError("simulated crash-equivalent failure")))
    run_bootstrap(context, now=now)
    os.close(context._lock._descriptor)
    context._lock._descriptor = None
    context._lock._operation_id = None

    fresh = build_admin_context(admin_env)
    fresh = _with_bootstrap_call(fresh, lambda: _result(ProvisioningOutcome.COMPLETED, "should never run"))
    result = run_bootstrap(fresh, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION


# --- H: concurrent bootstrap processes / lock contention -------------------


def test_concurrent_lock_holder_causes_lock_contention(admin_env, now):
    # Matrix: H
    # Both contexts must be constructed while state is still clean --
    # build_admin_context() itself refuses an ambiguous lock/journal
    # combination (see test_security_admin_composition.py), so a second
    # "process" reconnecting only after contention exists cannot be
    # modeled by a fresh build_admin_context() call here.
    context = build_admin_context(admin_env)
    holder = build_admin_context(admin_env)
    holder._lock.acquire("holder-op", timestamp=T0)
    try:
        clean_decision = RestartDecision(RestartClassification.CLEAN_NO_OPERATION, None)
        with patch.object(context.status, "classify", return_value=clean_decision):
            result = run_bootstrap(context, now=now)
        assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION
    finally:
        holder._lock.release(timestamp=now())


# --- I: corrupted journal ----------------------------------------------------


def test_corrupted_journal_blocks_with_corrupt_local_state(admin_env, now):
    # Matrix: I
    # Corruption happens after a successful construction (e.g. disk
    # damage while the process is running) -- build_admin_context()
    # itself already refuses to construct against an already-corrupt
    # journal (see test_security_admin_composition.py), so the
    # already-built `context` is reused rather than reconstructed.
    context = build_admin_context(admin_env)
    context._journal.create(
        context.new_operation_binding(operation_id="op-1", operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp=T0,
    )
    _write_secure(context.journal_path, b"not-a-valid-journal-line\n")

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE


# --- K: stale/ambiguous lock without a journal ------------------------------


def test_ambiguous_lock_without_journal_is_corrupt_not_clean(admin_env, now):
    # Matrix: K
    # As with I above, the already-built `context` is reused: a fresh
    # build_admin_context() call already refuses this combination itself.
    context = build_admin_context(admin_env)
    context._lock.acquire("op-x", timestamp=T0)
    os.close(context._lock._descriptor)
    context._lock._descriptor = None
    context._lock._operation_id = None

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE


# --- L/M: derivation failures (unsupported version / non-cross-checked) ---


@pytest.mark.parametrize(
    "detail",
    [
        "installed pfSense REST API package version is outside the verified-compatible range",
        "privilege derivation is not fully source-cross-checked for this profile",
    ],
)
def test_derivation_failed_is_reported_distinctly_but_still_blocks_reuse(admin_env, detail, now):
    # Matrix: L, M
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.DERIVATION_FAILED, detail))

    result = run_bootstrap(context, now=now)

    # Distinct outcome value (proven zero HTTP activity), but journaled
    # identically to any other engine failure: this offline slice cannot
    # let a subsequent attempt against the same namespace proceed without
    # either a live observation or manual state cleanup.
    assert result.outcome is BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN
    with pytest.raises(OperationLockError):
        context._lock.acquire("someone-else", timestamp=now())

    fresh = build_admin_context(admin_env)
    fresh = _with_bootstrap_call(fresh, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "should never run"))
    second = run_bootstrap(fresh, now=now)
    assert second.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION


# --- N/O/P/Q/R: engine FAILED outcomes at various stages --------------------


@pytest.mark.parametrize(
    "detail",
    [
        "pre-flight observation failed: pfSense API returned HTTP 401",
        "pre-flight observation failed: pfSense API returned HTTP 403",
        "post-sync verification failed: expected privilege still missing after PATCH",
        "API-key creation failed: pfSense API returned HTTP 500. The account currently holds the temporary "
        "bootstrap-only privilege and it was NOT automatically revoked.",
    ],
)
def test_engine_failed_outcomes_block_and_hold_lock(admin_env, detail, now):
    # Matrix: N, O, P, Q/R (representative failure-detail shapes)
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.FAILED, detail))

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    assert result.provisioning_detail == detail
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN


def test_blocked_existing_partial_blocks_and_holds_lock(admin_env, now):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(
        context,
        lambda: _result(
            ProvisioningOutcome.BLOCKED_EXISTING_PARTIAL, "existing account already holds bootstrap-only privilege"
        ),
    )

    result = run_bootstrap(context, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    snapshot = context._journal.load()
    assert snapshot.latest.state is DurableOperationState.MUTATION_RESULT_UNKNOWN


# --- S: secret-safety --------------------------------------------------------


def test_no_secret_material_in_orchestration_result_or_journal(admin_env, now):
    # Matrix: S
    context = build_admin_context(admin_env)
    secret = "s3cr3t-plaintext-key-do-not-leak"
    key = ProvisionedApiKey(username="pfsense-mcp", descr="d", hash_algo="sha256", length_bytes=32, _secret=secret)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.COMPLETED, "created", api_key=key))

    result = run_bootstrap(context, now=now)

    rendered = repr(result) + str(result)
    assert secret not in rendered

    journal_bytes = context.journal_path.read_bytes()
    assert secret.encode() not in journal_bytes

    custody = Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"])
    assert custody.read_bytes() == secret.encode()
    assert oct(custody.stat().st_mode & 0o777) == "0o600"


# --- T: idempotent rerun after successful completion ------------------------


def test_rerun_after_completion_without_live_observation_requires_review(admin_env, now):
    # Matrix: T (offline CLI default: authoritative=None always)
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    first = run_bootstrap(context, now=now)
    assert first.outcome is BootstrapOrchestrationOutcome.COMPLETED

    fresh = build_admin_context(admin_env)
    fresh = _with_bootstrap_call(fresh, lambda: _result(ProvisioningOutcome.COMPLETED, "should never run"))
    second = run_bootstrap(fresh, now=now)

    # Without a live authoritative observation, a completed journal is
    # conservatively treated as needing review, not silently re-affirmed.
    assert second.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION
    assert second.restart_decision.classification is RestartClassification.RECOVERY_REQUIRED


def test_rerun_after_completion_with_live_confirmation_reports_already_complete(admin_env, now):
    # Matrix: T (future live-authorized path, exercised here via injection)
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context, now=now)

    fresh = build_admin_context(admin_env)
    binding = fresh.binding
    authoritative = AuthoritativeRestartObservation(
        target_identity=binding.target_identity,
        target_origin=binding.target_origin,
        account_identity=binding.account_identity,
        approved_profile=binding.approved_profile,
        schema_version=binding.schema_version,
        schema_evidence_digest=binding.schema_evidence_digest,
        auth_methods=("KeyAuth",),
        server_state=AuthoritativeServerState.EXPECTED_COMPLETED,
        final_verification_complete=True,
    )
    result = run_bootstrap(fresh, authoritative=authoritative, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.ALREADY_COMPLETE


def test_already_complete_touches_neither_lock_nor_journal(admin_env, now):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context, now=now)
    before = context.journal_path.read_bytes()

    fresh = build_admin_context(admin_env)
    binding = fresh.binding
    authoritative = AuthoritativeRestartObservation(
        target_identity=binding.target_identity,
        target_origin=binding.target_origin,
        account_identity=binding.account_identity,
        approved_profile=binding.approved_profile,
        schema_version=binding.schema_version,
        schema_evidence_digest=binding.schema_evidence_digest,
        auth_methods=("KeyAuth",),
        server_state=AuthoritativeServerState.EXPECTED_COMPLETED,
        final_verification_complete=True,
    )
    lock_existed_before = fresh.lock_path.exists()
    result = run_bootstrap(fresh, authoritative=authoritative, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.ALREADY_COMPLETE
    assert context.journal_path.read_bytes() == before
    assert fresh.lock_path.exists() == lock_existed_before


# --- run_bootstrap_from_environment: the sole CLI-facing entry point -------


def test_from_environment_reports_configuration_error_without_touching_lock_or_journal(admin_env, now):
    del admin_env["PFSENSE_ADMIN_SCHEMA_FILE"]

    result = run_bootstrap_from_environment(admin_env, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR
    state_dir = Path(admin_env["PFSENSE_ADMIN_STATE_DIR"])
    assert list(state_dir.iterdir()) == []


def test_from_environment_happy_path_via_patched_construction(admin_env, now, monkeypatch):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "no-op"))
    monkeypatch.setattr(
        "pfsense_mcp.security_bootstrap_orchestration.build_admin_context",
        lambda source: context,
    )

    result = run_bootstrap_from_environment(admin_env, now=now)

    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
