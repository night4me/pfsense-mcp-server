"""Focused + adversarial tests for `security_setup_apply.py`'s Slice 4
inline `RECOVERY_REQUIRED` delegation (design report §10(b), option
(b)) -- the composition of `security_recovery_orchestration.
run_recovery_from_environment()` when `write_protected` bootstrap
composition itself reports `BLOCKED_PRIOR_OPERATION`.

Most scenarios monkeypatch both `run_bootstrap_from_environment` (to
force `BLOCKED_PRIOR_OPERATION` deterministically) and
`run_recovery_from_environment` (to control exactly what inspection
returns) -- this file is about the *composition boundary*: that
inline inspection only ever fires for the right outcome, that it is
never called with `execute_action`/`confirm_token` (the single most
security-relevant invariant this slice introduces), and that whatever
it returns is surfaced faithfully. It deliberately does not re-test
`run_recovery_from_environment()`'s own internal classify/candidate-
identification/token-derivation logic (see
`tests/test_security_recovery_orchestration.py` for that -- unchanged,
untouched by this slice). One end-to-end test drives a real
interrupted-bootstrap journal plus a real (synthetic) identifiable
orphan-key candidate to prove the full composition actually works,
not just the mapping layer."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import build_admin_context
from pfsense_mcp.security_bootstrap_client import ObservedApiKey
from pfsense_mcp.security_bootstrap_orchestration import BootstrapOrchestrationOutcome, BootstrapOrchestrationResult
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_operation_journal import AdministrativeOperationType
from pfsense_mcp.security_recovery_orchestration import RecoveryOrchestrationOutcome, RecoveryOrchestrationResult
from pfsense_mcp.security_setup_apply import ApplyOutcome, run_setup_apply_from_environment
from pfsense_mcp.security_setup_apply_confirmation import ApplyConfirmationBinding, derive_confirmation_token
from pfsense_mcp.security_setup_plan import generate_setup_plan
from pfsense_mcp.security_setup_plan_digest import compute_setup_plan_digest


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


def _confirm_key_file(tmp_path: Path, content: bytes = b"confirm-key-material-not-a-real-secret") -> Path:
    path = tmp_path / "setup-confirm.key"
    _write_secure(path, content)
    return path


def _admin_env(tmp_path: Path) -> dict[str, str]:
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
    return {
        "PFSENSE_API_URL": "https://lab.example.invalid",
        "PFSENSE_IDENTITY": "lab-appliance-one",
        "PFSENSE_API_KEY_FILE": str(tmp_path / "admin-api-key"),
        "PFSENSE_TLS_MODE": "strict",
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


def _base_env(tmp_path: Path, *, with_admin_env: bool = False) -> dict[str, str]:
    env: dict[str, str] = {"PFSENSE_SETUP_CONFIRM_KEY_FILE": str(_confirm_key_file(tmp_path))}
    if with_admin_env:
        env.update(_admin_env(tmp_path))
    return env


def _apply_token(tmp_path: Path, env: dict[str, str], *, anchor: str = "none") -> tuple[str, str]:
    posture = CapabilityPosture.WRITE_PROTECTED
    anchor_value = AnchorAssurance(anchor)
    plan = generate_setup_plan(target_capability_posture=posture, target_anchor_assurance=anchor_value, env=env)
    digest = compute_setup_plan_digest(plan)
    binding = ApplyConfirmationBinding(
        plan_digest=digest,
        target_origin=None,
        target_identity=None,
        capability_posture=posture.value,
        anchor_assurance=anchor_value.value,
    )
    key_path = Path(env["PFSENSE_SETUP_CONFIRM_KEY_FILE"])
    token = derive_confirmation_token(binding, integrity_key=key_path.read_bytes().strip())
    return digest, token


def _run(tmp_path, env):
    digest, token = _apply_token(tmp_path, env)
    return run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )


# --- inline recovery only fires for BLOCKED_PRIOR_OPERATION -----------------


@pytest.mark.parametrize(
    "bootstrap_outcome",
    [
        BootstrapOrchestrationOutcome.ALREADY_COMPLETE,
        BootstrapOrchestrationOutcome.COMPLETED,
        BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR,
        BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION,
        BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
        BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED,
        BootstrapOrchestrationOutcome.PROVISIONING_FAILED,
    ],
)
def test_inline_recovery_never_fires_for_any_outcome_other_than_blocked_prior_operation(
    tmp_path, monkeypatch, bootstrap_outcome
):
    def _explode(env, **kwargs):
        raise AssertionError(f"run_recovery_from_environment must not be called for {bootstrap_outcome}")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_recovery_from_environment", _explode)
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(bootstrap_outcome, "canned"),
    )
    env = _base_env(tmp_path)
    result = _run(tmp_path, env)
    assert result.recovery_outcome is None


def test_inline_recovery_fires_exactly_for_blocked_prior_operation(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_recovery_from_environment",
        lambda env, **kwargs: (
            calls.append("called")
            or RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED, "nothing to do")
        ),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    env = _base_env(tmp_path)
    result = _run(tmp_path, env)
    assert result.outcome is ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED
    assert calls == ["called"]


# --- the critical invariant: never execute_action/confirm_token -------------


def test_inline_recovery_is_called_with_only_env_never_execute_action_or_confirm_token(tmp_path, monkeypatch):
    captured: dict[str, object] = {}

    def _capture(env, **kwargs):
        captured["env"] = env
        captured["kwargs"] = kwargs
        return RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.RECOVERY_NEEDED, "needed")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_recovery_from_environment", _capture)
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    env = _base_env(tmp_path)
    _run(tmp_path, env)
    assert captured["env"] is env
    # target_profile is always supplied (added for the POST-v1.0 MANAGED READ-ONLY WIZARD
    # INTEGRATION mission, 2026-08-29, so inline recovery inspects the correct account's own
    # journal) -- but never execute_action/confirm_token, the actual invariant this test proves.
    assert captured["kwargs"] == {"target_profile": "write_protected"}


# --- faithful surfacing across every inspect-only RecoveryOrchestrationOutcome --


@pytest.mark.parametrize(
    "recovery_outcome",
    [
        RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED,
        RecoveryOrchestrationOutcome.RECOVERY_NEEDED,
        RecoveryOrchestrationOutcome.RECOVERY_ALREADY_COMPLETE,
        RecoveryOrchestrationOutcome.BLOCKED_AMBIGUOUS_RECOVERY_STATE,
        RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE,
        RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR,
        RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE,
    ],
)
def test_every_inspect_only_recovery_outcome_is_surfaced_verbatim(tmp_path, monkeypatch, recovery_outcome):
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_recovery_from_environment",
        lambda env, **kwargs: RecoveryOrchestrationResult(recovery_outcome, "canned recovery detail"),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    env = _base_env(tmp_path)
    result = _run(tmp_path, env)
    assert result.outcome is ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED
    assert result.recovery_outcome == recovery_outcome.value
    assert "canned recovery detail" in result.detail


def test_recovery_action_and_token_present_only_when_recovery_needed(tmp_path, monkeypatch):
    from pfsense_mcp.security_operation_journal import RecoveryAction

    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_recovery_from_environment",
        lambda env, **kwargs: RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_NEEDED,
            "revoke needed",
            recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
            confirmation_token="d" * 64,
        ),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    env = _base_env(tmp_path)
    result = _run(tmp_path, env)
    assert result.recovery_action == "revoke_orphan_key"
    assert result.recovery_confirmation_token == "d" * 64
    assert "pfsense-mcp-security recover --execute" in result.detail


def test_recovery_action_and_token_absent_when_candidate_not_identifiable(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_recovery_from_environment",
        lambda env, **kwargs: RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE, "zero candidates found"
        ),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    env = _base_env(tmp_path)
    result = _run(tmp_path, env)
    assert result.recovery_action is None
    assert result.recovery_confirmation_token is None


# --- secret redaction ---------------------------------------------------


def test_no_secret_material_leaks_into_the_inline_recovery_result(tmp_path, monkeypatch):
    from pfsense_mcp.security_operation_journal import RecoveryAction

    confirm_key_value = "super-secret-setup-confirm-key-value"
    confirm_key_path = _confirm_key_file(tmp_path, content=confirm_key_value.encode())
    env = {"PFSENSE_SETUP_CONFIRM_KEY_FILE": str(confirm_key_path)}

    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_recovery_from_environment",
        lambda env, **kwargs: RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_NEEDED,
            "sanitized detail only",
            recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
            confirmation_token="e" * 64,
        ),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "blocked"),
    )
    result = _run(tmp_path, env)
    serialized = repr(result)
    assert confirm_key_value not in serialized
    assert confirm_key_value not in result.detail


# --- full end-to-end: a real interrupted journal + a real candidate --------


def test_end_to_end_inline_recovery_against_a_real_journal_and_real_candidate(tmp_path, monkeypatch):
    """Proves the full Slice 4 composition against real
    `AdministrativeContext`/journal/candidate-identification machinery,
    not just monkeypatched results -- mirrors
    `tests/test_security_cli_recover.py`'s own end-to-end pattern."""

    from pfsense_mcp.security_operation_journal import (
        AdministrativeTransactionState,
        DurableOperationState,
        RecoveryAction,
    )

    env = _base_env(tmp_path, with_admin_env=True)

    bootstrap_context = build_admin_context(env)
    bootstrap_context._lock.acquire("incident-1", timestamp="2026-08-23T00:00:00Z")
    binding = bootstrap_context.new_operation_binding(
        operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    bootstrap_context._journal.create(binding, timestamp="2026-08-23T00:00:00Z")
    bootstrap_context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:01Z",
    )
    bootstrap_context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:02Z",
    )
    bootstrap_context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.MUTATION_RESULT_UNKNOWN,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:03Z",
    )
    # A determination that this incident specifically needs
    # revoke_orphan_key recovery -- classify_restart() only ever
    # surfaces a specific recovery_action once the journal actually
    # records one at the terminal RECOVERY_REQUIRED state (no
    # production code path in this codebase writes that state today;
    # this simulates the record a future/manual determination would
    # produce, exactly as tests/test_security_cli_recover.py's own
    # end-to-end fixture does).
    bootstrap_context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.RECOVERY_REQUIRED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:04Z",
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
    )
    # Deliberately left locked/unreleased, exactly like a real crash.

    key = ObservedApiKey(
        id=7, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
    )
    recovery_context = build_admin_context(env, operation_type=AdministrativeOperationType.RECOVER_ORPHAN_KEY)
    recovery_components = replace(
        recovery_context._mutation_components,
        identify_orphan_key_candidate=lambda: key,
    )
    recovery_context = replace(recovery_context, _mutation_components=recovery_components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP, resolution_operation_id=None):
        return bootstrap_context if operation_type is AdministrativeOperationType.BOOTSTRAP else recovery_context

    monkeypatch.setattr("pfsense_mcp.security_bootstrap_orchestration.build_admin_context", fake_build)
    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_admin_context", fake_build)

    result = _run(tmp_path, env)

    assert result.outcome is ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED
    assert result.recovery_outcome == "recovery_needed"
    assert result.recovery_action == "revoke_orphan_key"
    assert result.recovery_confirmation_token is not None
    assert len(result.recovery_confirmation_token) == 64
    # The original incident journal is left completely untouched by inspection.
    original = bootstrap_context._journal.load()
    assert original.latest.state.value == "recovery_required"
    assert original.latest.sequence == 4
    # Inspection never created/touched the recovery-typed journal either.
    assert not recovery_context.journal_path.exists()
