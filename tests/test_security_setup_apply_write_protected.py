"""Focused + adversarial tests for `security_setup_apply.py`'s
`write_protected` branch (Slice 3) -- `setup apply`'s composition of
`security_bootstrap_orchestration.run_bootstrap_from_environment()`.

Most scenarios monkeypatch `pfsense_mcp.security_setup_apply.
run_bootstrap_from_environment` with a canned `BootstrapOrchestrationResult`
-- this file is about the *mapping* from `BootstrapOrchestrationOutcome`
to `ApplyOutcome`, the doctor-gate ordering, and the plan/token
boundary that must be crossed before bootstrap is ever composed at all;
it deliberately does not re-test `run_bootstrap_from_environment()`'s
own internal journal/lock/engine logic (see
`tests/test_security_bootstrap_orchestration.py` for that -- unchanged,
untouched by this slice). One end-to-end test drives a real
`AdministrativeContext` (with only the engine's own HTTP-shaped call
stubbed, exactly mirroring `tests/test_security_cli_bootstrap.py`'s own
end-to-end test) to prove the full composition actually works
end-to-end, not just the mapping function's shape."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import PfRestReadOnlyStatus, build_admin_context
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    BootstrapOrchestrationResult,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
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
    """A full, real ADR-033 admin environment -- the same shape
    `tests/test_security_cli_bootstrap.py`'s own `real_admin_env`
    fixture builds, but as a plain dict (never touching real
    os.environ) since `run_setup_apply_from_environment()` accepts an
    explicit `env` override."""

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


def _current_token(
    tmp_path: Path,
    env: dict[str, str],
    *,
    target_anchor_assurance: str,
    target_origin: str | None = None,
    target_identity: str | None = None,
) -> tuple[str, str]:
    posture = CapabilityPosture.WRITE_PROTECTED
    anchor = AnchorAssurance(target_anchor_assurance)
    plan = generate_setup_plan(
        target_capability_posture=posture,
        target_anchor_assurance=anchor,
        target_origin=target_origin,
        target_identity=target_identity,
        env=env,
    )
    digest = compute_setup_plan_digest(plan)
    binding = ApplyConfirmationBinding(
        plan_digest=digest,
        target_origin=target_origin,
        target_identity=target_identity,
        capability_posture=posture.value,
        anchor_assurance=anchor.value,
    )
    key_path = Path(env["PFSENSE_SETUP_CONFIRM_KEY_FILE"])
    token = derive_confirmation_token(binding, integrity_key=key_path.read_bytes().strip())
    return digest, token


def _apply(tmp_path: Path, env: dict[str, str], *, anchor: str = "none") -> tuple[str, str]:
    """Returns (digest, token) for a fresh write_protected plan at the
    given anchor, ready to pass straight into
    run_setup_apply_from_environment()."""

    return _current_token(tmp_path, env, target_anchor_assurance=anchor)


class _NotReadyDoctor:
    ready = False


class _ReadyDoctor:
    ready = True


# --- outcome mapping: every BootstrapOrchestrationOutcome, 1:1 --------------


@pytest.mark.parametrize(
    ("bootstrap_outcome", "expected_apply_outcome"),
    [
        (BootstrapOrchestrationOutcome.ALREADY_COMPLETE, ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE),
        (BootstrapOrchestrationOutcome.COMPLETED, ApplyOutcome.BOOTSTRAP_COMPLETED),
        (BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR, ApplyOutcome.BLOCKED_CONFIGURATION_ERROR),
        (BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION, ApplyOutcome.BOOTSTRAP_LOCK_CONTENTION),
        (BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED),
        (BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE, ApplyOutcome.BOOTSTRAP_CORRUPT_LOCAL_STATE),
        (
            BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED,
            ApplyOutcome.BOOTSTRAP_PREFLIGHT_DERIVATION_FAILED,
        ),
        (BootstrapOrchestrationOutcome.PROVISIONING_FAILED, ApplyOutcome.BOOTSTRAP_PROVISIONING_FAILED),
    ],
)
def test_every_bootstrap_outcome_maps_1to1(tmp_path, monkeypatch, bootstrap_outcome, expected_apply_outcome):
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(bootstrap_outcome, "canned detail"),
    )
    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is expected_apply_outcome
    assert result.plan_digest == digest


def test_recovery_required_detail_points_at_the_recover_command(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, "a prior operation needs attention"
        ),
    )
    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED
    assert "pfsense-mcp-security recover" in result.detail
    assert "a prior operation needs attention" in result.detail


# --- doctor gate ordering ----------------------------------------------------


def test_hardware_witness_doctor_not_ready_blocks_before_bootstrap_is_ever_called(tmp_path, monkeypatch):
    def _explode(env):
        raise AssertionError("run_bootstrap_from_environment must not be called when doctor is not ready")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_bootstrap_from_environment", _explode)
    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_doctor_checks", lambda env: _NotReadyDoctor())

    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env, anchor="hardware_witness")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="hardware_witness",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.DOCTOR_NOT_READY
    assert result.doctor_ready is False


def test_hardware_witness_doctor_ready_proceeds_to_bootstrap(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: (
            calls.append("called") or BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.ALREADY_COMPLETE, "ok")
        ),
    )
    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_doctor_checks", lambda env: _ReadyDoctor())

    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env, anchor="hardware_witness")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="hardware_witness",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE
    assert calls == ["called"]


@pytest.mark.parametrize("anchor", ["none", "software"])
def test_non_hardware_witness_anchors_skip_the_doctor_gate_entirely(tmp_path, monkeypatch, anchor):
    doctor_calls: list[str] = []

    def _doctor_should_not_be_called(env):
        doctor_calls.append("called")
        return _NotReadyDoctor()

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_doctor_checks", _doctor_should_not_be_called)
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.ALREADY_COMPLETE, "ok"),
    )

    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env, anchor=anchor)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance=anchor,
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE
    assert doctor_calls == []


# --- isolation from the read_only code path ---------------------------------


def test_write_protected_never_calls_build_pfsense_client(tmp_path, monkeypatch):
    def _explode(config, api_key):
        raise AssertionError("build_pfsense_client is read_only's own code path")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.build_pfsense_client", _explode)
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.ALREADY_COMPLETE, "ok"),
    )
    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE


def test_write_protected_never_calls_load_config_or_load_api_key(tmp_path, monkeypatch):
    def _explode_config(env):
        raise AssertionError("load_config is read_only's own code path")

    def _explode_key(config):
        raise AssertionError("load_api_key is read_only's own code path")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.load_config", _explode_config)
    monkeypatch.setattr("pfsense_mcp.security_setup_apply.load_api_key", _explode_key)
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.ALREADY_COMPLETE, "ok"),
    )
    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE


def test_write_protected_calls_bootstrap_with_only_env_never_a_live_authoritative_observation(tmp_path, monkeypatch):
    """`run_bootstrap_from_environment()` must be called exactly the way
    standalone `bootstrap` itself calls it by default -- positional
    `env` only, `authoritative` left at its own `None` default -- never
    a synthetic/forced-clean observation that would bypass its own
    restart classification."""

    captured: dict[str, object] = {}

    def _capture(env, **kwargs):
        captured["env"] = env
        captured["kwargs"] = kwargs
        return BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.ALREADY_COMPLETE, "ok")

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_bootstrap_from_environment", _capture)
    env = _base_env(tmp_path)
    digest, token = _apply(tmp_path, env)
    run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert captured["env"] is env
    assert captured["kwargs"] == {}


# --- secret redaction ---------------------------------------------------


@pytest.mark.parametrize(
    "bootstrap_outcome",
    [
        BootstrapOrchestrationOutcome.ALREADY_COMPLETE,
        BootstrapOrchestrationOutcome.COMPLETED,
        BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION,
        BootstrapOrchestrationOutcome.PROVISIONING_FAILED,
    ],
)
def test_no_secret_material_leaks_into_any_write_protected_result(tmp_path, monkeypatch, bootstrap_outcome):
    confirm_key_value = "super-secret-setup-confirm-key-value"
    confirm_key_path = _confirm_key_file(tmp_path, content=confirm_key_value.encode())
    env = {"PFSENSE_SETUP_CONFIRM_KEY_FILE": str(confirm_key_path)}

    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.run_bootstrap_from_environment",
        lambda env: BootstrapOrchestrationResult(bootstrap_outcome, "sanitized detail only"),
    )
    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    serialized = repr(result)
    assert confirm_key_value not in serialized
    assert confirm_key_value not in result.detail
    assert result.confirmation_token is None


# --- full end-to-end: a real AdministrativeContext, only the HTTP-shaped ---
# --- engine call stubbed, mirroring tests/test_security_cli_bootstrap.py ---


def test_end_to_end_write_protected_apply_against_a_real_admin_context(tmp_path, monkeypatch):
    env = _base_env(tmp_path, with_admin_env=True)

    # Inspect first, exactly as an operator would.
    digest, token = _apply(tmp_path, env)
    inspect_result = run_setup_apply_from_environment(
        env, target_capability_posture="write_protected", target_anchor_assurance="none"
    )
    assert inspect_result.outcome is ApplyOutcome.INSPECT_PLAN_CURRENT
    assert inspect_result.plan_digest == digest
    assert inspect_result.confirmation_token == token

    context = build_admin_context(env)
    components = replace(
        context._mutation_components,
        bootstrap_call=lambda: ProvisioningResult(ProvisioningOutcome.ALREADY_SATISFIED, "no-op"),
        check_pfrest_read_only_call=lambda: PfRestReadOnlyStatus.WRITABLE,
    )
    stubbed_context = replace(context, _mutation_components=components)
    monkeypatch.setattr(
        "pfsense_mcp.security_bootstrap_orchestration.build_admin_context",
        lambda source: stubbed_context,
    )

    apply_result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert apply_result.outcome is ApplyOutcome.BOOTSTRAP_COMPLETED
    snapshot = stubbed_context._journal.load()
    assert snapshot.latest.state.value == "completed"


def test_end_to_end_write_protected_apply_surfaces_recovery_required_from_a_real_journal(tmp_path, monkeypatch):
    """A genuine prior-incident journal (not a canned result) must still
    be refused, proving the real classify_restart() path -- not just
    the outcome-mapping layer -- gates write_protected apply."""

    from pfsense_mcp.security_operation_journal import (
        AdministrativeOperationType,
        AdministrativeTransactionState,
        DurableOperationState,
    )

    env = _base_env(tmp_path, with_admin_env=True)
    context = build_admin_context(env)
    context._lock.acquire("incident-1", timestamp="2026-08-23T00:00:00Z")
    binding = context.new_operation_binding(
        operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    context._journal.create(binding, timestamp="2026-08-23T00:00:00Z")
    context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:01Z",
    )
    context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:02Z",
    )
    context._journal.append(
        operation_id="incident-1",
        state=DurableOperationState.MUTATION_RESULT_UNKNOWN,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:03Z",
    )
    # Deliberately left locked/unreleased -- exactly the state a real
    # crash mid-operation leaves behind (security_bootstrap_orchestration.py's
    # own docstring: a failure never releases the lock).

    digest, token = _apply(tmp_path, env)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED
    assert "pfsense-mcp-security recover" in result.detail
    # The original incident journal must be left completely untouched.
    original = context._journal.load()
    assert original.latest.state.value == "mutation_result_unknown"


def test_env_var_key_names_are_absent_from_the_confirm_key(tmp_path):
    """Sanity check that the confirm-key fixture used throughout this
    file is not accidentally an empty/whitespace file (which would make
    every test above pass for the wrong reason -- BLOCKED_CONFIGURATION_ERROR
    instead of real posture-specific outcomes)."""

    path = _confirm_key_file(tmp_path)
    assert path.read_bytes().strip()
