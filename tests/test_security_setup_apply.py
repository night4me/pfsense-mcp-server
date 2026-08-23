"""Focused + adversarial tests for `pfsense_mcp.security_setup_apply` --
`pfsense-mcp-security setup apply` Slice 2's READ-only apply.

Every test runs with a controlled environment dict (never the real
`os.environ`) so results are deterministic and independent of the
machine running the tests. The one live pfSense call
(`PfSenseClient.get_system_status`) is exercised through
`build_pfsense_client` monkeypatched to a fake transport/client pair --
this file never makes a real network connection, mirroring
`tests/test_security_recovery_orchestration.py` and
`tests/test_security_bootstrap_orchestration.py`'s own established
pattern for orchestration-layer tests (no bespoke AST isolation file;
the repository-wide `get_only_check.py`/`tools_write_check.py` static
gates already prove the request()/write-import isolation properties for
every module, this one included)."""

from __future__ import annotations

from pathlib import Path

import pytest

from pfsense_mcp.errors import PfSenseConnectionError
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_setup_apply import ApplyOutcome, run_setup_apply_from_environment
from pfsense_mcp.security_setup_apply_confirmation import (
    ApplyConfirmationBinding,
    derive_confirmation_token,
)
from pfsense_mcp.security_setup_plan import generate_setup_plan
from pfsense_mcp.security_setup_plan_digest import compute_setup_plan_digest


class _FakeTransport:
    def __init__(self) -> None:
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeClient:
    def __init__(self, *, raises: Exception | None = None) -> None:
        self._raises = raises
        self.called = False

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> object:
        self.called = True
        if self._raises is not None:
            raise self._raises
        return object()


def _confirm_key_file(tmp_path: Path, content: bytes = b"confirm-key-material-not-a-real-secret") -> Path:
    path = tmp_path / "confirm.key"
    path.write_bytes(content)
    path.chmod(0o600)
    return path


def _base_env(tmp_path: Path, *, with_confirm_key: bool = True, with_pfsense_config: bool = False) -> dict[str, str]:
    env: dict[str, str] = {}
    if with_confirm_key:
        env["PFSENSE_SETUP_CONFIRM_KEY_FILE"] = str(_confirm_key_file(tmp_path))
    if with_pfsense_config:
        api_key_file = tmp_path / "api.key"
        api_key_file.write_bytes(b"fake-api-key-not-real")
        api_key_file.chmod(0o600)
        env["PFSENSE_API_URL"] = "https://pfsense.example"
        env["PFSENSE_IDENTITY"] = "admin"
        env["PFSENSE_API_KEY_FILE"] = str(api_key_file)
    return env


def _current_token(
    tmp_path: Path,
    env: dict[str, str],
    *,
    target_capability_posture: str,
    target_anchor_assurance: str,
    target_origin: str | None = None,
    target_identity: str | None = None,
) -> tuple[str, str]:
    """Independently recomputes the digest/token a correct inspection
    would show, without going through the module under test -- so
    tests never assert against a value the module itself produced."""

    posture = CapabilityPosture(target_capability_posture)
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


# --- inspection-only (no --confirm) -----------------------------------


def test_inspect_mode_returns_current_digest_and_token_without_pfsense_config(tmp_path):
    env = _base_env(tmp_path)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.INSPECT_PLAN_CURRENT
    assert result.plan_digest is not None
    assert result.confirmation_token is not None


def test_inspect_mode_without_confirm_key_file_env_var_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path, with_confirm_key=False)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR
    assert result.confirmation_token is None


def test_inspect_mode_with_missing_confirm_key_path_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path, with_confirm_key=False)
    env["PFSENSE_SETUP_CONFIRM_KEY_FILE"] = str(tmp_path / "does-not-exist.key")
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR


def test_inspect_mode_with_empty_confirm_key_file_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path, with_confirm_key=False)
    env["PFSENSE_SETUP_CONFIRM_KEY_FILE"] = str(_confirm_key_file(tmp_path, content=b"   \n"))
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR


def test_inspect_mode_with_symlinked_confirm_key_file_is_blocked_configuration_error(tmp_path):
    real = _confirm_key_file(tmp_path)
    link = tmp_path / "confirm-link.key"
    link.symlink_to(real)
    env = _base_env(tmp_path, with_confirm_key=False)
    env["PFSENSE_SETUP_CONFIRM_KEY_FILE"] = str(link)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR


def test_inspect_mode_never_touches_pfsense_even_when_config_is_present(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: calls.append("called") or (_FakeTransport(), _FakeClient()),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.INSPECT_PLAN_CURRENT
    assert calls == []


# --- malformed axis values ---------------------------------------------


def test_malformed_capability_posture_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="not-a-real-posture", target_anchor_assurance="none"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR
    assert result.plan_digest is None


def test_malformed_anchor_assurance_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path)
    result = run_setup_apply_from_environment(
        env, target_capability_posture="read_only", target_anchor_assurance="not-a-real-anchor"
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR
    assert result.plan_digest is None


# --- staleness -----------------------------------------------------------


def test_stale_plan_digest_is_refused_before_confirm_key_is_even_loaded(tmp_path):
    env = _base_env(tmp_path, with_confirm_key=False)
    env["PFSENSE_SETUP_CONFIRM_KEY_FILE"] = str(tmp_path / "does-not-exist.key")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest="0" * 64,
    )
    # Digest mismatch is caught before the (missing) confirm key is ever
    # loaded -- if it were BLOCKED_CONFIGURATION_ERROR instead, staleness
    # would not be checked first.
    assert result.outcome is ApplyOutcome.PLAN_STALE


# --- confirmation token verification -------------------------------------


def test_wrong_confirm_token_is_refused_before_pfsense_contact(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: calls.append("called") or (_FakeTransport(), _FakeClient()),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, _token = _current_token(
        tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token="0" * 64,
    )
    assert result.outcome is ApplyOutcome.CONFIRM_TOKEN_INVALID
    assert calls == []


def test_correct_token_without_plan_digest_still_verifies(tmp_path):
    env = _base_env(tmp_path)
    _digest, token = _current_token(
        tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none"
    )
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="none",
        confirm_token=token,
    )
    # Posture differs from the one the token was derived for, so the
    # token binding -- computed against *this* call's fresh digest --
    # must fail even though --plan-digest was never supplied at all.
    assert result.outcome is ApplyOutcome.CONFIRM_TOKEN_INVALID


def test_token_derived_for_one_target_identity_is_rejected_for_another_even_without_plan_digest(tmp_path):
    env = _base_env(tmp_path)
    _digest, token = _current_token(
        tmp_path,
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        target_identity="original-admin",
    )
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        target_identity="attacker-supplied-admin",
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.CONFIRM_TOKEN_INVALID


# --- posture support -------------------------------------------------------


def test_write_protected_posture_is_not_supported_even_with_a_valid_token(tmp_path, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: calls.append("called") or (_FakeTransport(), _FakeClient()),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(
        tmp_path, env, target_capability_posture="write_protected", target_anchor_assurance="hardware_witness"
    )
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="write_protected",
        target_anchor_assurance="hardware_witness",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.NOT_SUPPORTED_FOR_POSTURE
    assert calls == []


# --- pfSense configuration/credential errors --------------------------------


def test_read_only_valid_token_missing_pfsense_config_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path, with_pfsense_config=False)
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR


def test_read_only_valid_token_unreadable_api_key_file_is_blocked_configuration_error(tmp_path):
    env = _base_env(tmp_path, with_pfsense_config=True)
    Path(env["PFSENSE_API_KEY_FILE"]).write_bytes(b"")
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.BLOCKED_CONFIGURATION_ERROR


# --- connectivity -----------------------------------------------------------


def test_read_only_valid_token_connectivity_failure_closes_transport(tmp_path, monkeypatch):
    fake_transport = _FakeTransport()
    fake_client = _FakeClient(raises=PfSenseConnectionError("connection refused"))
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (fake_transport, fake_client),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.CONNECTIVITY_FAILED
    assert fake_client.called
    assert fake_transport.closed


# --- doctor / anchor readiness ----------------------------------------------


def test_read_only_hardware_witness_valid_token_doctor_not_ready(tmp_path, monkeypatch):
    fake_transport = _FakeTransport()
    fake_client = _FakeClient()
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (fake_transport, fake_client),
    )

    class _NotReady:
        ready = False

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_doctor_checks", lambda env: _NotReady())

    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(
        tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="hardware_witness"
    )
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="hardware_witness",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.DOCTOR_NOT_READY
    assert result.doctor_ready is False
    assert fake_client.called
    assert fake_transport.closed


def test_read_only_anchor_none_ignores_doctor_not_ready(tmp_path, monkeypatch):
    """`anchor=none` never needs witness readiness -- doctor is
    informational only for that anchor, never blocking."""

    fake_transport = _FakeTransport()
    fake_client = _FakeClient()
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (fake_transport, fake_client),
    )

    class _NotReady:
        ready = False

    monkeypatch.setattr("pfsense_mcp.security_setup_apply.run_doctor_checks", lambda env: _NotReady())

    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.APPLY_COMPLETED
    assert result.doctor_ready is False


# --- happy path --------------------------------------------------------------


def test_read_only_happy_path_completes_and_never_mutates(tmp_path, monkeypatch):
    fake_transport = _FakeTransport()
    fake_client = _FakeClient()
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (fake_transport, fake_client),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture="read_only",
        target_anchor_assurance="none",
        plan_digest=digest,
        confirm_token=token,
    )
    assert result.outcome is ApplyOutcome.APPLY_COMPLETED
    assert fake_client.called
    assert fake_transport.closed
    assert not hasattr(fake_client, "post")
    assert not hasattr(fake_client, "put")
    assert not hasattr(fake_client, "delete")


def test_rerun_after_success_is_idempotent_and_produces_the_same_outcome(tmp_path, monkeypatch):
    monkeypatch.setattr(
        "pfsense_mcp.security_setup_apply.build_pfsense_client",
        lambda config, api_key: (_FakeTransport(), _FakeClient()),
    )
    env = _base_env(tmp_path, with_pfsense_config=True)
    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")
    kwargs = {
        "target_capability_posture": "read_only",
        "target_anchor_assurance": "none",
        "plan_digest": digest,
        "confirm_token": token,
    }
    first = run_setup_apply_from_environment(env, **kwargs)  # type: ignore[arg-type]
    second = run_setup_apply_from_environment(env, **kwargs)  # type: ignore[arg-type]
    assert first.outcome is second.outcome is ApplyOutcome.APPLY_COMPLETED


# --- secret redaction --------------------------------------------------------


@pytest.mark.parametrize(
    "scenario",
    ["inspect", "invalid_token", "connectivity_failed", "apply_completed"],
)
def test_no_secret_material_leaks_into_any_result_across_the_matrix(tmp_path, monkeypatch, scenario):
    api_key_value = "super-secret-api-key-value"
    confirm_key_value = "super-secret-confirm-key-value"
    api_key_file = tmp_path / "api.key"
    api_key_file.write_bytes(api_key_value.encode())
    api_key_file.chmod(0o600)
    confirm_key_path = _confirm_key_file(tmp_path, content=confirm_key_value.encode())

    env = {
        "PFSENSE_SETUP_CONFIRM_KEY_FILE": str(confirm_key_path),
        "PFSENSE_API_URL": "https://pfsense.example",
        "PFSENSE_IDENTITY": "admin",
        "PFSENSE_API_KEY_FILE": str(api_key_file),
    }

    if scenario == "connectivity_failed":
        monkeypatch.setattr(
            "pfsense_mcp.security_setup_apply.build_pfsense_client",
            lambda config, api_key: (_FakeTransport(), _FakeClient(raises=PfSenseConnectionError("refused"))),
        )
    else:
        monkeypatch.setattr(
            "pfsense_mcp.security_setup_apply.build_pfsense_client",
            lambda config, api_key: (_FakeTransport(), _FakeClient()),
        )

    digest, token = _current_token(tmp_path, env, target_capability_posture="read_only", target_anchor_assurance="none")

    if scenario == "inspect":
        result = run_setup_apply_from_environment(
            env, target_capability_posture="read_only", target_anchor_assurance="none"
        )
    elif scenario == "invalid_token":
        result = run_setup_apply_from_environment(
            env,
            target_capability_posture="read_only",
            target_anchor_assurance="none",
            plan_digest=digest,
            confirm_token="0" * 64,
        )
    else:
        result = run_setup_apply_from_environment(
            env,
            target_capability_posture="read_only",
            target_anchor_assurance="none",
            plan_digest=digest,
            confirm_token=token,
        )

    serialized = repr(result)
    assert api_key_value not in serialized
    assert confirm_key_value not in serialized
    assert result.detail is not None
    assert api_key_value not in result.detail
    assert confirm_key_value not in result.detail
    if result.confirmation_token is not None:
        assert result.confirmation_token != confirm_key_value
        assert api_key_value not in result.confirmation_token
