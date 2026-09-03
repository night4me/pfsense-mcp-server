"""`target_profile` support in `run_recovery_from_environment()` -- the
read_only-profile counterpart of `test_security_recovery_orchestration.py`.

POST-v1.0 MANAGED READ-ONLY WIZARD INTEGRATION mission (2026-08-29):
before this slice, a managed read_only `setup apply` hitting
`BLOCKED_PRIOR_OPERATION` had no correct way to inline-inspect its own
account's incident -- calling `run_recovery_from_environment()`
unparameterized would have silently inspected the unrelated
`pfsense-mcp` (write_protected) journal instead. This file proves the
fix: `target_profile="read_only"` reaches
`build_readonly_admin_context()`, never `build_admin_context()`, and
that a read_only incident is inspected/recovered against its own,
entirely separate namespace -- never conflated with a write_protected
one for the identical target."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import build_admin_context
from pfsense_mcp.security_bootstrap_client import ObservedApiKey
from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    DurableOperationState,
    RecoveryAction,
)
from pfsense_mcp.security_readonly_admin_composition import build_readonly_admin_context
from pfsense_mcp.security_recovery_orchestration import (
    RecoveryOrchestrationOutcome,
    run_recovery_from_environment,
)


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


@pytest.fixture
def admin_env(tmp_path: Path) -> dict[str, str]:
    """Both write_protected's `PFSENSE_SERVICE_API_KEY_FILE` and
    read_only's own `PFSENSE_READONLY_SERVICE_API_KEY_FILE` are present
    together -- mirrors a real operator environment where both profiles'
    env vars are simultaneously exported, since only one is ever
    consulted per call, selected by `target_profile`."""

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
        "PFSENSE_READONLY_SERVICE_API_KEY_FILE": str(custody / "pfsense-mcp-readonly.key"),
        "PFSENSE_ADMIN_STATE_DIR": str(state),
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE": str(tmp_path / "journal-key"),
        "PFSENSE_ADMIN_SCHEMA_FILE": str(schema),
        "PFSENSE_ADMIN_SCHEMA_VERSION": "restapi-v2.10",
        "PFSENSE_RESTAPI_PACKAGE_VERSION": "2.10.0",
    }


# --- Profile selection reaches the correct builder, never the other one ----


def test_read_only_target_profile_never_calls_build_admin_context(admin_env, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_recovery_orchestration.build_admin_context",
        lambda *a, **k: calls.append("write_protected") or pytest.fail("build_admin_context must not be called"),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_recovery_orchestration.build_readonly_admin_context",
        lambda *a, **k: calls.append("read_only") or build_readonly_admin_context(admin_env, **k),
    )

    result = run_recovery_from_environment(admin_env, target_profile="read_only")

    assert calls == ["read_only"]
    assert result.outcome is RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED


def test_write_protected_default_never_calls_build_readonly_admin_context(admin_env, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        "pfsense_mcp.security_recovery_orchestration.build_admin_context",
        lambda *a, **k: calls.append("write_protected") or build_admin_context(admin_env, **k),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_recovery_orchestration.build_readonly_admin_context",
        lambda *a, **k: calls.append("read_only") or pytest.fail("build_readonly_admin_context must not be called"),
    )

    result = run_recovery_from_environment(admin_env)

    assert calls == ["write_protected"]
    assert result.outcome is RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED


# --- Full read_only incident inspection, real journals -----------------


_READONLY_KEY = ObservedApiKey(
    id=11,
    username="pfsense-mcp-readonly",
    descr="pfsense-mcp-server read-only API key",
    hash_algo="sha256",
    length_bytes=32,
)

T0 = "2026-08-29T00:00:00Z"


def _create_readonly_bootstrap_incident(context, *, operation_id: str = "readonly-incident-1") -> None:
    binding = context.new_operation_binding(
        operation_id=operation_id, operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    context._journal.create(binding, timestamp=T0)
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.PRE_SEND_READY,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-29T00:00:01Z",
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.MUTATION_INTENT_RECORDED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-29T00:00:02Z",
    )
    context._journal.append(
        operation_id=operation_id,
        state=DurableOperationState.RECOVERY_REQUIRED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-29T00:00:03Z",
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
    )


def test_read_only_incident_is_inspected_against_its_own_namespace_and_issues_a_token(admin_env, monkeypatch):
    """Primes ONLY the read_only account's bootstrap journal to
    RECOVERY_REQUIRED (the write_protected journal for the identical
    target never exists in this test) -- proves target_profile="read_only"
    reaches, classifies, and issues a confirmation token for exactly
    that account's own incident, never the other profile's (nonexistent
    here) journal."""

    readonly_bootstrap_context = build_readonly_admin_context(admin_env)
    _create_readonly_bootstrap_incident(readonly_bootstrap_context)

    readonly_recovery_context = build_readonly_admin_context(
        admin_env, operation_type=AdministrativeOperationType.RECOVER_ORPHAN_KEY
    )
    components = replace(
        readonly_recovery_context._mutation_components,
        identify_orphan_key_candidate=lambda: _READONLY_KEY,
    )
    readonly_recovery_context = replace(readonly_recovery_context, _mutation_components=components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP, resolution_operation_id=None):
        return (
            readonly_bootstrap_context
            if operation_type is AdministrativeOperationType.BOOTSTRAP
            else readonly_recovery_context
        )

    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_readonly_admin_context", fake_build)
    monkeypatch.setattr(
        "pfsense_mcp.security_recovery_orchestration.build_admin_context",
        lambda *a, **k: pytest.fail("build_admin_context must not be called for target_profile=read_only"),
    )

    result = run_recovery_from_environment(admin_env, target_profile="read_only")

    assert result.outcome is RecoveryOrchestrationOutcome.RECOVERY_NEEDED
    assert result.recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY
    assert result.confirmation_token is not None
    assert len(result.confirmation_token) == 64
