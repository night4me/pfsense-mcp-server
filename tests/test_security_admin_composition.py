from __future__ import annotations

import json
import shutil
from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import (
    AdminCompositionError,
    AdministrativeContext,
    build_admin_context,
)
from pfsense_mcp.security_operation_journal import (
    AdministrativeOperationType,
    AdministrativeTransactionState,
    AuthoritativeRestartObservation,
    AuthoritativeServerState,
    DurableOperationState,
    RecoveryAction,
    RestartClassification,
)

T0 = "2026-08-19T21:00:00Z"
T1 = "2026-08-19T21:00:01Z"
T2 = "2026-08-19T21:00:02Z"
T3 = "2026-08-19T21:00:03Z"


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


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


def _authoritative(
    context: AdministrativeContext,
    *,
    server_state: AuthoritativeServerState = AuthoritativeServerState.CLEAN,
    final: bool = False,
    recovery: RecoveryAction | None = None,
) -> AuthoritativeRestartObservation:
    binding = context.binding
    return AuthoritativeRestartObservation(
        target_identity=binding.target_identity,
        target_origin=binding.target_origin,
        account_identity=binding.account_identity,
        approved_profile=binding.approved_profile,
        schema_version=binding.schema_version,
        schema_evidence_digest=binding.schema_evidence_digest,
        auth_methods=("KeyAuth",),
        server_state=server_state,
        final_verification_complete=final,
        applicable_recovery=recovery,
    )


def _create(context: AdministrativeContext, operation_id: str = "op-1") -> None:
    context._journal.create(
        context.new_operation_binding(operation_id=operation_id, operation_type=AdministrativeOperationType.BOOTSTRAP),
        timestamp=T0,
    )


def _append(
    context: AdministrativeContext,
    state: DurableOperationState,
    transaction: AdministrativeTransactionState,
    *,
    timestamp: str,
    recovery: RecoveryAction | None = None,
) -> None:
    context._journal.append(
        operation_id="op-1",
        state=state,
        transaction_state=transaction,
        mutation_index=1,
        timestamp=timestamp,
        recovery_action=recovery,
    )


def test_builds_fixed_secure_context_without_network_or_mutation(admin_env: dict[str, str], monkeypatch):
    calls: list[str] = []

    def forbidden(*args, **kwargs):
        calls.append("network")
        raise AssertionError("transport construction is not allowed during composition")

    monkeypatch.setattr("pfsense_mcp.security_admin_composition.HttpTransport", forbidden)
    monkeypatch.setattr("pfsense_mcp.security_admin_composition.BasicAuthHttpTransport", forbidden)
    context = build_admin_context(admin_env)
    availability = context.status.availability(authoritative=None)

    assert calls == []
    assert availability.bootstrap_available
    assert availability.recovery_action is None
    assert availability.restart_decision.classification is RestartClassification.CLEAN_NO_OPERATION
    assert context.binding.account_identity == "pfsense-mcp"
    assert context.binding.approved_profile == "write_protected"
    assert context.journal_path.parent == Path(admin_env["PFSENSE_ADMIN_STATE_DIR"])
    assert context.lock_path.parent == context.journal_path.parent
    assert not context.journal_path.exists()
    assert not context.lock_path.exists()


def test_context_and_config_repr_do_not_expose_secrets_or_secret_paths(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    rendered = repr(context) + repr(context.config) + repr(context._mutation_components)
    assert "synthetic-admin-key" not in rendered
    assert "synthetic-admin-password" not in rendered
    assert admin_env["PFSENSE_ADMIN_PASSWORD_FILE"] not in rendered
    assert admin_env["PFSENSE_API_KEY_FILE"] not in rendered


@pytest.mark.parametrize(
    "missing",
    [
        "PFSENSE_API_URL",
        "PFSENSE_IDENTITY",
        "PFSENSE_API_KEY_FILE",
        "PFSENSE_API_VERSION",
        "PFSENSE_TLS_MODE",
        "PFSENSE_ADMIN_USERNAME",
        "PFSENSE_ADMIN_PASSWORD_FILE",
        "PFSENSE_SERVICE_API_KEY_FILE",
        "PFSENSE_ADMIN_STATE_DIR",
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE",
        "PFSENSE_ADMIN_SCHEMA_FILE",
        "PFSENSE_ADMIN_SCHEMA_VERSION",
        "PFSENSE_RESTAPI_PACKAGE_VERSION",
    ],
)
def test_missing_required_configuration_fails_closed(admin_env: dict[str, str], missing: str):
    del admin_env[missing]
    with pytest.raises(AdminCompositionError, match="Missing required"):
        build_admin_context(admin_env)


@pytest.mark.parametrize(
    "variable",
    [
        "PFSENSE_API_KEY_FILE",
        "PFSENSE_ADMIN_PASSWORD_FILE",
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE",
        "PFSENSE_ADMIN_SCHEMA_FILE",
        "PFSENSE_TLS_CA_FILE",
    ],
)
def test_symlink_input_files_are_refused(admin_env: dict[str, str], variable: str, tmp_path: Path):
    original = Path(admin_env[variable])
    link = tmp_path / f"link-{variable.lower()}"
    link.symlink_to(original)
    admin_env[variable] = str(link)
    with pytest.raises(AdminCompositionError):
        build_admin_context(admin_env)


def test_unsafe_secret_permission_and_state_directory_are_refused(admin_env: dict[str, str]):
    password = Path(admin_env["PFSENSE_ADMIN_PASSWORD_FILE"])
    password.chmod(0o644)
    with pytest.raises(AdminCompositionError):
        build_admin_context(admin_env)
    password.chmod(0o600)
    Path(admin_env["PFSENSE_ADMIN_STATE_DIR"]).chmod(0o755)
    with pytest.raises(AdminCompositionError, match="owner-only"):
        build_admin_context(admin_env)


def test_relative_and_reused_security_paths_are_refused(admin_env: dict[str, str]):
    admin_env["PFSENSE_ADMIN_PASSWORD_FILE"] = "relative-password"
    with pytest.raises(AdminCompositionError, match="absolute"):
        build_admin_context(admin_env)
    admin_env["PFSENSE_ADMIN_PASSWORD_FILE"] = admin_env["PFSENSE_API_KEY_FILE"]
    with pytest.raises(AdminCompositionError, match="distinct"):
        build_admin_context(admin_env)


@pytest.mark.parametrize(
    "name",
    [
        "PFSENSE_SERVICE_ACCOUNT_USERNAME",
        "PFSENSE_SERVICE_ACCOUNT_DESCRIPTION",
        "PFSENSE_SERVICE_ACCOUNT_PROFILE",
    ],
)
def test_service_account_and_profile_overrides_are_refused(admin_env: dict[str, str], name: str):
    admin_env[name] = "attacker-selected"
    with pytest.raises(AdminCompositionError, match="must not be overridden"):
        build_admin_context(admin_env)


def test_service_key_symlink_and_unsafe_existing_file_are_refused(admin_env: dict[str, str]):
    path = Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"])
    path.symlink_to(Path(admin_env["PFSENSE_API_KEY_FILE"]))
    with pytest.raises(AdminCompositionError, match="symbolic link"):
        build_admin_context(admin_env)
    path.unlink()
    _write_secure(path, b"existing-service-key", mode=0o644)
    with pytest.raises(AdminCompositionError):
        build_admin_context(admin_env)


def test_insecure_tls_and_malformed_package_or_schema_are_refused(admin_env: dict[str, str]):
    admin_env["PFSENSE_TLS_MODE"] = "insecure"
    admin_env.pop("PFSENSE_TLS_CA_FILE")
    with pytest.raises(AdminCompositionError, match="forbids insecure TLS"):
        build_admin_context(admin_env)
    admin_env["PFSENSE_TLS_MODE"] = "strict"
    admin_env["PFSENSE_RESTAPI_PACKAGE_VERSION"] = "v2.10"
    with pytest.raises(AdminCompositionError, match="three-part"):
        build_admin_context(admin_env)
    admin_env["PFSENSE_RESTAPI_PACKAGE_VERSION"] = "2.10.0"
    _write_secure(Path(admin_env["PFSENSE_ADMIN_SCHEMA_FILE"]), b"{}")
    with pytest.raises(AdminCompositionError, match="non-empty"):
        build_admin_context(admin_env)


def test_schema_without_approved_profile_evidence_fails_closed(admin_env: dict[str, str]):
    _write_secure(Path(admin_env["PFSENSE_ADMIN_SCHEMA_FILE"]), json.dumps({"paths": {}}).encode())
    with pytest.raises(AdminCompositionError, match="source-cross-checked"):
        build_admin_context(admin_env)


def test_target_origin_and_identity_bind_distinct_namespaces(admin_env: dict[str, str]):
    first = build_admin_context(admin_env)
    changed_identity = dict(admin_env, PFSENSE_IDENTITY="lab-appliance-two")
    second = build_admin_context(changed_identity)
    changed_origin = dict(admin_env, PFSENSE_API_URL="https://other.example.invalid")
    third = build_admin_context(changed_origin)
    assert len({first.binding.namespace, second.binding.namespace, third.binding.namespace}) == 3
    assert len({first.journal_path, second.journal_path, third.journal_path}) == 3
    assert len({first.lock_path, second.lock_path, third.lock_path}) == 3


def test_schema_drift_reuses_target_namespace_and_fails_against_existing_journal(admin_env: dict[str, str]):
    first = build_admin_context(admin_env)
    _create(first)
    schema = json.loads(Path(admin_env["PFSENSE_ADMIN_SCHEMA_FILE"]).read_text(encoding="utf-8"))
    schema["info"] = {"title": "drifted-but-still-structurally-valid"}
    _write_secure(Path(admin_env["PFSENSE_ADMIN_SCHEMA_FILE"]), json.dumps(schema).encode())
    with pytest.raises(AdminCompositionError, match="another target"):
        build_admin_context(admin_env)


def test_reused_journal_for_another_target_is_untrusted(admin_env: dict[str, str]):
    first = build_admin_context(admin_env)
    _create(first)
    second_env = dict(admin_env, PFSENSE_IDENTITY="lab-appliance-two")
    second = build_admin_context(second_env)
    shutil.copy2(first.journal_path, second.journal_path)
    shutil.copy2(
        first.journal_path.with_name(f"{first.journal_path.name}.head"),
        second.journal_path.with_name(f"{second.journal_path.name}.head"),
    )
    with pytest.raises(AdminCompositionError, match="another target"):
        build_admin_context(second_env)


def test_corrupt_journal_and_lock_fail_during_composition(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _write_secure(context.journal_path, b"not-a-journal\n")
    _write_secure(context.journal_path.with_name(f"{context.journal_path.name}.head"), b"not-a-head\n")
    with pytest.raises(AdminCompositionError, match="corrupt"):
        build_admin_context(admin_env)
    context.journal_path.unlink()
    context.journal_path.with_name(f"{context.journal_path.name}.head").unlink()
    _write_secure(context.lock_path, b"not-a-lock\n")
    with pytest.raises(AdminCompositionError, match="lock"):
        build_admin_context(admin_env)


def test_lock_owned_by_different_operation_fails_composition(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _create(context, operation_id="op-1")
    context._lock.acquire("op-2", timestamp=T0)
    try:
        with pytest.raises(AdminCompositionError, match="different operation"):
            build_admin_context(admin_env)
    finally:
        context._lock.release(timestamp=T1)


def test_unfinished_operation_blocks_bootstrap_and_unknown_send_never_resumes(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _create(context)
    _append(
        context,
        DurableOperationState.PRE_SEND_READY,
        AdministrativeTransactionState.NOT_STARTED,
        timestamp=T1,
    )
    _append(
        context,
        DurableOperationState.MUTATION_INTENT_RECORDED,
        AdministrativeTransactionState.USER_CREATED,
        timestamp=T2,
    )
    _append(
        context,
        DurableOperationState.MUTATION_RESULT_UNKNOWN,
        AdministrativeTransactionState.USER_CREATED,
        timestamp=T3,
    )
    availability = context.status.availability(authoritative=_authoritative(context))
    assert not availability.bootstrap_available
    assert availability.recovery_action is None
    assert availability.restart_decision.classification is RestartClassification.MUTATION_SENT_RESULT_UNKNOWN


def test_recovery_state_exposes_only_exact_recovery_action(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _create(context)
    _append(
        context,
        DurableOperationState.PRE_SEND_READY,
        AdministrativeTransactionState.NOT_STARTED,
        timestamp=T1,
    )
    _append(
        context,
        DurableOperationState.MUTATION_INTENT_RECORDED,
        AdministrativeTransactionState.RECOVERY_MUTATION_SENT,
        timestamp=T2,
    )
    _append(
        context,
        DurableOperationState.RECOVERY_REQUIRED,
        AdministrativeTransactionState.RECOVERY_OBJECT_IDENTIFIED,
        timestamp=T3,
        recovery=RecoveryAction.REVOKE_ORPHAN_KEY,
    )
    availability = context.status.availability(
        authoritative=_authoritative(context, recovery=RecoveryAction.REVOKE_ORPHAN_KEY)
    )
    assert not availability.bootstrap_available
    assert availability.recovery_action is RecoveryAction.REVOKE_ORPHAN_KEY
    assert availability.restart_decision.classification is RestartClassification.RECOVERY_REQUIRED


def test_completed_operation_never_silently_reopens_bootstrap(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _create(context)
    _append(
        context,
        DurableOperationState.PRE_SEND_READY,
        AdministrativeTransactionState.NOT_STARTED,
        timestamp=T1,
    )
    _append(
        context,
        DurableOperationState.COMPLETED,
        AdministrativeTransactionState.VERIFIED,
        timestamp=T2,
    )
    _write_secure(Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"]), b"synthetic-service-key")
    availability = context.status.availability(
        authoritative=_authoritative(context, server_state=AuthoritativeServerState.EXPECTED_COMPLETED, final=True)
    )
    assert not availability.bootstrap_available
    assert availability.restart_decision.classification is RestartClassification.CLEAN_COMPLETED


def test_custody_artifact_is_observed_internally_and_cannot_be_hidden(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    custody = Path(admin_env["PFSENSE_SERVICE_API_KEY_FILE"])
    _write_secure(custody, b"synthetic-service-key")
    availability = context.status.availability(authoritative=None)
    assert not availability.bootstrap_available
    assert availability.restart_decision.classification is RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE
    custody.chmod(0o644)
    assert (
        context.status.classify(authoritative=None).classification
        is RestartClassification.CORRUPT_OR_UNTRUSTED_LOCAL_STATE
    )


def test_target_schema_auth_and_profile_drift_block_bootstrap(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    _create(context)
    observed = _authoritative(context)
    for drifted in (
        replace(observed, target_identity="other"),
        replace(observed, target_origin="https://other.invalid"),
        replace(observed, approved_profile="other"),
        replace(observed, schema_version="other"),
        replace(observed, auth_methods=("KeyAuth", "BasicAuth")),
    ):
        availability = context.status.availability(authoritative=drifted)
        assert not availability.bootstrap_available
        assert availability.restart_decision.classification is RestartClassification.RECOVERY_REQUIRED


def test_context_has_no_public_mutating_or_generic_dispatch_surface(admin_env: dict[str, str]):
    context = build_admin_context(admin_env)
    public = {name for name in dir(context) if not name.startswith("_")}
    assert public == {"binding", "config", "journal_path", "lock_path", "new_operation_binding", "status"}
    status_public = {name for name in dir(context.status) if not name.startswith("_")}
    assert status_public == {"availability", "classify"}
    source = Path("src/pfsense_mcp/security_admin_composition.py").read_text(encoding="utf-8")
    assert ".request(" not in source
    assert "generic" not in public
    assert "execute" not in public
    assert "provision" not in public
    assert "recover" not in public
    assert "delete" not in public
    assert "patch" not in public
