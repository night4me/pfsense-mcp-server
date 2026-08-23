"""Focused tests for `pfsense-mcp-security recover` -- the CLI wiring
around `security_recovery_orchestration.run_recovery_from_environment()`.

Most scenarios are exercised by monkeypatching
`pfsense_mcp.security_cli.run_recovery_from_environment` with a canned
`RecoveryOrchestrationResult` -- this file is about argument parsing,
human/--json formatting, stdin-confirmation, and exit-code mapping, not
about re-testing orchestration logic (see
`tests/test_security_recovery_orchestration.py` for that). One
end-to-end test drives the real `main(["recover", ...])` path against a
fully valid, real (but offline-stubbed) environment to prove the wiring
works together.
"""

from __future__ import annotations

import io
import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp import security_cli
from pfsense_mcp.security_admin_composition import build_admin_context
from pfsense_mcp.security_bootstrap_recovery import RecoveryDeletionEvidence
from pfsense_mcp.security_cli import main
from pfsense_mcp.security_operation_journal import AdministrativeOperationType, RecoveryAction
from pfsense_mcp.security_recovery_orchestration import (
    RecoveryOrchestrationOutcome,
    RecoveryOrchestrationResult,
)


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


def _canned(monkeypatch, result: RecoveryOrchestrationResult) -> dict[str, object]:
    captured: dict[str, object] = {}

    def fake(env, *, execute_action=None, confirm_token=None):
        captured["execute_action"] = execute_action
        captured["confirm_token"] = confirm_token
        return result

    monkeypatch.setattr(security_cli, "run_recovery_from_environment", fake)
    return captured


def test_no_recovery_needed_human_output_exit_zero(capsys, monkeypatch):
    _canned(monkeypatch, RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED, "clean"))

    exit_code = main(["recover"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Outcome: no_recovery_needed" in out
    assert "read-only inspection only" in out


def test_recovery_needed_prints_token_and_execute_command(capsys, monkeypatch):
    _canned(
        monkeypatch,
        RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_NEEDED,
            "revoke needed",
            operation_id="op-1",
            recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
            confirmation_token="a" * 64,
        ),
    )

    exit_code = main(["recover"])

    assert exit_code == 1
    out = capsys.readouterr().out
    assert "Recovery action: revoke_orphan_key" in out
    assert f"Confirmation token: {'a' * 64}" in out
    assert f"--execute revoke_orphan_key --confirm {'a' * 64}" in out


def test_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    result = RecoveryOrchestrationResult(
        RecoveryOrchestrationOutcome.RECOVERY_COMPLETED,
        "done",
        operation_id="op-2",
        recovery_action=RecoveryAction.DELETE_DEDICATED_USER,
        evidence=RecoveryDeletionEvidence(
            object_kind="user",
            selected_id=9,
            objects_before=2,
            objects_after=1,
            verified_absent=True,
            unrelated_objects_preserved=True,
        ),
    )
    _canned(monkeypatch, result)

    first_exit = main(["recover", "--json"])
    first_out = capsys.readouterr().out
    second_exit = main(["recover", "--json"])
    second_out = capsys.readouterr().out

    assert first_exit == 0
    assert second_exit == 0
    assert first_out == second_out
    payload = json.loads(first_out)
    assert payload["outcome"] == "recovery_completed"
    assert payload["recovery_action"] == "delete_dedicated_user"
    assert payload["evidence"]["object_kind"] == "user"
    assert payload["evidence"]["selected_id"] == 9


@pytest.mark.parametrize(
    ("outcome", "expected_exit"),
    [
        (RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED, 0),
        (RecoveryOrchestrationOutcome.RECOVERY_ALREADY_COMPLETE, 0),
        (RecoveryOrchestrationOutcome.RECOVERY_COMPLETED, 0),
        (RecoveryOrchestrationOutcome.RECOVERY_NEEDED, 1),
        (RecoveryOrchestrationOutcome.EXECUTE_ACTION_MISMATCH, 2),
        (RecoveryOrchestrationOutcome.BLOCKED_LOCK_CONTENTION, 3),
        (RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR, 4),
        (RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED, 5),
        (RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID, 6),
        (RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE, 7),
        (RecoveryOrchestrationOutcome.BLOCKED_AMBIGUOUS_RECOVERY_STATE, 8),
        (RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE, 9),
    ],
)
def test_exit_code_mapping_is_exhaustive_and_correct(capsys, monkeypatch, outcome, expected_exit):
    _canned(monkeypatch, RecoveryOrchestrationResult(outcome, "synthetic detail"))

    exit_code = main(["recover"])

    assert exit_code == expected_exit


def test_exit_code_mapping_covers_every_outcome_member():
    mapped = set(security_cli._RECOVERY_EXIT_CODES.keys())
    assert mapped == set(RecoveryOrchestrationOutcome)


def test_bare_invocation_never_passes_an_execute_action(monkeypatch):
    captured = _canned(monkeypatch, RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED, "x"))

    main(["recover"])

    assert captured["execute_action"] is None
    assert captured["confirm_token"] is None


def test_execute_with_confirm_passes_both_through(monkeypatch):
    captured = _canned(
        monkeypatch, RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID, "x")
    )

    main(["recover", "--execute", "revoke_orphan_key", "--confirm", "sometoken"])

    assert captured["execute_action"] is RecoveryAction.REVOKE_ORPHAN_KEY
    assert captured["confirm_token"] == "sometoken"


def test_confirm_dash_reads_token_from_stdin(monkeypatch):
    captured = _canned(
        monkeypatch, RecoveryOrchestrationResult(RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID, "x")
    )
    monkeypatch.setattr("sys.stdin", io.StringIO("token-from-stdin\n"))

    main(["recover", "--execute", "revoke_orphan_key", "--confirm", "-"])

    assert captured["confirm_token"] == "token-from-stdin"


def test_confirm_without_execute_is_a_usage_error(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["recover", "--confirm", "sometoken"])

    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "--confirm requires --execute" in err


def test_execute_rejects_arbitrary_action_strings(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["recover", "--execute", "delete_everything", "--confirm", "x"])

    assert excinfo.value.code == 2
    err = capsys.readouterr().err
    assert "invalid choice" in err


def test_configuration_error_default_environment(capsys, monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_"):
            monkeypatch.delenv(name, raising=False)

    exit_code = main(["recover"])

    assert exit_code == 4
    out = capsys.readouterr().out
    assert "blocked_configuration_error" in out


def test_never_prints_secret_looking_detail(capsys, monkeypatch):
    secret_marker = "s3cr3t-should-never-appear"
    _canned(
        monkeypatch,
        RecoveryOrchestrationResult(
            RecoveryOrchestrationOutcome.RECOVERY_COMPLETED,
            "done (no secret in detail)",
            recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
            evidence=RecoveryDeletionEvidence(
                object_kind="api_key",
                selected_id=1,
                objects_before=2,
                objects_after=1,
                verified_absent=True,
                unrelated_objects_preserved=True,
            ),
        ),
    )

    main(["recover", "--json"])
    out = capsys.readouterr().out
    assert secret_marker not in out
    assert "never a credential" in out or "Never prints" in out


def test_help_documents_exit_codes_and_offline_only_and_standalone_boundary(capsys):
    with pytest.raises(SystemExit):
        main(["recover", "--help"])
    out = capsys.readouterr().out
    assert "Exit codes:" in out
    for code_marker in ("0 no recovery needed", "6 the confirmation token", "9 local recovery"):
        assert code_marker in out
    assert "Standalone" in out
    assert "not folded into" in out


def test_module_docstring_lists_recover_as_standalone_and_offline_verified():
    joined = " ".join(security_cli.__doc__.split())
    assert "`recover`:" in joined
    assert "Standalone -- not folded into `bootstrap` or a future `setup` wizard." in joined
    assert "Verified offline only" in joined


# --- end-to-end: real main() -> real orchestration -> stubbed HTTP-level closures --


@pytest.fixture
def real_admin_env(tmp_path: Path, monkeypatch) -> None:
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
    env = {
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
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_end_to_end_main_recover_inspect_against_real_environment_with_no_incident(real_admin_env, capsys):
    exit_code = main(["recover", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "no_recovery_needed"
    assert payload["confirmation_token"] is None


def test_end_to_end_main_recover_execute_against_real_environment(real_admin_env, capsys, monkeypatch):
    bootstrap_context = build_admin_context(dict(os.environ))
    binding = bootstrap_context.new_operation_binding(
        operation_id="incident-1", operation_type=AdministrativeOperationType.BOOTSTRAP
    )
    bootstrap_context._journal.create(binding, timestamp="2026-08-23T00:00:00Z")
    from pfsense_mcp.security_operation_journal import AdministrativeTransactionState, DurableOperationState

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
        state=DurableOperationState.RECOVERY_REQUIRED,
        transaction_state=AdministrativeTransactionState.NOT_STARTED,
        mutation_index=1,
        timestamp="2026-08-23T00:00:03Z",
        recovery_action=RecoveryAction.REVOKE_ORPHAN_KEY,
    )

    recovery_context = build_admin_context(
        dict(os.environ), operation_type=AdministrativeOperationType.RECOVER_ORPHAN_KEY
    )
    from pfsense_mcp.security_bootstrap_client import ObservedApiKey

    key = ObservedApiKey(
        id=7, username="pfsense-mcp", descr="pfsense-mcp-server primary API key", hash_algo="sha256", length_bytes=32
    )
    evidence = RecoveryDeletionEvidence(
        object_kind="api_key",
        selected_id=7,
        objects_before=2,
        objects_after=1,
        verified_absent=True,
        unrelated_objects_preserved=True,
    )
    components = replace(
        recovery_context._mutation_components,
        identify_orphan_key_candidate=lambda: key,
        revoke_orphan_key_call=lambda: evidence,
    )
    recovery_context = replace(recovery_context, _mutation_components=components)

    def fake_build(source, *, operation_type=AdministrativeOperationType.BOOTSTRAP):
        return bootstrap_context if operation_type is AdministrativeOperationType.BOOTSTRAP else recovery_context

    monkeypatch.setattr("pfsense_mcp.security_recovery_orchestration.build_admin_context", fake_build)

    inspect_exit = main(["recover", "--json"])
    inspect_payload = json.loads(capsys.readouterr().out)
    assert inspect_exit == 1
    assert inspect_payload["outcome"] == "recovery_needed"
    token = inspect_payload["confirmation_token"]
    assert token

    execute_exit = main(["recover", "--execute", "revoke_orphan_key", "--confirm", token, "--json"])
    execute_payload = json.loads(capsys.readouterr().out)

    assert execute_exit == 0
    assert execute_payload["outcome"] == "recovery_completed"
    assert execute_payload["evidence"]["object_kind"] == "api_key"
    snapshot = recovery_context._journal.load()
    assert snapshot.latest.state.value == "completed"
    # The original incident journal remains untouched.
    original_snapshot = bootstrap_context._journal.load()
    assert original_snapshot.latest.state.value == "recovery_required"
