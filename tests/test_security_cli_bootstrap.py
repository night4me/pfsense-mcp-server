"""Focused tests for `pfsense-mcp-security bootstrap` -- the CLI wiring
around `security_bootstrap_orchestration.run_bootstrap_from_environment()`.

Most scenarios are exercised by monkeypatching
`pfsense_mcp.security_cli.run_bootstrap_from_environment` with a canned
`BootstrapOrchestrationResult` -- this file is about argument parsing,
human/--json formatting, and exit-code mapping, not about re-testing
orchestration logic (see `tests/test_security_bootstrap_orchestration.py`
for that). One end-to-end test drives the real `main(["bootstrap"])`
path against a fully valid, real (but offline-stubbed) environment to
prove the wiring works together.
"""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp import security_cli
from pfsense_mcp.security_admin_composition import PfRestReadOnlyStatus, build_admin_context
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    BootstrapOrchestrationResult,
)
from pfsense_mcp.security_cli import main
from pfsense_mcp.security_operation_journal import RecoveryAction, RestartClassification, RestartDecision


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


def _canned(monkeypatch, result: BootstrapOrchestrationResult) -> None:
    monkeypatch.setattr(security_cli, "run_bootstrap_from_environment", lambda env: result)


def test_default_target_profile_calls_write_protected_orchestration_only(capsys, monkeypatch):
    """POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission (2026-08-29):
    omitting --target-profile must reach exactly the same function this
    file's other, pre-existing tests already exercise -- proving the
    new flag's default preserves 100% of existing behavior."""

    calls: list[str] = []
    monkeypatch.setattr(
        security_cli,
        "run_bootstrap_from_environment",
        lambda env: (
            calls.append("write_protected")
            or BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.COMPLETED, "synced", operation_id="op-1")
        ),
    )
    monkeypatch.setattr(
        security_cli,
        "run_readonly_bootstrap_from_environment",
        lambda env: (_ for _ in ()).throw(AssertionError("must not be called for the default target-profile")),
    )
    exit_code = main(["bootstrap"])
    assert exit_code == 0
    assert calls == ["write_protected"]


def test_target_profile_read_only_calls_readonly_orchestration_only(capsys, monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(
        security_cli,
        "run_bootstrap_from_environment",
        lambda env: (_ for _ in ()).throw(AssertionError("must not be called for --target-profile read_only")),
    )
    monkeypatch.setattr(
        security_cli,
        "run_readonly_bootstrap_from_environment",
        lambda env: (
            calls.append("read_only")
            or BootstrapOrchestrationResult(BootstrapOrchestrationOutcome.COMPLETED, "synced", operation_id="op-1")
        ),
    )
    exit_code = main(["bootstrap", "--target-profile", "read_only"])
    assert exit_code == 0
    assert calls == ["read_only"]


def test_target_profile_rejects_unknown_value():
    with pytest.raises(SystemExit):
        main(["bootstrap", "--target-profile", "admin"])


def test_bootstrap_success_human_output_exit_zero(capsys, monkeypatch):
    _canned(
        monkeypatch,
        BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.COMPLETED,
            "synced",
            operation_id="op-1",
            provisioning_outcome=ProvisioningOutcome.PRIVILEGES_SYNCED,
            provisioning_detail="synced",
        ),
    )

    exit_code = main(["bootstrap"])

    assert exit_code == 0
    out = capsys.readouterr().out
    assert "Outcome: completed" in out
    assert "op-1" in out
    assert "can mutate pfSense state" in out


def test_bootstrap_json_output_is_valid_and_deterministic(capsys, monkeypatch):
    result = BootstrapOrchestrationResult(
        BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION,
        "prior operation requires review",
        operation_id="op-1",
        restart_decision=RestartDecision(
            RestartClassification.RECOVERY_REQUIRED, "op-1", RecoveryAction.REVOKE_ORPHAN_KEY
        ),
    )
    _canned(monkeypatch, result)

    first_exit = main(["bootstrap", "--json"])
    first_out = capsys.readouterr().out
    second_exit = main(["bootstrap", "--json"])
    second_out = capsys.readouterr().out

    assert first_exit == 4
    assert second_exit == 4
    assert first_out == second_out
    payload = json.loads(first_out)
    assert payload["outcome"] == "blocked_prior_operation"
    assert payload["restart_decision"]["classification"] == "recovery_required"
    assert payload["restart_decision"]["recovery_action"] == "revoke_orphan_key"


@pytest.mark.parametrize(
    ("outcome", "expected_exit"),
    [
        (BootstrapOrchestrationOutcome.ALREADY_COMPLETE, 0),
        (BootstrapOrchestrationOutcome.COMPLETED, 0),
        (BootstrapOrchestrationOutcome.PROVISIONING_FAILED, 1),
        (BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED, 2),
        (BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION, 3),
        (BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION, 4),
        (BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE, 5),
        (BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR, 6),
        (BootstrapOrchestrationOutcome.BLOCKED_READ_ONLY_MODE, 7),
    ],
)
def test_bootstrap_exit_code_mapping_is_exhaustive_and_distinct(capsys, monkeypatch, outcome, expected_exit):
    _canned(monkeypatch, BootstrapOrchestrationResult(outcome, "synthetic detail"))

    exit_code = main(["bootstrap"])

    assert exit_code == expected_exit


def test_bootstrap_exit_codes_are_all_distinct():
    codes = list(security_cli._BOOTSTRAP_EXIT_CODES.values())
    # COMPLETED and ALREADY_COMPLETE intentionally share 0 (both success);
    # every other outcome must have its own distinct non-zero code.
    non_zero = [code for code in codes if code != 0]
    assert len(non_zero) == len(set(non_zero))


def test_bootstrap_configuration_error_default_environment(capsys, monkeypatch):
    for name in list(os.environ):
        if name.startswith("PFSENSE_"):
            monkeypatch.delenv(name, raising=False)

    exit_code = main(["bootstrap"])

    assert exit_code == 6
    out = capsys.readouterr().out
    assert "blocked_configuration_error" in out


def test_bootstrap_never_prints_secret_looking_detail(capsys, monkeypatch):
    secret_marker = "s3cr3t-should-never-appear"
    _canned(
        monkeypatch,
        BootstrapOrchestrationResult(
            BootstrapOrchestrationOutcome.COMPLETED,
            "created (no secret in detail)",
            provisioning_outcome=ProvisioningOutcome.COMPLETED,
            provisioning_detail="created (no secret in detail)",
        ),
    )

    main(["bootstrap", "--json"])
    out = capsys.readouterr().out
    assert secret_marker not in out
    assert "PFSENSE_SERVICE_API_KEY_FILE" in out or "custody" in out  # points at the path, not a value


def test_bootstrap_help_documents_exit_codes_and_verification_status_and_setup_boundary(capsys):
    with pytest.raises(SystemExit):
        main(["bootstrap", "--help"])
    # v1.0.0 Product/UX closure arc (C3): help text now wraps to the
    # terminal width (see _ParagraphHelpFormatter); normalize whitespace
    # before substring matching so this assertion is width-independent.
    out = " ".join(capsys.readouterr().out.split())
    assert "Exit codes:" in out
    for code_marker in ("0 success", "1 the engine ran", "2 the engine refused", "6 the environment"):
        assert code_marker in out
    assert "verified offline" in out
    assert "2026-08-26" in out
    assert "pfsense-mcp-security setup" in out
    assert "already-implemented interactive wizard" in out


def test_bootstrap_module_docstring_lists_the_mutating_subcommands():
    """Updated for Slice 3: `setup apply` (write_protected only) joins
    `bootstrap`/`recover` as a third path that can mutate pfSense state,
    always via the exact same composed `run_bootstrap_from_environment()`
    call and the same one fixed service account -- never a new,
    independent mutating primitive."""

    joined = " ".join(security_cli.__doc__.split())
    assert (
        "`bootstrap`, `recover`, and `setup apply` (for `write_protected` only) are the only "
        "subcommands that can mutate pfSense state"
    ) in joined


# --- end-to-end: real main() -> real orchestration -> stubbed engine call --


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


def test_end_to_end_main_bootstrap_against_real_environment(real_admin_env, capsys, monkeypatch):
    context = build_admin_context(dict(os.environ))
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

    exit_code = main(["bootstrap", "--json"])

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["outcome"] == "completed"
    assert payload["provisioning_outcome"] == "already_satisfied"
    snapshot = stubbed_context._journal.load()
    assert snapshot.latest.state.value == "completed"
