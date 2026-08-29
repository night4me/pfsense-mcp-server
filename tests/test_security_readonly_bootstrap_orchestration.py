"""Focused tests for `run_readonly_bootstrap_from_environment()` -- the
`read_only`-profile counterpart of (a small slice of)
`test_security_bootstrap_orchestration.py`.

`run_bootstrap()` itself is untouched by this mission and already has
its own exhaustive matrix (locking, journal sequencing, crash/restart
classification) against the write_protected path -- since `run_
readonly_bootstrap_from_environment()` composes that exact same,
unmodified function, this file only proves the one thing that
genuinely differs: which context gets built, and that a read_only run
and a write_protected run against the identical target/admin
configuration never share state."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.security_admin_composition import AdministrativeContext, build_admin_context
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    run_bootstrap_from_environment,
    run_readonly_bootstrap_from_environment,
)
from pfsense_mcp.security_readonly_admin_composition import build_readonly_admin_context


def _write_secure(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.write_bytes(value)
    path.chmod(mode)


@pytest.fixture
def readonly_admin_env(tmp_path: Path) -> dict[str, str]:
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
        "PFSENSE_READONLY_SERVICE_API_KEY_FILE": str(custody / "pfsense-mcp-readonly.key"),
        "PFSENSE_ADMIN_STATE_DIR": str(state),
        "PFSENSE_ADMIN_JOURNAL_KEY_FILE": str(tmp_path / "journal-key"),
        "PFSENSE_ADMIN_SCHEMA_FILE": str(schema),
        "PFSENSE_ADMIN_SCHEMA_VERSION": "restapi-v2.10",
        "PFSENSE_RESTAPI_PACKAGE_VERSION": "2.10.0",
    }


@pytest.fixture
def write_protected_admin_env(readonly_admin_env: dict[str, str], tmp_path: Path) -> dict[str, str]:
    env = dict(readonly_admin_env)
    del env["PFSENSE_READONLY_SERVICE_API_KEY_FILE"]
    env["PFSENSE_SERVICE_API_KEY_FILE"] = str(tmp_path / "custody" / "pfsense-mcp.key")
    return env


def _with_bootstrap_call(context: AdministrativeContext, call) -> AdministrativeContext:
    components = replace(context._mutation_components, bootstrap_call=call)
    return replace(context, _mutation_components=components)


def test_missing_config_is_blocked_configuration_error():
    result = run_readonly_bootstrap_from_environment({})
    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR


def test_successful_completed_provisioning_reaches_the_orchestration_success_outcome(readonly_admin_env, monkeypatch):
    context = build_readonly_admin_context(readonly_admin_env)
    context = _with_bootstrap_call(
        context, lambda: ProvisioningResult(ProvisioningOutcome.COMPLETED, "synthetic completed provisioning")
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_bootstrap_orchestration.build_readonly_admin_context", lambda source: context
    )
    result = run_readonly_bootstrap_from_environment(readonly_admin_env)
    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert context.journal_path.exists()


def test_readonly_and_write_protected_runs_never_share_a_journal_or_lock(
    readonly_admin_env, write_protected_admin_env, monkeypatch
):
    """The orchestration-level equivalent of the composition-level
    namespace-collision proof: running both ceremonies against
    byte-identical target/admin configuration must never let one
    ceremony's journal/lock be mistaken for the other's."""

    readonly_context = build_readonly_admin_context(readonly_admin_env)
    write_protected_context = build_admin_context(write_protected_admin_env)

    readonly_context = _with_bootstrap_call(
        readonly_context, lambda: ProvisioningResult(ProvisioningOutcome.COMPLETED, "synthetic read_only completed")
    )
    write_protected_context = _with_bootstrap_call(
        write_protected_context,
        lambda: ProvisioningResult(ProvisioningOutcome.COMPLETED, "synthetic write_protected completed"),
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_bootstrap_orchestration.build_readonly_admin_context", lambda source: readonly_context
    )
    monkeypatch.setattr(
        "pfsense_mcp.security_bootstrap_orchestration.build_admin_context", lambda source: write_protected_context
    )

    readonly_result = run_readonly_bootstrap_from_environment(readonly_admin_env)
    write_protected_result = run_bootstrap_from_environment(write_protected_admin_env)

    assert readonly_result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert write_protected_result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert readonly_context.journal_path != write_protected_context.journal_path
    assert readonly_context.journal_path.exists()
    assert write_protected_context.journal_path.exists()
    # Each journal records only its own ceremony's operation -- reading
    # one back must never surface the other's binding.
    readonly_snapshot = readonly_context._journal.load()
    write_protected_snapshot = write_protected_context._journal.load()
    assert readonly_snapshot.latest.binding.account_identity == "pfsense-mcp-readonly"
    assert write_protected_snapshot.latest.binding.account_identity == "pfsense-mcp"
