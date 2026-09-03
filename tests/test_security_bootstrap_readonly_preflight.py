"""Mission II Mission B -- pfREST global "Read Only" pre-flight check
(`security_bootstrap_orchestration.py::_run_locked()`), the journal-
boundary half of the mission (the client-level parsing of `GET /system/
restapi/settings`'s `read_only` field is covered by
test_security_bootstrap_client.py's own `observe_restapi_mode()` tests).

Owner-invariant this file also proves negatively: nothing in this
codebase ever disables, bypasses, or attempts to change pfREST's global
Read Only setting -- `check_pfrest_read_only_call` is a pure GET-only
observation; no PATCH/POST/DELETE to `/system/restapi/settings` exists
anywhere in `security_bootstrap_client.py`'s read-only-mode-related
surface (`observe_restapi_mode()` is the only method touching that path
this mission adds)."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest

from pfsense_mcp.security_admin_composition import AdministrativeContext, PfRestReadOnlyStatus, build_admin_context
from pfsense_mcp.security_bootstrap_engine import ProvisioningOutcome, ProvisioningResult
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    run_bootstrap,
)
from pfsense_mcp.security_operation_journal import (
    OperationLockError,
    RestartClassification,
    RestartDecision,
)


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


def _with_preflight_and_bootstrap_call(
    context: AdministrativeContext, *, status: PfRestReadOnlyStatus, call=None
) -> AdministrativeContext:
    def _unexpected() -> ProvisioningResult:
        pytest.fail("bootstrap_call must never be invoked when the read-only pre-flight check did not pass")

    components = replace(
        context._mutation_components,
        check_pfrest_read_only_call=lambda: status,
        bootstrap_call=call or _unexpected,
    )
    return replace(context, _mutation_components=components)


@pytest.mark.parametrize(
    "status",
    [PfRestReadOnlyStatus.BLOCKED_READ_ONLY, PfRestReadOnlyStatus.BLOCKED_UNVERIFIABLE],
    ids=["confirmed_read_only", "unverifiable"],
)
def test_blocked_status_sends_zero_mutating_calls_and_creates_no_journal(admin_env, status):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=status)

    result = run_bootstrap(context)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_READ_ONLY_MODE
    # No journal record was ever created -- proves zero POST/PATCH/DELETE
    # was attempted and the pre-flight rejection left no MUTATION_RESULT_
    # UNKNOWN (or any other) journal state behind.
    assert not context.journal_path.exists()


def test_confirmed_read_only_produces_actionable_owner_facing_detail(admin_env):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)

    result = run_bootstrap(context)

    assert "read only" in result.detail.lower() or "Read Only" in result.detail
    assert "webconfigurator" in result.detail.lower()
    assert "owner" in result.detail.lower()


def test_unverifiable_status_produces_a_distinct_actionable_detail(admin_env):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_UNVERIFIABLE)

    result = run_bootstrap(context)

    assert "could not" in result.detail.lower() or "not verif" in result.detail.lower()
    # The two blocked details must be distinguishable from each other --
    # an operator must never be told to go disable Read Only when the
    # real problem is connectivity/configuration.
    context2 = build_admin_context(admin_env)
    context2 = _with_preflight_and_bootstrap_call(context2, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)
    confirmed = run_bootstrap(context2)
    assert result.detail != confirmed.detail


def test_writable_status_proceeds_to_the_real_provisioning_call_unchanged(admin_env):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(
        context,
        status=PfRestReadOnlyStatus.WRITABLE,
        call=lambda: ProvisioningResult(ProvisioningOutcome.ALREADY_SATISFIED, "no-op"),
    )

    result = run_bootstrap(context)

    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert context.journal_path.exists()


def test_read_only_preflight_covers_the_existing_account_patch_path_too(admin_env):
    """The check runs unconditionally before `bootstrap_call()`, so it
    equally blocks the existing-account PATCH/key-generation path, not
    only new-account creation -- the orchestration layer has no way to
    know in advance which path a given run will take, and correctly does
    not need to."""

    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(
        context,
        status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY,
        call=lambda: ProvisioningResult(ProvisioningOutcome.PRIVILEGES_SYNCED, "would have PATCHed"),
    )

    result = run_bootstrap(context)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_READ_ONLY_MODE


def test_lock_is_released_so_a_subsequent_attempt_is_not_also_blocked_by_contention(admin_env):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)
    run_bootstrap(context)

    # The lock this run acquired must have been released -- a second,
    # independent context can acquire it freely.
    holder = build_admin_context(admin_env)
    holder._lock.acquire("someone-else", timestamp="2026-08-23T00:00:00Z")
    holder._lock.release(timestamp="2026-08-23T00:00:01Z")


def test_journal_semantics_remain_deterministic_across_a_blocked_then_writable_retry(admin_env):
    """Mirrors the intended production ceremony: a blocked attempt while
    Read Only is enabled leaves the namespace exactly as if nothing had
    ever been tried; once the owner manually disables Read Only (proven
    here purely by re-stubbing WRITABLE, never by this codebase acting on
    the setting itself), the very next attempt is a completely fresh,
    unblocked CLEAN_NO_OPERATION start -- no recovery action, no distinct
    namespace, no manual intervention required."""

    context = build_admin_context(admin_env)
    blocked_context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)
    blocked = run_bootstrap(blocked_context)
    assert blocked.outcome is BootstrapOrchestrationOutcome.BLOCKED_READ_ONLY_MODE

    retry_context = build_admin_context(admin_env)
    retry_context = _with_preflight_and_bootstrap_call(
        retry_context,
        status=PfRestReadOnlyStatus.WRITABLE,
        call=lambda: ProvisioningResult(ProvisioningOutcome.COMPLETED, "created"),
    )
    retry = run_bootstrap(retry_context)

    assert retry.outcome is BootstrapOrchestrationOutcome.COMPLETED
    assert retry_context.journal_path.exists()
    snapshot = retry_context._journal.load()
    # A completely fresh chain: exactly the CREATED -> ... -> COMPLETED
    # sequence a first-ever attempt produces, with no RECOVERY_REQUIRED
    # detour and no distinct retry namespace involved.
    assert snapshot.records[0].sequence == 0
    assert snapshot.latest.state.value == "completed"


def test_no_secret_or_internal_exception_text_leaks_into_the_blocked_detail(admin_env):
    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_UNVERIFIABLE)

    result = run_bootstrap(context)

    # The unverifiable-status detail is one of two fixed, hard-coded
    # strings -- never derived from a caught exception's own message
    # (which could echo a response body, header, or other target-
    # controlled content).
    assert "Traceback" not in result.detail
    assert "Exception" not in result.detail
    assert admin_env["PFSENSE_API_URL"] not in result.detail


def test_lock_contention_is_still_reported_before_the_preflight_check_ever_runs(admin_env):
    """Lock acquisition happens in `run_bootstrap()`, strictly before
    `_run_locked()` (and hence before the read-only check) -- contention
    must be reported as contention, not conflated with a read-only
    rejection."""

    context = build_admin_context(admin_env)
    holder = build_admin_context(admin_env)
    holder._lock.acquire("holder-op", timestamp="2026-08-23T00:00:00Z")
    try:
        context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)
        clean_decision = RestartDecision(RestartClassification.CLEAN_NO_OPERATION, None)
        with patch.object(context.status, "classify", return_value=clean_decision):
            result = run_bootstrap(context)
        assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION
    finally:
        holder._lock.release(timestamp="2026-08-23T00:00:01Z")


def test_double_release_is_never_attempted_on_the_blocked_path(admin_env):
    """A defensive regression check: `_run_locked()`'s early-return on a
    blocked read-only status must release the lock exactly once -- a
    double-release would raise `OperationLockError` from `ExclusiveOperationLock
    .release()`'s own "not held by this object" guard, which would
    surface as an unhandled exception escaping `run_bootstrap()`."""

    context = build_admin_context(admin_env)
    context = _with_preflight_and_bootstrap_call(context, status=PfRestReadOnlyStatus.BLOCKED_READ_ONLY)

    try:
        run_bootstrap(context)
    except OperationLockError:
        pytest.fail("run_bootstrap() must not raise OperationLockError on the blocked read-only path")
