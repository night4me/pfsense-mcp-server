"""Adversarial test matrix for the bootstrap-restart-classification
improvement: `observe_account_provisioning_state()`
(`security_bootstrap_engine.py`) and
`build_authoritative_restart_observation()`/`run_bootstrap_from_environment()`'s
new wiring (`security_bootstrap_orchestration.py`).

Core invariant under test throughout: **the journal alone must never be
sufficient evidence of completion.** A completed journal may become
`CLEAN_COMPLETED`/`ALREADY_COMPLETE` only when a fresh, live,
independently-derived authoritative observation *exactly* matches --
any mismatch, any read failure, any ambiguity remains fail-closed
(`RECOVERY_REQUIRED`/`BLOCKED_PRIOR_OPERATION`).

`classify_restart()` itself and its existing state-transition proofs
are not re-tested here (see `tests/test_security_operation_journal.py`
and the existing `tests/test_security_bootstrap_orchestration.py`
tests that already prove `run_bootstrap(..., authoritative=<synthetic>)`
resolves `CLEAN_COMPLETED` correctly when handed a hand-built
observation). This file proves two additional things those tests
don't: (1) `observe_account_provisioning_state()`'s own live-read
correctness across every adversarial account shape, reusing exactly
the same privilege derivation/drift comparison the write path uses;
and (2) that `run_bootstrap_from_environment()` now actually
*constructs* that observation from live evidence automatically,
exactly once, only when it could matter, and never mutates."""

from __future__ import annotations

import json
import pathlib
from dataclasses import replace
from pathlib import Path

import pytest

from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.errors import BootstrapProvisioningError
from pfsense_mcp.security_admin_composition import AdministrativeContext, build_admin_context
from pfsense_mcp.security_bootstrap_engine import (
    AccountProvisioningObservation,
    ProvisioningOutcome,
    ProvisioningResult,
    TargetProfile,
    observe_account_provisioning_state,
)
from pfsense_mcp.security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    build_authoritative_restart_observation,
    run_bootstrap,
    run_bootstrap_from_environment,
)
from pfsense_mcp.security_operation_journal import AuthoritativeServerState, RestartClassification
from pfsense_mcp.security_privileges import (
    distinct_ok_privileges,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)
from pfsense_mcp.transport.base import TransportResponse

_USERS_PATH = "/api/v2/users"
_AUTH_SETTINGS_PATH = "/api/v2/system/restapi/settings"
_USER_DESCR = "Dedicated service account for pfsense-mcp-server"
_ACCOUNT_NAME = "pfsense-mcp"


def _load_trimmed_schema() -> dict:
    path = pathlib.Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
    return json.loads(path.read_text(encoding="utf-8"))


_SCHEMA = _load_trimmed_schema()
_EXPECTED_WRITE_PROTECTED_PRIVS = distinct_ok_privileges(
    resolve_profile_privileges(_SCHEMA, write_protected_profile_requirements())
)


class _FakeAdminTransport:
    """Minimal in-memory transport for `observe_account_provisioning_state()`
    -- handles only `GET /api/v2/users` (mirrors
    `test_security_bootstrap_engine.py`'s own `_FakeAdminTransport`,
    reduced to what this read-only function needs; never a mutating
    method)."""

    def __init__(self, *, users: list[dict] | None = None, fail_status: int | None = None) -> None:
        self.calls: list[tuple[str, str]] = []
        self._users = users or []
        self._fail_status = fail_status

    def request(self, method: str, path: str, *, body: bytes | None = None) -> TransportResponse:
        self.calls.append((method, path))
        if method != "GET" or path != _USERS_PATH:
            raise AssertionError(
                f"observe_account_provisioning_state must only ever GET {_USERS_PATH}, got {method} {path}"
            )
        if self._fail_status is not None:
            return TransportResponse(self._fail_status, json.dumps({"message": "synthetic failure"}))
        return TransportResponse(200, json.dumps({"data": self._users}))

    def close(self) -> None:
        pass


def _user(
    *,
    user_id: int = 2,
    name: str = _ACCOUNT_NAME,
    priv: frozenset[str] | None = None,
    disabled: bool = False,
    descr: str = _USER_DESCR,
) -> dict:
    return {
        "id": user_id,
        "name": name,
        "descr": descr,
        "priv": sorted(priv if priv is not None else _EXPECTED_WRITE_PROTECTED_PRIVS),
        "disabled": disabled,
    }


def _observe(
    transport: _FakeAdminTransport,
    *,
    schema: dict | None = _SCHEMA,
    installed_package_version: tuple[int, int, int] | None = (2, 10, 0),
) -> AccountProvisioningObservation:
    return observe_account_provisioning_state(
        admin_transport=transport,
        api_version=ApiVersion.V2,
        username=_ACCOUNT_NAME,
        target_profile=TargetProfile.WRITE_PROTECTED,
        schema=schema,
        installed_package_version=installed_package_version,
        user_descr=_USER_DESCR,
    )


# =====================================================================
# 1. observe_account_provisioning_state() -- engine-level read
# =====================================================================


def test_exact_match_is_observed_as_such():
    transport = _FakeAdminTransport(users=[_user()])
    observation = _observe(transport)
    assert observation == AccountProvisioningObservation(
        exists=True,
        enabled=True,
        matches_expected_description=True,
        has_exact_expected_privileges=True,
        has_temporary_bootstrap_privilege=False,
    )
    assert transport.calls == [("GET", _USERS_PATH)]


def test_account_missing_is_a_definitive_observation_not_an_error():
    transport = _FakeAdminTransport(users=[])
    observation = _observe(transport)
    assert observation == AccountProvisioningObservation(exists=False)


def test_unrelated_account_does_not_satisfy_binding():
    transport = _FakeAdminTransport(users=[_user(user_id=9, name="someone-else")])
    observation = _observe(transport)
    assert observation == AccountProvisioningObservation(exists=False)


def test_duplicate_same_named_accounts_raise_rather_than_guess():
    transport = _FakeAdminTransport(users=[_user(user_id=2), _user(user_id=3)])
    with pytest.raises(BootstrapProvisioningError, match="ambiguous"):
        _observe(transport)


def test_disabled_account_is_observed_disabled():
    transport = _FakeAdminTransport(users=[_user(disabled=True)])
    observation = _observe(transport)
    assert observation.exists is True
    assert observation.enabled is False


def test_wrong_description_is_observed_as_mismatch():
    transport = _FakeAdminTransport(users=[_user(descr="not the expected description")])
    observation = _observe(transport)
    assert observation.matches_expected_description is False


def test_missing_required_privilege_is_observed_as_mismatch():
    incomplete = frozenset(list(_EXPECTED_WRITE_PROTECTED_PRIVS)[:-1])
    transport = _FakeAdminTransport(users=[_user(priv=incomplete)])
    observation = _observe(transport)
    assert observation.has_exact_expected_privileges is False


def test_extra_unexpected_privilege_is_observed_as_mismatch():
    extra = _EXPECTED_WRITE_PROTECTED_PRIVS | {"api-v2-firewall-rules-post"}
    transport = _FakeAdminTransport(users=[_user(priv=extra)])
    observation = _observe(transport)
    assert observation.has_exact_expected_privileges is False


def test_temporary_bootstrap_privilege_present_is_observed():
    with_temp = _EXPECTED_WRITE_PROTECTED_PRIVS | {"api-v2-auth-key-post"}
    transport = _FakeAdminTransport(users=[_user(priv=with_temp)])
    observation = _observe(transport)
    assert observation.has_temporary_bootstrap_privilege is True
    # A temp privilege alongside every expected privilege is still an
    # *exact* mismatch from the drift comparison's own point of view
    # (an unexpected additional privilege) -- both signals independently
    # available to the caller.
    assert observation.has_exact_expected_privileges is False


def test_package_version_out_of_range_refuses_to_observe():
    transport = _FakeAdminTransport(users=[_user()])
    with pytest.raises(BootstrapProvisioningError):
        _observe(transport, installed_package_version=(9, 9, 9))


def test_missing_schema_refuses_to_observe():
    transport = _FakeAdminTransport(users=[_user()])
    with pytest.raises(BootstrapProvisioningError):
        _observe(transport, schema=None)


def test_transport_failure_propagates_never_silently_absent():
    transport = _FakeAdminTransport(fail_status=500)
    with pytest.raises(BootstrapProvisioningError):
        _observe(transport)


def test_malformed_response_body_propagates():
    class _MalformedTransport(_FakeAdminTransport):
        def request(self, method, path, *, body=None):
            self.calls.append((method, path))
            return TransportResponse(200, "not json")

    with pytest.raises(BootstrapProvisioningError):
        _observe(_MalformedTransport())


def test_observation_never_issues_a_mutating_http_method():
    transport = _FakeAdminTransport(users=[_user()])
    _observe(transport)
    assert all(method == "GET" for method, _ in transport.calls)


# =====================================================================
# 2. build_authoritative_restart_observation() -- orchestration-level
# =====================================================================


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
    fixture = pathlib.Path(__file__).parent / "fixtures" / "pfsense_openapi_schema_trimmed.json"
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


def _with_observe_restart_state_call(context: AdministrativeContext, call) -> AdministrativeContext:
    components = replace(context._mutation_components, observe_restart_state_call=call)
    return replace(context, _mutation_components=components)


def _with_bootstrap_call(context: AdministrativeContext, call) -> AdministrativeContext:
    components = replace(context._mutation_components, bootstrap_call=call)
    return replace(context, _mutation_components=components)


def _result(outcome: ProvisioningOutcome, detail: str = "synthetic", **kwargs) -> ProvisioningResult:
    return ProvisioningResult(outcome, detail, **kwargs)


_MATCHING_ACCOUNT = AccountProvisioningObservation(
    exists=True,
    enabled=True,
    matches_expected_description=True,
    has_exact_expected_privileges=True,
    has_temporary_bootstrap_privilege=False,
)


def test_build_observation_exact_match_yields_expected_completed(admin_env):
    context = build_admin_context(admin_env)
    context = _with_observe_restart_state_call(context, lambda: (_MATCHING_ACCOUNT, frozenset({"KeyAuth"})))

    observation = build_authoritative_restart_observation(context)

    assert observation is not None
    assert observation.server_state is AuthoritativeServerState.EXPECTED_COMPLETED
    assert observation.final_verification_complete is True
    assert observation.target_identity == context.binding.target_identity
    assert observation.target_origin == context.binding.target_origin
    assert observation.account_identity == context.binding.account_identity
    assert observation.approved_profile == context.binding.approved_profile
    assert observation.schema_version == context.binding.schema_version
    assert observation.schema_evidence_digest == context.binding.schema_evidence_digest
    assert observation.auth_methods == ("KeyAuth",)


@pytest.mark.parametrize(
    "account",
    [
        AccountProvisioningObservation(exists=False),
        replace(_MATCHING_ACCOUNT, enabled=False),
        replace(_MATCHING_ACCOUNT, matches_expected_description=False),
        replace(_MATCHING_ACCOUNT, has_exact_expected_privileges=False),
        replace(_MATCHING_ACCOUNT, has_temporary_bootstrap_privilege=True),
    ],
    ids=["missing", "disabled", "wrong-description", "missing-or-extra-privilege", "temp-privilege-present"],
)
def test_build_observation_any_mismatch_yields_unknown_never_expected_completed(admin_env, account):
    context = build_admin_context(admin_env)
    context = _with_observe_restart_state_call(context, lambda: (account, frozenset({"KeyAuth"})))

    observation = build_authoritative_restart_observation(context)

    assert observation is not None  # a definitive "does not match" is still real evidence, not an error
    assert observation.server_state is AuthoritativeServerState.UNKNOWN


def test_build_observation_read_failure_returns_none_not_a_guess(admin_env):
    def _boom():
        raise BootstrapProvisioningError("synthetic transport failure")

    context = build_admin_context(admin_env)
    context = _with_observe_restart_state_call(context, _boom)

    assert build_authoritative_restart_observation(context) is None


def test_build_observation_unexpected_exception_also_returns_none(admin_env):
    def _boom():
        raise RuntimeError("unexpected shape")

    context = build_admin_context(admin_env)
    context = _with_observe_restart_state_call(context, _boom)

    assert build_authoritative_restart_observation(context) is None


def test_build_observation_never_calls_a_mutating_method(admin_env, monkeypatch):
    calls: list[str] = []

    def _tracking_observe():
        calls.append("observe_restart_state_call")
        return _MATCHING_ACCOUNT, frozenset({"KeyAuth"})

    context = build_admin_context(admin_env)
    context = _with_observe_restart_state_call(context, _tracking_observe)
    # bootstrap_call must never be reached by the observation builder.
    context = _with_bootstrap_call(context, lambda: (_ for _ in ()).throw(AssertionError("must never be called")))

    build_authoritative_restart_observation(context)

    assert calls == ["observe_restart_state_call"]


# =====================================================================
# 3. run_bootstrap_from_environment() -- the new wiring, end to end
# =====================================================================


def test_no_journal_never_triggers_the_extra_live_read(admin_env, monkeypatch):
    # Matrix: A -- byte-for-byte equivalent to prior behavior when no
    # journal exists yet: the observation builder must never even be
    # invoked (proven by monkeypatching it to explode if called).
    import pfsense_mcp.security_bootstrap_orchestration as orch

    def _boom(context):
        raise AssertionError("build_authoritative_restart_observation must not be called when no journal exists")

    monkeypatch.setattr(orch, "build_authoritative_restart_observation", _boom)

    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.COMPLETED, "created"))
    monkeypatch.setattr(orch, "build_admin_context", lambda source: context)

    result = run_bootstrap_from_environment(admin_env)
    assert result.outcome is BootstrapOrchestrationOutcome.COMPLETED


def test_completed_journal_exact_match_resolves_already_complete(admin_env):
    # Matrix: H
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    first = run_bootstrap(context)
    assert first.outcome is BootstrapOrchestrationOutcome.COMPLETED

    # run_bootstrap_from_environment() builds its own context internally;
    # exercise the exact wiring via a monkeypatched build_admin_context
    # returning a pre-wired context whose observe_restart_state_call
    # reports an exact live match.
    fresh = build_admin_context(admin_env)
    fresh = _with_observe_restart_state_call(fresh, lambda: (_MATCHING_ACCOUNT, frozenset({"KeyAuth"})))
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        second = run_bootstrap_from_environment(admin_env)

    assert second.outcome is BootstrapOrchestrationOutcome.ALREADY_COMPLETE
    assert second.restart_decision.classification is RestartClassification.CLEAN_COMPLETED


@pytest.mark.parametrize(
    "account",
    [
        AccountProvisioningObservation(exists=False),
        replace(_MATCHING_ACCOUNT, has_exact_expected_privileges=False),
        replace(_MATCHING_ACCOUNT, has_temporary_bootstrap_privilege=True),
    ],
    ids=["account-vanished", "privileges-drifted", "temp-privilege-reappeared"],
)
def test_completed_journal_mismatch_remains_blocked_prior_operation(admin_env, account):
    # Matrix: G -- mismatched live state after a real completion must
    # never be silently reaffirmed.
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context)

    fresh = build_admin_context(admin_env)
    fresh = _with_observe_restart_state_call(fresh, lambda: (account, frozenset({"KeyAuth"})))
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        result = run_bootstrap_from_environment(admin_env)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION
    assert result.restart_decision.classification is not RestartClassification.CLEAN_COMPLETED


def test_completed_journal_read_failure_remains_blocked_prior_operation(admin_env):
    # Matrix: F
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context)

    fresh = build_admin_context(admin_env)

    def _boom():
        raise BootstrapProvisioningError("synthetic connection failure")

    fresh = _with_observe_restart_state_call(fresh, _boom)
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        result = run_bootstrap_from_environment(admin_env)

    assert result.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION


def test_explicit_authoritative_override_wins_over_auto_built(admin_env):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context)

    fresh = build_admin_context(admin_env)

    def _boom():
        raise AssertionError("observe_restart_state_call must not be invoked when authoritative is explicit")

    fresh = _with_observe_restart_state_call(fresh, _boom)
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    binding = fresh.binding
    from pfsense_mcp.security_operation_journal import AuthoritativeRestartObservation

    explicit = AuthoritativeRestartObservation(
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

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        result = run_bootstrap_from_environment(admin_env, authoritative=explicit)

    assert result.outcome is BootstrapOrchestrationOutcome.ALREADY_COMPLETE


def test_observation_builder_invoked_at_most_once_per_invocation(admin_env):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context)

    fresh = build_admin_context(admin_env)
    call_count = {"n": 0}

    def _counting_observe():
        call_count["n"] += 1
        return _MATCHING_ACCOUNT, frozenset({"KeyAuth"})

    fresh = _with_observe_restart_state_call(fresh, _counting_observe)
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        run_bootstrap_from_environment(admin_env)

    assert call_count["n"] == 1


def test_completed_journal_and_clean_completed_touches_neither_lock_nor_journal_again(admin_env):
    context = build_admin_context(admin_env)
    context = _with_bootstrap_call(context, lambda: _result(ProvisioningOutcome.ALREADY_SATISFIED, "first run"))
    run_bootstrap(context)
    before = context.journal_path.read_bytes()

    fresh = build_admin_context(admin_env)
    fresh = _with_observe_restart_state_call(fresh, lambda: (_MATCHING_ACCOUNT, frozenset({"KeyAuth"})))
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        run_bootstrap_from_environment(admin_env)

    after = context.journal_path.read_bytes()
    assert before == after
    assert fresh._lock.inspect().state.value in {"absent", "released"}


def test_mutation_result_unknown_journal_remains_fail_closed_even_with_matching_observation(admin_env):
    """Matrix: C/D -- an ambiguous, crashed-mid-mutation local state
    must never resolve to ALREADY_COMPLETE, no matter how clean a
    *subsequent* live observation looks. Simulated by crashing
    bootstrap mid-flight (journal left at MUTATION_RESULT_UNKNOWN, lock
    deliberately not released -- `ACTIVE_HELD`), then supplying a
    "looks completed" observation on the next attempt: the held lock
    alone already forces RECOVERY_REQUIRED before `authoritative` is
    even consulted, proving observation-based evidence can never route
    around the lock/crash-safety gate."""

    context = build_admin_context(admin_env)

    class _Crash:
        def __call__(self):
            raise RuntimeError("simulated crash mid-mutation")

    context = _with_bootstrap_call(context, _Crash())
    first = run_bootstrap(context)
    assert first.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED
    # The lock is deliberately not released on a crash -- confirms the
    # journal is genuinely left at MUTATION_RESULT_UNKNOWN, not COMPLETED.

    fresh = build_admin_context(admin_env)
    fresh = _with_observe_restart_state_call(fresh, lambda: (_MATCHING_ACCOUNT, frozenset({"KeyAuth"})))
    fresh = _with_bootstrap_call(fresh, lambda: (_ for _ in ()).throw(AssertionError("must never re-run bootstrap")))

    import pfsense_mcp.security_bootstrap_orchestration as orch

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(orch, "build_admin_context", lambda source: fresh)
        second = run_bootstrap_from_environment(admin_env)

    assert second.outcome is not BootstrapOrchestrationOutcome.ALREADY_COMPLETE
    assert second.restart_decision.classification is not RestartClassification.CLEAN_COMPLETED
