from __future__ import annotations

import os

from pydantic import BaseModel

from lab.fault_proxy import FaultProxy, FaultScenario
from lab.harness import (
    AcceptanceReport,
    ExitConditionReport,
    ScenarioReport,
    ScenarioSetup,
    prepare_contract,
    run_full_acceptance,
    run_scenario,
)
from pfsense_mcp.api_version import ApiVersion
from pfsense_mcp.capabilities import Capability
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.policy import MutationPolicy, MutationRule
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore
from pfsense_mcp.transport.mock import MockTransport
from pfsense_mcp.write_api_client import WriteApiClient
from pfsense_mcp.write_endpoints import WriteEndpointInfo, WriteEndpoints

_INTEGRITY_KEY = b"synthetic-lab-test-integrity-key-32b!"
_ENCRYPTION_KEY = os.urandom(32)
_CAPABILITY = Capability.ALIAS_WRITE
_ENDPOINT_SYMBOL = "LAB_SYNTHETIC_ENDPOINT"
_HTTP_METHOD = "PATCH"


class _SyntheticRequest(BaseModel):
    descr: str


class _SyntheticAdapter:
    """Test-only CapabilityAdapter -- never a real capability adapter."""

    capability = _CAPABILITY
    endpoint_symbol = _ENDPOINT_SYMBOL
    http_method = _HTTP_METHOD

    def read_target(self, read_client, natural_identity):
        return {"name": "lab-synthetic-target.invalid", "revision": "lab-1", "descr": "updated-description"}

    def natural_identity(self, raw_target):
        return {"name": raw_target["name"]}

    def fingerprint(self, raw_target):
        return {"revision": raw_target["revision"]}

    def build_request(self, intent):
        return _SyntheticRequest(descr=intent["descr"])

    def parse_response(self, raw_response):
        return {"status_code": raw_response.status_code}

    def is_semantically_verified(self, pre, post, intent):
        return True

    def build_rollback_request(self, pre):
        return _SyntheticRequest(descr=pre["descr"])

    def is_rollback_verified(self, pre, post_rollback):
        return True


class _AcceptingVerifier:
    def verify(self, evidence):
        return evidence.proof == b"lab-synthetic-valid-proof"


def _store(tmp_path):
    tmp_path.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(tmp_path, 0o700)
    return SqliteRecoveryContractStore(
        tmp_path / "contracts.sqlite3",
        integrity_key=_INTEGRITY_KEY,
        store_id="lab-synthetic-store",
        confirmation_verifier=_AcceptingVerifier(),
    )


def _write_client(monkeypatch):
    monkeypatch.setattr(
        WriteEndpoints,
        _ENDPOINT_SYMBOL,
        WriteEndpointInfo(
            path_suffix="/lab-synthetic",
            http_method=_HTTP_METHOD,
            verified=True,
            min_api_version=ApiVersion.V2,
            reversible=True,
            dry_run_supported=True,
        ),
        raising=False,
    )
    transport = MockTransport()
    proxy = FaultProxy(transport)
    client = WriteApiClient(proxy, identity="lab-test-executor", api_version=ApiVersion.V2)
    return client, transport, proxy


def _executor(store, write_client):
    from pfsense_mcp.tier1.executor import MutationExecutor

    policy = MutationPolicy(frozenset({MutationRule(_CAPABILITY, _ENDPOINT_SYMBOL, _HTTP_METHOD)}))
    return MutationExecutor(
        store=store,
        write_client=write_client,
        read_client=object(),
        policy=policy,
        anti_rollback_anchor=None,
        encryption_key=_ENCRYPTION_KEY,
    )


def _setup():
    return ScenarioSetup(
        raw_target_hint={"name": "lab-synthetic-target.invalid", "revision": "lab-1"},
        intent_payload={"descr": "updated-description"},
        snapshot_payload={"descr": "original-description"},
    )


def _confirm_via_store(store):
    def confirm(contract):
        evidence = ConfirmationEvidence(
            authority_id="lab-synthetic-owner",
            algorithm="test-verifier",
            nonce="lab-nonce-001",
            contract_id=contract.contract_id,
            operation_id=contract.operation_id,
            target_identity_digest=contract.target_identity_digest,
            target_fingerprint=contract.target_fingerprint,
            intent_digest=contract.intent_digest,
            expires_at=contract.expires_at,
            issued_at=contract.created_at,
            proof=b"lab-synthetic-valid-proof",
        )
        return store.confirm(contract.contract_id, evidence=evidence, expected_version=contract.state_version)

    return confirm


def test_prepare_contract_produces_a_preparing_contract_and_matching_intent():
    adapter = _SyntheticAdapter()
    contract, intent = prepare_contract(
        adapter=adapter,
        setup=_setup(),
        encryption_key=_ENCRYPTION_KEY,
        contract_id="lab-contract-001",
        operation_id="lab-operation-001",
    )

    assert contract.state == RecoveryState.PREPARING
    assert contract.capability == _CAPABILITY
    assert intent["raw_target_hint"] == _setup().raw_target_hint
    assert intent["descr"] == "updated-description"


def test_run_scenario_clean_passthrough_reaches_verified(tmp_path, monkeypatch):
    store = _store(tmp_path)
    write_client, transport, proxy = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/lab-synthetic", status_code=200, text='{"ok": true}')
    executor = _executor(store, write_client)

    report = run_scenario(
        store=store,
        executor=executor,
        adapter=_SyntheticAdapter(),
        setup=_setup(),
        confirm=_confirm_via_store(store),
        scenario=FaultScenario.CLEAN_PASSTHROUGH,
        fault_proxy=proxy,
        encryption_key=_ENCRYPTION_KEY,
        contract_id="lab-contract-clean",
        operation_id="lab-operation-clean",
    )

    assert report.passed is True
    assert report.final_state == RecoveryState.VERIFIED.value
    assert report.scenario == FaultScenario.CLEAN_PASSTHROUGH


def test_run_scenario_connection_reset_reaches_failed(tmp_path, monkeypatch):
    store = _store(tmp_path)
    write_client, transport, proxy = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/lab-synthetic", status_code=200, text='{"ok": true}')
    executor = _executor(store, write_client)

    report = run_scenario(
        store=store,
        executor=executor,
        adapter=_SyntheticAdapter(),
        setup=_setup(),
        confirm=_confirm_via_store(store),
        scenario=FaultScenario.CONNECTION_RESET_DURING_UPLOAD,
        fault_proxy=proxy,
        encryption_key=_ENCRYPTION_KEY,
        contract_id="lab-contract-reset",
        operation_id="lab-operation-reset",
    )

    # run_scenario reports execute()'s outcome as "passed" (it completed
    # without raising) -- the scenario's assertion is on final_state, not
    # on report.passed alone: a connection reset must resolve to FAILED
    # (proven zero effect), never VERIFIED.
    assert report.passed is True
    assert report.final_state == RecoveryState.FAILED.value
    assert transport.calls == []


def test_run_scenario_timeout_reaches_reconciliation(tmp_path, monkeypatch):
    store = _store(tmp_path)
    write_client, transport, proxy = _write_client(monkeypatch)
    transport.register("PATCH", "/api/v2/lab-synthetic", status_code=200, text='{"ok": true}')
    executor = _executor(store, write_client)

    report = run_scenario(
        store=store,
        executor=executor,
        adapter=_SyntheticAdapter(),
        setup=_setup(),
        confirm=_confirm_via_store(store),
        scenario=FaultScenario.TIMEOUT_DURING_RESPONSE,
        fault_proxy=proxy,
        encryption_key=_ENCRYPTION_KEY,
        contract_id="lab-contract-timeout",
        operation_id="lab-operation-timeout",
    )

    assert report.final_state == RecoveryState.RECONCILIATION.value


def test_run_scenario_captures_unexpected_exception_without_raising(tmp_path, monkeypatch):
    store = _store(tmp_path)
    write_client, transport, proxy = _write_client(monkeypatch)
    executor = _executor(store, write_client)

    def failing_confirm(contract):
        raise RuntimeError("synthetic confirm failure")

    report = run_scenario(
        store=store,
        executor=executor,
        adapter=_SyntheticAdapter(),
        setup=_setup(),
        confirm=failing_confirm,
        scenario=FaultScenario.CLEAN_PASSTHROUGH,
        fault_proxy=proxy,
        encryption_key=_ENCRYPTION_KEY,
        contract_id="lab-contract-confirm-fail",
        operation_id="lab-operation-confirm-fail",
    )

    assert report.passed is False
    assert "RuntimeError" in report.detail
    assert report.final_state is None


def test_run_full_acceptance_aggregates_mixed_synthetic_results():
    passing = ScenarioReport(scenario=FaultScenario.CLEAN_PASSTHROUGH, passed=True, detail="ok", final_state="verified")
    failing = ScenarioReport(
        scenario=FaultScenario.CONNECTION_RESET_DURING_UPLOAD, passed=False, detail="synthetic failure"
    )
    runners = {
        FaultScenario.CLEAN_PASSTHROUGH: lambda: passing,
        FaultScenario.CONNECTION_RESET_DURING_UPLOAD: lambda: failing,
    }

    report = run_full_acceptance(
        scenario_runners=runners,
        verify_exit_conditions=lambda: ExitConditionReport(permission_revoked=True, read_only_confirmed=True),
    )

    assert isinstance(report, AcceptanceReport)
    assert report.scenario_reports == (passing, failing)
    assert report.all_passed is False  # one scenario failed
    assert report.exit_condition.clean is True


def test_run_full_acceptance_all_passed_true_when_everything_succeeds():
    passing_a = ScenarioReport(scenario=FaultScenario.CLEAN_PASSTHROUGH, passed=True, detail="ok")
    passing_b = ScenarioReport(scenario=FaultScenario.TIMEOUT_DURING_RESPONSE, passed=True, detail="ok")
    runners = {
        FaultScenario.CLEAN_PASSTHROUGH: lambda: passing_a,
        FaultScenario.TIMEOUT_DURING_RESPONSE: lambda: passing_b,
    }

    report = run_full_acceptance(
        scenario_runners=runners,
        verify_exit_conditions=lambda: ExitConditionReport(permission_revoked=True, read_only_confirmed=True),
    )

    assert report.all_passed is True


def test_exit_condition_verification_runs_even_when_a_runner_raises():
    """A scenario runner raising an exception the runner itself didn't
    catch (fault-injected into the harness's own control flow, not just
    the pfSense-facing calls) must still reach exit-condition
    verification -- a crashed run must never silently leave elevated lab
    permissions active (I5)."""

    verified = {"called": False}

    def verify_exit_conditions():
        verified["called"] = True
        return ExitConditionReport(permission_revoked=True, read_only_confirmed=True)

    def exploding_runner():
        raise RuntimeError("harness control-flow fault, not a pfSense-facing failure")

    report = run_full_acceptance(
        scenario_runners={FaultScenario.CLEAN_PASSTHROUGH: exploding_runner},
        verify_exit_conditions=verify_exit_conditions,
    )

    assert verified["called"] is True
    assert report.scenario_reports[0].passed is False
    assert "RuntimeError" in report.scenario_reports[0].detail


def test_exit_condition_not_clean_marks_acceptance_failed_even_if_every_scenario_passed():
    passing = ScenarioReport(scenario=FaultScenario.CLEAN_PASSTHROUGH, passed=True, detail="ok")

    report = run_full_acceptance(
        scenario_runners={FaultScenario.CLEAN_PASSTHROUGH: lambda: passing},
        verify_exit_conditions=lambda: ExitConditionReport(permission_revoked=False, read_only_confirmed=True),
    )

    assert report.all_passed is False
