from datetime import datetime, timedelta, timezone

import pytest

from lab.stage3_deg import (
    CANDIDATE,
    SEMANTIC_UNIT,
    LiveStatus,
    ReadBackClassification,
    ScenarioId,
    scenario_plan,
)
from lab.stage3_live_binding import (
    BackendResult,
    ClosedLiveBinding,
    FinalStatePolicy,
    GateReceipt,
    LiveBindingError,
    TransportOutcome,
    required_attestation_time,
)
from pfsense_mcp.tier1.state_machine import RecoveryState

_NOW = datetime(2026, 8, 12, 12, 0, tzinfo=timezone.utc)
_A = "a" * 64
_B = "b" * 64
_C = "c" * 64


class _Backend:
    def __init__(self, result=None, *, lifetime=timedelta(minutes=10)):
        self.result = result
        self.lifetime = lifetime
        self.gate_calls = []
        self.execute_calls = []

    def run_mandatory_gates(self, scenario_id):
        self.gate_calls.append(scenario_id)
        return GateReceipt(
            scenario_id,
            CANDIDATE,
            SEMANTIC_UNIT,
            True,
            True,
            True,
            False,
            _NOW,
            _NOW + self.lifetime,
        )

    def execute_closed_scenario(self, definition, *, deadline):
        self.execute_calls.append((definition, deadline))
        return self.result or _result(definition.scenario_id)


def _result(
    scenario_id,
    *,
    live=_A,
    exact_a=True,
    state=None,
    retried=False,
    owner_evidence=False,
):
    definition = scenario_plan(scenario_id)
    transport_outcome = TransportOutcome.RESPONSE_RECEIVED
    if definition.upstream_delivery is not None:
        transport_outcome = {
            "proven_delivered": TransportOutcome.RESPONSE_DROPPED,
            "proven_not_delivered": TransportOutcome.CONNECTION_CLOSED,
            "possibly_delivered": TransportOutcome.TIMEOUT,
        }[definition.upstream_delivery.value]
    return BackendResult(
        scenario_id,
        definition.expected_orchestration_sends,
        definition.expected_forward_sends,
        definition.expected_rollback_sends,
        transport_outcome,
        live if definition.authoritative_read_back_required else None,
        _A if definition.authoritative_read_back_required else None,
        _B if definition.authoritative_read_back_required else None,
        _A if exact_a else _C,
        _A,
        state or definition.expected_state,
        not retried,
        owner_evidence,
    )


def test_unknown_non_enum_scenario_is_refused_before_gates():
    backend = _Backend()
    with pytest.raises(LiveBindingError, match="closed ScenarioId"):
        ClosedLiveBinding(backend).execute("d1-stale-description-before-forward", now=_NOW)
    assert backend.gate_calls == []


@pytest.mark.parametrize("attribute", ["endpoint", "payload", "candidate", "locator", "http_method"])
def test_closed_execution_api_has_no_arbitrary_request_inputs(attribute):
    assert attribute not in ClosedLiveBinding.execute.__annotations__


@pytest.mark.parametrize("scenario_id", [ScenarioId.D1, ScenarioId.D2, ScenarioId.D3, ScenarioId.D4, ScenarioId.D5])
def test_d1_d5_bind_exact_counts_and_exact_a(scenario_id):
    backend = _Backend()
    report = ClosedLiveBinding(backend).execute(scenario_id, now=_NOW)
    definition = scenario_plan(scenario_id)
    assert report.orchestration_sends == definition.expected_orchestration_sends
    assert report.forward_sends == definition.expected_forward_sends
    assert report.rollback_sends == definition.expected_rollback_sends
    assert report.final_state_policy is FinalStatePolicy.EXACT_A
    assert backend.execute_calls[0][0] is definition


def test_d6_remains_blocked_before_backend_execution():
    backend = _Backend()
    assert scenario_plan(ScenarioId.D6).live_status is LiveStatus.BLOCKED
    with pytest.raises(LiveBindingError, match="blocked"):
        ClosedLiveBinding(backend).execute(ScenarioId.D6, now=_NOW)
    assert backend.gate_calls == []


def test_send_accounting_cannot_be_hidden_or_merged():
    bad = _result(ScenarioId.D3)
    bad = BackendResult(**{**bad.__dict__, "rollback_sends": 1})
    with pytest.raises(LiveBindingError, match="send accounting"):
        ClosedLiveBinding(_Backend(bad)).execute(ScenarioId.D3, now=_NOW)


@pytest.mark.parametrize(
    ("scenario_id", "delivery"),
    [
        (ScenarioId.E1, "proven_delivered"),
        (ScenarioId.E2, "possibly_delivered"),
        (ScenarioId.E3, "proven_not_delivered"),
        (ScenarioId.E4, "possibly_delivered"),
        (ScenarioId.E5, "possibly_delivered"),
        (ScenarioId.E6, "possibly_delivered"),
        (ScenarioId.E7, "possibly_delivered"),
    ],
)
def test_e_scenarios_bind_declared_delivery_not_timing(scenario_id, delivery):
    assert scenario_plan(scenario_id).upstream_delivery.value == delivery


def test_transport_result_cannot_contradict_declared_delivery():
    result = _result(ScenarioId.E1, live=_B)
    result = BackendResult(**{**result.__dict__, "transport_outcome": TransportOutcome.RESPONSE_RECEIVED})
    with pytest.raises(LiveBindingError, match="contradicts"):
        ClosedLiveBinding(_Backend(result)).execute(ScenarioId.E1, now=_NOW)


def test_definitely_applied_requires_later_exact_a_restoration():
    report = ClosedLiveBinding(_Backend(_result(ScenarioId.E1, live=_B))).execute(ScenarioId.E1, now=_NOW)
    assert report.read_back_classification is ReadBackClassification.DEFINITELY_APPLIED
    assert report.final_state_policy is FinalStatePolicy.EXACT_A


def test_definitely_not_applied_requires_exact_a():
    report = ClosedLiveBinding(_Backend(_result(ScenarioId.E3, live=_A))).execute(ScenarioId.E3, now=_NOW)
    assert report.read_back_classification is ReadBackClassification.DEFINITELY_NOT_APPLIED
    assert report.final_state_policy is FinalStatePolicy.DEFINITELY_NOT_APPLIED_A


def test_ambiguous_stops_in_reconciliation_without_owner_evidence_or_restoration_send():
    result = _result(ScenarioId.E2, live=_C, exact_a=False, state=RecoveryState.RECONCILIATION)
    report = ClosedLiveBinding(_Backend(result)).execute(ScenarioId.E2, now=_NOW)
    assert report.read_back_classification is ReadBackClassification.AMBIGUOUS
    assert report.final_state_policy is FinalStatePolicy.RECONCILIATION_STOP
    assert report.reconciliation_state is RecoveryState.RECONCILIATION


def test_ambiguous_cannot_fabricate_owner_reconciliation():
    result = _result(
        ScenarioId.E2,
        live=_C,
        exact_a=False,
        state=RecoveryState.RECONCILIATION,
        owner_evidence=True,
    )
    with pytest.raises(LiveBindingError, match="fabricate"):
        ClosedLiveBinding(_Backend(result)).execute(ScenarioId.E2, now=_NOW)


def test_ambiguous_cannot_auto_progress():
    result = _result(ScenarioId.E2, live=_C, exact_a=False, state=RecoveryState.VERIFIED)
    with pytest.raises(LiveBindingError, match="remain in reconciliation"):
        ClosedLiveBinding(_Backend(result)).execute(ScenarioId.E2, now=_NOW)


def test_any_retry_is_refused():
    with pytest.raises(LiveBindingError, match="retry suppression"):
        ClosedLiveBinding(_Backend(_result(ScenarioId.E1, live=_B, retried=True))).execute(ScenarioId.E1, now=_NOW)


@pytest.mark.parametrize("scenario_id", [ScenarioId.G1, ScenarioId.G2, ScenarioId.G3, ScenarioId.G4, ScenarioId.G5])
def test_g_restart_binding_uses_only_closed_definition(scenario_id):
    definition = scenario_plan(scenario_id)
    result = _result(scenario_id, live=_C, exact_a=False, state=RecoveryState.RECONCILIATION)
    if not definition.authoritative_read_back_required:
        result = _result(scenario_id)
    report = ClosedLiveBinding(_Backend(result)).execute(scenario_id, now=_NOW)
    assert report.scenario_id is scenario_id


def test_attestation_time_refusal_occurs_before_scenario_action():
    definition = scenario_plan(ScenarioId.D1)
    backend = _Backend(lifetime=required_attestation_time(definition) - timedelta(seconds=1))
    with pytest.raises(LiveBindingError, match="insufficient attestation"):
        ClosedLiveBinding(backend).execute(ScenarioId.D1, now=_NOW)
    assert backend.execute_calls == []


def test_gate_receipt_rejects_arbitrary_candidate():
    with pytest.raises(LiveBindingError, match="closed candidate"):
        GateReceipt(
            ScenarioId.D1,
            "OTHER_ALIAS",
            SEMANTIC_UNIT,
            True,
            True,
            True,
            False,
            _NOW,
            _NOW + timedelta(minutes=10),
        )


def test_gate_receipt_rejects_dry_run_send():
    with pytest.raises(LiveBindingError, match="unexpectedly sent"):
        GateReceipt(
            ScenarioId.D1,
            CANDIDATE,
            SEMANTIC_UNIT,
            True,
            True,
            True,
            True,
            _NOW,
            _NOW + timedelta(minutes=10),
        )


def test_exact_a_is_mandatory_for_non_ambiguous_completion():
    with pytest.raises(LiveBindingError, match="exact A"):
        ClosedLiveBinding(_Backend(_result(ScenarioId.E1, live=_B, exact_a=False))).execute(ScenarioId.E1, now=_NOW)
