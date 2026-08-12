from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from lab.stage3_backend import ClosedStage3Backend
from lab.stage3_deg import CANDIDATE, SCENARIOS, SEMANTIC_UNIT, EvidenceStage, ScenarioId, scenario_plan
from lab.stage3_live_binding import BackendResult, GateReceipt, LiveBindingError, TransportOutcome
from lab.stage3_live_runtime import execute_live_scenario
from pfsense_mcp.tier1.state_machine import RecoveryState

_NOW = datetime.now(timezone.utc)
_A = "a" * 64
_B = "b" * 64


class _Port:
    def __init__(self):
        self.calls = []

    def mandatory_gates(self, scenario_id):
        return GateReceipt(
            scenario_id, CANDIDATE, SEMANTIC_UNIT, True, True, True, False, _NOW, _NOW + timedelta(hours=2)
        )

    def _result(self, definition):
        self.calls.append(definition)
        pending = definition.expected_state is RecoveryState.RECONCILIATION
        return BackendResult(
            definition.scenario_id,
            definition.expected_orchestration_sends,
            definition.expected_forward_sends,
            definition.expected_rollback_sends,
            _outcome(definition),
            _A if definition.authoritative_read_back_required else None,
            _A if definition.authoritative_read_back_required else None,
            _B if definition.authoritative_read_back_required else None,
            _A,
            _A,
            definition.expected_state,
            True,
            False,
            pending,
        )

    def execute_stage_d(self, definition, *, deadline):
        assert definition.stage is EvidenceStage.D
        return self._result(definition)

    def execute_stage_e(self, definition, *, deadline):
        assert definition.stage is EvidenceStage.E
        return self._result(definition)

    def execute_stage_g(self, definition, *, deadline):
        assert definition.stage is EvidenceStage.G
        return self._result(definition)


def _outcome(definition):
    if definition.upstream_delivery is None:
        return (
            TransportOutcome.PROCESS_RESTART
            if definition.stage is EvidenceStage.G
            else TransportOutcome.RESPONSE_RECEIVED
        )
    return {
        "proven_delivered": TransportOutcome.RESPONSE_DROPPED,
        "proven_not_delivered": TransportOutcome.CONNECTION_CLOSED,
        "possibly_delivered": TransportOutcome.TIMEOUT,
    }[definition.upstream_delivery.value]


@pytest.mark.parametrize("scenario_id", [item for item in ScenarioId if item is not ScenarioId.D6])
def test_backend_dispatches_every_executable_registry_scenario_to_exact_stage(scenario_id):
    port = _Port()
    backend = ClosedStage3Backend(port)
    definition = scenario_plan(scenario_id)
    result = backend.execute_closed_scenario(definition, deadline=_NOW + timedelta(hours=1))
    assert result.scenario_id is scenario_id
    assert port.calls == [definition]


def test_backend_refuses_forged_scenario_definition():
    definition = scenario_plan(ScenarioId.D1)
    forged = replace(definition, fault_class="forged")
    with pytest.raises(LiveBindingError, match="immutable registry"):
        ClosedStage3Backend(_Port()).execute_closed_scenario(forged, deadline=_NOW + timedelta(hours=1))


def test_backend_refuses_expired_deadline_before_port_action():
    port = _Port()
    with pytest.raises(LiveBindingError, match="deadline expired"):
        ClosedStage3Backend(port).execute_closed_scenario(
            scenario_plan(ScenarioId.D1), deadline=_NOW - timedelta(seconds=1)
        )
    assert port.calls == []


def test_registry_has_only_fixed_candidate_semantic_unit_and_d6_blocked():
    assert CANDIDATE == "LAB_ALIAS_TEST"
    assert SEMANTIC_UNIT == "set_firewall_alias_description_v1"
    assert scenario_plan(ScenarioId.D6).live_status.value == "blocked"
    assert len(SCENARIOS) == 26


def test_public_runtime_accepts_only_scenario_selector():
    assert set(execute_live_scenario.__annotations__) == {"scenario_value", "return"}
