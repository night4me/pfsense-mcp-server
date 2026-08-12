"""Closed Stage 3D/E/G backend dispatcher.

The dispatcher owns scenario selection, deadline enforcement and result
validation.  The execution port is deliberately lab-internal and receives only
the immutable registry object; it has no endpoint, payload, method, candidate,
locator, description or fault-mode parameters.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol

from .stage3_deg import CANDIDATE, SCENARIOS, SEMANTIC_UNIT, EvidenceStage, ScenarioDefinition, ScenarioId
from .stage3_live_binding import BackendResult, GateReceipt, LiveBindingError


class ClosedStage3ExecutionPort(Protocol):
    """Sealed lab port implemented by the Tier-1 scenario runtime."""

    def mandatory_gates(self, scenario_id: ScenarioId) -> GateReceipt: ...

    def execute_stage_d(self, definition: ScenarioDefinition, *, deadline: datetime) -> BackendResult: ...

    def execute_stage_e(self, definition: ScenarioDefinition, *, deadline: datetime) -> BackendResult: ...

    def execute_stage_g(self, definition: ScenarioDefinition, *, deadline: datetime) -> BackendResult: ...


@dataclass(frozen=True)
class ClosedStage3Backend:
    """Concrete dispatcher for the immutable D/E/G registry only."""

    port: ClosedStage3ExecutionPort

    def run_mandatory_gates(self, scenario_id: ScenarioId) -> GateReceipt:
        if not isinstance(scenario_id, ScenarioId):
            raise LiveBindingError("scenario selector is not a closed ScenarioId")
        return self.port.mandatory_gates(scenario_id)

    def execute_closed_scenario(self, definition: ScenarioDefinition, *, deadline: datetime) -> BackendResult:
        if not isinstance(definition, ScenarioDefinition) or SCENARIOS.get(definition.scenario_id) is not definition:
            raise LiveBindingError("scenario definition is not the immutable registry entry")
        if CANDIDATE != "LAB_ALIAS_TEST" or SEMANTIC_UNIT != "set_firewall_alias_description_v1":
            raise LiveBindingError("closed candidate or semantic unit invariant changed")
        self._check_deadline(deadline)
        method = {
            EvidenceStage.D: self.port.execute_stage_d,
            EvidenceStage.E: self.port.execute_stage_e,
            EvidenceStage.G: self.port.execute_stage_g,
        }[definition.stage]
        result = method(definition, deadline=deadline)
        self._check_deadline(deadline)
        if result.scenario_id is not definition.scenario_id:
            raise LiveBindingError("execution port returned evidence for another scenario")
        return result

    @staticmethod
    def _check_deadline(deadline: datetime) -> None:
        if not isinstance(deadline, datetime) or deadline.tzinfo is None or deadline.utcoffset() is None:
            raise LiveBindingError("scenario deadline must be timezone-aware")
        if datetime.now(timezone.utc) >= deadline:
            raise LiveBindingError("scenario attestation deadline expired before a declared action")
