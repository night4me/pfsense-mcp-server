"""Closed live binding for predeclared ADR-026 Stage 3D/E/G scenarios.

The module is lab-only and contains no transport construction.  It binds one
immutable ScenarioId to a backend that must use the existing LAB-T1 gate and
sealed Tier-1 machinery.  Tests inject an offline backend; a real backend may
only be constructed by the lab package under a separately authorized run.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Protocol, cast

from pfsense_mcp.tier1.state_machine import RecoveryState

from .fault_proxy import UpstreamDelivery
from .stage3_deg import (
    CANDIDATE,
    SEMANTIC_UNIT,
    LiveStatus,
    ReadBackClassification,
    ScenarioDefinition,
    ScenarioFinalRequirement,
    ScenarioId,
    classify_read_back,
    scenario_plan,
)

# HttpTransport's connect/read/write/pool limits total 60 seconds.  This is an
# upper bound derived from the real transport configuration, not a guessed
# typical duration.  Each plan receives one bound per declared send plus four
# authoritative/gate/recovery operations, and 30 seconds local persistence
# overhead.  Backends must additionally recheck the absolute deadline before
# every individual action.
HTTP_OPERATION_UPPER_BOUND = timedelta(seconds=60)
LOCAL_PERSISTENCE_OVERHEAD = timedelta(seconds=30)


class LiveBindingError(RuntimeError):
    """A closed live scenario was refused before unsafe progress."""


class FinalStatePolicy(str, Enum):
    EXACT_A = "exact_authoritative_a"
    DEFINITELY_NOT_APPLIED_A = "definitely_not_applied_exact_a"
    RECONCILIATION_STOP = "reconciliation_required_stop_no_additional_send"


class TransportOutcome(str, Enum):
    RESPONSE_RECEIVED = "response_received"
    RESPONSE_DROPPED = "response_dropped"
    TIMEOUT = "timeout"
    CONNECTION_CLOSED = "connection_closed"
    NOT_SENT = "not_sent"
    PROCESS_RESTART = "process_restart"


@dataclass(frozen=True)
class GateReceipt:
    scenario_id: ScenarioId
    candidate: str
    semantic_unit: str
    evidence_env_passed: bool
    preflight_passed: bool
    dry_run_passed: bool
    dry_run_sent: bool
    attestation_issued_at: datetime
    attestation_expires_at: datetime

    def __post_init__(self) -> None:
        if self.candidate != CANDIDATE or self.semantic_unit != SEMANTIC_UNIT:
            raise LiveBindingError("gate receipt does not bind the closed candidate and semantic unit")
        if not (self.evidence_env_passed and self.preflight_passed and self.dry_run_passed):
            raise LiveBindingError("mandatory LAB-T1 gate did not pass")
        if self.dry_run_sent:
            raise LiveBindingError("mandatory dry-run unexpectedly sent a request")
        for value in (self.attestation_issued_at, self.attestation_expires_at):
            if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
                raise LiveBindingError("attestation receipt timestamps must be UTC")
        if self.attestation_expires_at <= self.attestation_issued_at:
            raise LiveBindingError("attestation receipt lifetime is invalid")


@dataclass(frozen=True)
class BackendResult:
    scenario_id: ScenarioId
    orchestration_sends: int
    forward_sends: int
    rollback_sends: int
    transport_outcome: TransportOutcome
    authoritative_live_fingerprint: str | None
    authoritative_a_fingerprint: str | None
    authoritative_b_fingerprint: str | None
    final_live_fingerprint: str
    final_a_fingerprint: str
    resulting_state: RecoveryState
    retry_suppressed: bool
    owner_reconciliation_evidence_used: bool = False
    pending_evidence_authenticated: bool = False


@dataclass(frozen=True)
class LiveExecutionReport:
    scenario_id: ScenarioId
    transport_outcome: TransportOutcome
    read_back_classification: ReadBackClassification | None
    reconciliation_state: RecoveryState
    retry_suppressed: bool
    final_state_policy: FinalStatePolicy
    orchestration_sends: int
    forward_sends: int
    rollback_sends: int

    def sanitized(self) -> dict[str, object]:
        return {
            "scenario_id": self.scenario_id.value,
            "transport_outcome": self.transport_outcome.value,
            "read_back_classification": (
                self.read_back_classification.value if self.read_back_classification is not None else None
            ),
            "reconciliation_state": self.reconciliation_state.value,
            "retry_suppressed": self.retry_suppressed,
            "final_state_policy": self.final_state_policy.value,
            "orchestration_sends": self.orchestration_sends,
            "forward_sends": self.forward_sends,
            "rollback_sends": self.rollback_sends,
            "pending_evidence_authenticated": self.final_state_policy is FinalStatePolicy.RECONCILIATION_STOP,
        }


class ClosedScenarioBackend(Protocol):
    """Internal lab backend; receives only one immutable closed definition."""

    def run_mandatory_gates(self, scenario_id: ScenarioId) -> GateReceipt: ...

    def execute_closed_scenario(self, definition: ScenarioDefinition, *, deadline: datetime) -> BackendResult: ...


def required_attestation_time(definition: ScenarioDefinition) -> timedelta:
    operations = (
        definition.expected_orchestration_sends
        + definition.expected_forward_sends
        + definition.expected_rollback_sends
        + 4
    )
    return HTTP_OPERATION_UPPER_BOUND * operations + LOCAL_PERSISTENCE_OVERHEAD


class ClosedLiveBinding:
    """Validate gates, lease, accounting, classification, and safe completion."""

    def __init__(self, backend: ClosedScenarioBackend) -> None:
        self._backend = backend

    def execute(self, scenario_id: ScenarioId, *, now: datetime | None = None) -> LiveExecutionReport:
        if not isinstance(scenario_id, ScenarioId):
            raise LiveBindingError("scenario selector is not a closed ScenarioId")
        definition = scenario_plan(scenario_id)
        if definition.live_status is LiveStatus.BLOCKED:
            raise LiveBindingError("scenario is blocked at a sealed security boundary")

        current = now or datetime.now(timezone.utc)
        receipt = self._backend.run_mandatory_gates(scenario_id)
        if receipt.scenario_id is not scenario_id:
            raise LiveBindingError("gate receipt belongs to a different scenario")
        if receipt.attestation_issued_at > current + timedelta(seconds=30) or receipt.attestation_expires_at <= current:
            raise LiveBindingError("attestation receipt is not currently valid")
        required = required_attestation_time(definition)
        if receipt.attestation_expires_at - current < required:
            raise LiveBindingError("insufficient attestation lifetime for the complete scenario bound")
        deadline = receipt.attestation_expires_at
        result = self._backend.execute_closed_scenario(definition, deadline=deadline)
        return self._validate_result(definition, result)

    @staticmethod
    def _validate_result(definition: ScenarioDefinition, result: BackendResult) -> LiveExecutionReport:
        if result.scenario_id is not definition.scenario_id:
            raise LiveBindingError("backend result belongs to a different scenario")
        actual = (result.orchestration_sends, result.forward_sends, result.rollback_sends)
        expected = (
            definition.expected_orchestration_sends,
            definition.expected_forward_sends,
            definition.expected_rollback_sends,
        )
        if actual != expected:
            raise LiveBindingError("backend send accounting violated the closed scenario plan")
        if not result.retry_suppressed:
            raise LiveBindingError("scenario did not prove retry suppression")
        ClosedLiveBinding._validate_transport_outcome(definition, result.transport_outcome)

        classification = ClosedLiveBinding._classification(definition, result)
        exact_a = ClosedLiveBinding._exact_final_a(result)
        if result.resulting_state is RecoveryState.RECONCILIATION:
            if result.owner_reconciliation_evidence_used:
                raise LiveBindingError("runner may not fabricate or self-supply owner reconciliation evidence")
            if definition.final_requirement is not ScenarioFinalRequirement.RECONCILIATION_REQUIRED:
                raise LiveBindingError("scenario unexpectedly stopped in reconciliation")
            if not result.pending_evidence_authenticated:
                raise LiveBindingError("reconciliation stop lacks authenticated pending evidence")
            policy = FinalStatePolicy.RECONCILIATION_STOP
        elif definition.final_requirement is ScenarioFinalRequirement.RECONCILIATION_REQUIRED:
            raise LiveBindingError("reconciliation-required scenario auto-progressed")
        elif classification is ReadBackClassification.DEFINITELY_NOT_APPLIED:
            if not exact_a:
                raise LiveBindingError("definitely-not-applied result did not verify exact A")
            policy = FinalStatePolicy.DEFINITELY_NOT_APPLIED_A
        else:
            if not exact_a:
                raise LiveBindingError("completed scenario did not independently verify exact A restoration")
            policy = FinalStatePolicy.EXACT_A

        return LiveExecutionReport(
            definition.scenario_id,
            result.transport_outcome,
            classification,
            result.resulting_state,
            result.retry_suppressed,
            policy,
            *actual,
        )

    @staticmethod
    def _exact_final_a(result: BackendResult) -> bool:
        values = (result.final_live_fingerprint, result.final_a_fingerprint)
        if not all(isinstance(value, str) and len(value) == 64 for value in values):
            raise LiveBindingError("final authoritative fingerprint evidence is malformed")
        return result.final_live_fingerprint == result.final_a_fingerprint

    @staticmethod
    def _classification(definition: ScenarioDefinition, result: BackendResult) -> ReadBackClassification | None:
        if not definition.authoritative_read_back_required:
            return None
        values = (
            result.authoritative_live_fingerprint,
            result.authoritative_a_fingerprint,
            result.authoritative_b_fingerprint,
        )
        if not all(isinstance(value, str) for value in values):
            raise LiveBindingError("authoritative read-back evidence is incomplete")
        live, a, b = cast(tuple[str, str, str], values)
        return classify_read_back(live_fingerprint=live, a_fingerprint=a, b_fingerprint=b)

    @staticmethod
    def _validate_transport_outcome(definition: ScenarioDefinition, outcome: TransportOutcome) -> None:
        allowed: dict[UpstreamDelivery, frozenset[TransportOutcome]] = {
            UpstreamDelivery.PROVEN_DELIVERED: frozenset({TransportOutcome.RESPONSE_DROPPED}),
            UpstreamDelivery.PROVEN_NOT_DELIVERED: frozenset(
                {TransportOutcome.NOT_SENT, TransportOutcome.CONNECTION_CLOSED}
            ),
            UpstreamDelivery.POSSIBLY_DELIVERED: frozenset(
                {
                    TransportOutcome.RESPONSE_DROPPED,
                    TransportOutcome.TIMEOUT,
                    TransportOutcome.CONNECTION_CLOSED,
                }
            ),
        }
        delivery = definition.upstream_delivery
        if delivery is not None and outcome not in allowed[delivery]:
            raise LiveBindingError("transport outcome contradicts the scenario's declared delivery semantics")
