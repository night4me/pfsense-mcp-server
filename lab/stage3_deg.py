"""Closed, lab-only Stage 3D/E/G scenario and evidence model.

This module contains no client, endpoint, credential, or arbitrary payload
surface.  It pre-declares the only future live scenarios and provides pure
classification/evidence validation for an owner-authorized runner.  Importing
it cannot contact pfSense or make a mutation reachable from production MCP.
"""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, TypeVar

from pfsense_mcp.tier1.confirmation import ConfirmationVerifier
from pfsense_mcp.tier1.reconciliation import ReconciliationVerifier
from pfsense_mcp.tier1.state_machine import RecoveryState
from pfsense_mcp.tier1.store import SqliteRecoveryContractStore

from .fault_proxy import FaultScenario, UpstreamDelivery

ORIGINAL_DESCRIPTION = "Disposable LAB-T1 synthetic test alias"
SEMANTIC_UNIT = "set_firewall_alias_description_v1"
CANDIDATE = "LAB_ALIAS_TEST"
_T = TypeVar("_T")


class EvidenceStage(str, Enum):
    D = "stage3d"
    E = "stage3e"
    G = "stage3g"


class LiveStatus(str, Enum):
    READY = "ready_for_separately_authorized_live_run"
    BLOCKED = "blocked"
    OFFLINE_ONLY = "offline_only"


class ReadBackClassification(str, Enum):
    DEFINITELY_APPLIED = "definitely_applied"
    DEFINITELY_NOT_APPLIED = "definitely_not_applied"
    AMBIGUOUS = "ambiguous"


class ScenarioId(str, Enum):
    D1 = "d1-stale-description-before-forward"
    D2 = "d2-preparation-to-send-drift"
    D3 = "d3-post-b-description-drift"
    D4 = "d4-stale-expected-b"
    D5 = "d5-rollback-fingerprint-conflict"
    D6 = "d6-pre-rollback-race-boundary"
    E1 = "e1-forward-response-dropped"
    E2 = "e2-forward-timeout"
    E3 = "e3-request-blocked-before-delivery"
    E4 = "e4-rollback-response-dropped"
    E5 = "e5-rollback-timeout"
    E6 = "e6-connection-loss-around-response"
    E7 = "e7-retry-suppression"
    E8 = "e8-forward-applied-reconciliation"
    E9 = "e9-not-applied-reconciliation"
    E10 = "e10-ambiguous-human-boundary"
    G1 = "g1-executing-restart"
    G2 = "g2-verified-b-restart"
    G3 = "g3-rolling-back-restart"
    G4 = "g4-uncertain-forward-restart"
    G5 = "g5-uncertain-rollback-restart"
    G6 = "g6-locator-persistence"
    G7 = "g7-b-integrity"
    G8 = "g8-a-integrity"
    G9 = "g9-ephemeral-projection-non-persistence"
    G10 = "g10-legacy-malformed-state"


@dataclass(frozen=True)
class ScenarioDefinition:
    scenario_id: ScenarioId
    stage: EvidenceStage
    fault_class: str
    starting_required_state: RecoveryState
    orchestration_action: str
    expected_orchestration_sends: int
    expected_forward_sends: int
    expected_rollback_sends: int
    upstream_delivery: UpstreamDelivery | None
    authoritative_read_back_required: bool
    expected_state: RecoveryState
    expected_reconciliation: str
    exact_final_state_requirement: str
    repetition_target: int
    live_status: LiveStatus
    requires_fresh_attestation: bool

    def __post_init__(self) -> None:
        if not self.fault_class or not self.orchestration_action or not self.expected_reconciliation:
            raise ValueError("scenario semantics must be explicit")
        if self.exact_final_state_requirement != "exact-authoritative-A":
            raise ValueError("every scenario must require exact authoritative A restoration")
        counts = (self.expected_orchestration_sends, self.expected_forward_sends, self.expected_rollback_sends)
        if any(type(value) is not int or value < 0 or value > 2 for value in counts):
            raise ValueError("scenario send counts are invalid")
        if type(self.repetition_target) is not int or self.repetition_target < 1:
            raise ValueError("scenario repetition target is invalid")


@dataclass(frozen=True)
class ScenarioEvidence:
    definition: ScenarioDefinition
    orchestration_sends: int
    executor_forward_sends: int
    executor_rollback_sends: int
    read_back_classification: ReadBackClassification | None
    final_state_is_exact_a: bool
    exception_class: str | None = None

    def __post_init__(self) -> None:
        actual = (self.orchestration_sends, self.executor_forward_sends, self.executor_rollback_sends)
        expected = (
            self.definition.expected_orchestration_sends,
            self.definition.expected_forward_sends,
            self.definition.expected_rollback_sends,
        )
        if actual != expected:
            raise ValueError("observed sends do not match the closed scenario plan")
        if self.definition.authoritative_read_back_required and self.read_back_classification is None:
            raise ValueError("authoritative read-back classification is required")
        if not self.final_state_is_exact_a:
            raise ValueError("scenario did not prove exact authoritative A restoration")
        if self.exception_class is not None and (
            not self.exception_class.isidentifier() or len(self.exception_class) > 128
        ):
            raise ValueError("exception evidence must contain only a sanitized class name")

    def sanitized(self) -> dict[str, object]:
        return {
            "scenario_id": self.definition.scenario_id.value,
            "stage": self.definition.stage.value,
            "orchestration_sends": self.orchestration_sends,
            "executor_forward_sends": self.executor_forward_sends,
            "executor_rollback_sends": self.executor_rollback_sends,
            "read_back_classification": (
                self.read_back_classification.value if self.read_back_classification is not None else None
            ),
            "expected_state": self.definition.expected_state.value,
            "final_state": "exact-authoritative-A",
            "exception_class": self.exception_class,
        }


@dataclass(frozen=True)
class OfflineRestartHarness:
    """Reopen the real authenticated store after discarding process objects.

    The harness deliberately stores only store bootstrap material.  It cannot
    persist or reconstruct a transport projection, read client, adapter, or
    write client.  A future live caller must build those objects afresh and
    MutationExecutor construction will reconcile interrupted records.
    """

    store_path: Path
    integrity_key: bytes
    store_id: str
    confirmation_verifier: ConfirmationVerifier | None = None
    reconciliation_verifier: ReconciliationVerifier | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.store_path, Path):
            raise ValueError("restart store path is invalid")
        if not isinstance(self.integrity_key, bytes) or len(self.integrity_key) < 32:
            raise ValueError("restart integrity key is invalid")

    def reconstruct_store(self) -> SqliteRecoveryContractStore:
        return SqliteRecoveryContractStore(
            self.store_path,
            integrity_key=self.integrity_key,
            store_id=self.store_id,
            confirmation_verifier=self.confirmation_verifier,
            reconciliation_verifier=self.reconciliation_verifier,
        )

    def reconstruct_process_object(self, factory: Callable[[SqliteRecoveryContractStore], _T]) -> _T:
        """Build a fresh executor-like object from only the reopened store."""

        return factory(self.reconstruct_store())


def classify_read_back(*, live_fingerprint: str, a_fingerprint: str, b_fingerprint: str) -> ReadBackClassification:
    """Classify only exact authoritative A/B observations; everything else is ambiguous."""

    if not all(
        isinstance(value, str) and len(value) == 64 for value in (live_fingerprint, a_fingerprint, b_fingerprint)
    ):
        raise ValueError("read-back fingerprints must be canonical digests")
    if a_fingerprint == b_fingerprint:
        raise ValueError("A and B must be distinct")
    if live_fingerprint == b_fingerprint:
        return ReadBackClassification.DEFINITELY_APPLIED
    if live_fingerprint == a_fingerprint:
        return ReadBackClassification.DEFINITELY_NOT_APPLIED
    return ReadBackClassification.AMBIGUOUS


def _definition(
    scenario_id: ScenarioId,
    stage: EvidenceStage,
    fault_class: str,
    *,
    start: RecoveryState,
    orchestration: str = "none",
    orchestration_sends: int = 0,
    forward_sends: int = 0,
    rollback_sends: int = 0,
    delivery: UpstreamDelivery | None = None,
    read_back: bool = True,
    result: RecoveryState = RecoveryState.RECONCILIATION,
    reconciliation: str = "signed-human-resolution-required",
    repetitions: int = 3,
    status: LiveStatus = LiveStatus.READY,
    attestation: bool = True,
) -> ScenarioDefinition:
    return ScenarioDefinition(
        scenario_id,
        stage,
        fault_class,
        start,
        orchestration,
        orchestration_sends,
        forward_sends,
        rollback_sends,
        delivery,
        read_back,
        result,
        reconciliation,
        "exact-authoritative-A",
        repetitions,
        status,
        attestation,
    )


SCENARIOS: dict[ScenarioId, ScenarioDefinition] = {
    ScenarioId.D1: _definition(
        ScenarioId.D1,
        EvidenceStage.D,
        "stale-precondition",
        start=RecoveryState.PREPARED,
        orchestration="description-A-to-C",
        orchestration_sends=2,
        read_back=False,
        result=RecoveryState.FAILED,
        reconciliation="executor-zero-send; tracked-orchestration-restores-A",
    ),
    ScenarioId.D2: _definition(
        ScenarioId.D2,
        EvidenceStage.D,
        "pre-send-drift",
        start=RecoveryState.PREPARED,
        orchestration="description-A-to-C-after-prepare",
        orchestration_sends=2,
        read_back=False,
        result=RecoveryState.FAILED,
        reconciliation="executor-zero-send; tracked-orchestration-restores-A",
    ),
    ScenarioId.D3: _definition(
        ScenarioId.D3,
        EvidenceStage.D,
        "post-b-conflict",
        start=RecoveryState.VERIFIED,
        orchestration="description-B-to-C",
        orchestration_sends=2,
        forward_sends=1,
        read_back=False,
        result=RecoveryState.ROLLBACK_FAILED,
        reconciliation="rollback-zero-send; tracked-orchestration-restores-A",
    ),
    ScenarioId.D4: _definition(
        ScenarioId.D4,
        EvidenceStage.D,
        "stale-expected-b",
        start=RecoveryState.VERIFIED,
        orchestration="description-B-to-C",
        orchestration_sends=2,
        forward_sends=1,
        read_back=False,
        result=RecoveryState.ROLLBACK_FAILED,
        reconciliation="rollback-zero-send; tracked-orchestration-restores-A",
    ),
    ScenarioId.D5: _definition(
        ScenarioId.D5,
        EvidenceStage.D,
        "fingerprint-conflict",
        start=RecoveryState.VERIFIED,
        orchestration="description-B-to-C-with-stable-locator",
        orchestration_sends=2,
        forward_sends=1,
        read_back=False,
        result=RecoveryState.ROLLBACK_FAILED,
        reconciliation="locator-match-does-not-override-fingerprint-conflict",
    ),
    ScenarioId.D6: _definition(
        ScenarioId.D6,
        EvidenceStage.D,
        "sealed-pre-rollback-race",
        start=RecoveryState.VERIFIED,
        read_back=False,
        result=RecoveryState.ROLLBACK_FAILED,
        reconciliation="blocked-no-deterministic-hook-between-final-read-and-send",
        repetitions=1,
        status=LiveStatus.BLOCKED,
    ),
    ScenarioId.E1: _definition(
        ScenarioId.E1,
        EvidenceStage.E,
        FaultScenario.RESPONSE_DROPPED_AFTER_COMMIT.value,
        start=RecoveryState.PREPARED,
        forward_sends=1,
        delivery=UpstreamDelivery.PROVEN_DELIVERED,
    ),
    ScenarioId.E2: _definition(
        ScenarioId.E2,
        EvidenceStage.E,
        FaultScenario.TIMEOUT_DURING_RESPONSE.value,
        start=RecoveryState.PREPARED,
        forward_sends=1,
        delivery=UpstreamDelivery.POSSIBLY_DELIVERED,
    ),
    ScenarioId.E3: _definition(
        ScenarioId.E3,
        EvidenceStage.E,
        FaultScenario.CONNECTION_RESET_DURING_UPLOAD.value,
        start=RecoveryState.PREPARED,
        forward_sends=1,
        delivery=UpstreamDelivery.PROVEN_NOT_DELIVERED,
        result=RecoveryState.FAILED,
        reconciliation="no-retry; authoritative-A-required",
    ),
    ScenarioId.E4: _definition(
        ScenarioId.E4,
        EvidenceStage.E,
        FaultScenario.ROLLBACK_RESPONSE_LOST.value,
        start=RecoveryState.VERIFIED,
        forward_sends=1,
        rollback_sends=1,
        delivery=UpstreamDelivery.POSSIBLY_DELIVERED,
    ),
    ScenarioId.E5: _definition(
        ScenarioId.E5,
        EvidenceStage.E,
        "rollback-timeout",
        start=RecoveryState.VERIFIED,
        forward_sends=1,
        rollback_sends=1,
        delivery=UpstreamDelivery.POSSIBLY_DELIVERED,
    ),
    ScenarioId.E6: _definition(
        ScenarioId.E6,
        EvidenceStage.E,
        "connection-loss-around-response",
        start=RecoveryState.PREPARED,
        forward_sends=1,
        delivery=UpstreamDelivery.POSSIBLY_DELIVERED,
    ),
    ScenarioId.E7: _definition(
        ScenarioId.E7,
        EvidenceStage.E,
        "retry-suppression",
        start=RecoveryState.EXECUTING,
        forward_sends=1,
        delivery=UpstreamDelivery.POSSIBLY_DELIVERED,
    ),
    ScenarioId.E8: _definition(
        ScenarioId.E8,
        EvidenceStage.E,
        "applied-reconciliation",
        start=RecoveryState.RECONCILIATION,
        reconciliation="signed-exact-B-and-locator-binding; no-resend",
    ),
    ScenarioId.E9: _definition(
        ScenarioId.E9,
        EvidenceStage.E,
        "not-applied-reconciliation",
        start=RecoveryState.RECONCILIATION,
        result=RecoveryState.FAILED,
        reconciliation="signed-not-applied-with-no-applied-only-bindings; no-resend",
    ),
    ScenarioId.E10: _definition(
        ScenarioId.E10,
        EvidenceStage.E,
        "ambiguous-human-boundary",
        start=RecoveryState.RECONCILIATION,
        reconciliation="remain-reconciliation-without-valid-human-signature",
    ),
    ScenarioId.G1: _definition(
        ScenarioId.G1,
        EvidenceStage.G,
        "executing-restart",
        start=RecoveryState.EXECUTING,
        reconciliation="reconstruct-to-reconciliation; fresh-read; no-resend",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G2: _definition(
        ScenarioId.G2,
        EvidenceStage.G,
        "verified-b-restart",
        start=RecoveryState.VERIFIED,
        rollback_sends=1,
        result=RecoveryState.ROLLED_BACK,
        reconciliation="authenticated-A-B-locator; fresh-read-before-rollback",
        repetitions=1,
    ),
    ScenarioId.G3: _definition(
        ScenarioId.G3,
        EvidenceStage.G,
        "rolling-back-restart",
        start=RecoveryState.ROLLING_BACK,
        reconciliation="reconstruct-to-reconciliation; no-resend; no-second-rollback",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G4: _definition(
        ScenarioId.G4,
        EvidenceStage.G,
        "uncertain-forward-restart",
        start=RecoveryState.RECONCILIATION,
        reconciliation="authoritative-read-and-signed-resolution; no-resend",
        repetitions=1,
    ),
    ScenarioId.G5: _definition(
        ScenarioId.G5,
        EvidenceStage.G,
        "uncertain-rollback-restart",
        start=RecoveryState.RECONCILIATION,
        reconciliation="authoritative-read-and-signed-resolution; no-resend",
        repetitions=1,
    ),
    ScenarioId.G6: _definition(
        ScenarioId.G6,
        EvidenceStage.G,
        "locator-persistence",
        start=RecoveryState.VERIFIED,
        reconciliation="authenticated-lifecycle-locator-rechecked-after-fresh-read",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G7: _definition(
        ScenarioId.G7,
        EvidenceStage.G,
        "b-integrity",
        start=RecoveryState.VERIFIED,
        reconciliation="store-HMAC-refuses-tampered-B",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G8: _definition(
        ScenarioId.G8,
        EvidenceStage.G,
        "a-integrity",
        start=RecoveryState.VERIFIED,
        reconciliation="AEAD/store-HMAC-refuses-tampered-A",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G9: _definition(
        ScenarioId.G9,
        EvidenceStage.G,
        "projection-non-persistence",
        start=RecoveryState.VERIFIED,
        reconciliation="fresh-authoritative-projection-only",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
    ScenarioId.G10: _definition(
        ScenarioId.G10,
        EvidenceStage.G,
        "legacy-malformed-state",
        start=RecoveryState.RECONCILIATION,
        reconciliation="schema-v6-and-HMAC-fail-closed",
        repetitions=1,
        status=LiveStatus.OFFLINE_ONLY,
        attestation=False,
    ),
}


def scenario_plan(scenario_id: ScenarioId) -> ScenarioDefinition:
    """Return one closed predeclared plan; callers cannot supply endpoint/payload data."""

    return SCENARIOS[scenario_id]


def sanitized_plan(definition: ScenarioDefinition) -> dict[str, object]:
    """Produce value-free operator metadata for one predeclared scenario."""

    return {
        "scenario_id": definition.scenario_id.value,
        "stage": definition.stage.value,
        "fault_class": definition.fault_class,
        "starting_required_state": definition.starting_required_state.value,
        "expected_orchestration_sends": definition.expected_orchestration_sends,
        "expected_forward_sends": definition.expected_forward_sends,
        "expected_rollback_sends": definition.expected_rollback_sends,
        "upstream_delivery": definition.upstream_delivery.value if definition.upstream_delivery else None,
        "authoritative_read_back_required": definition.authoritative_read_back_required,
        "expected_state": definition.expected_state.value,
        "exact_final_state_requirement": definition.exact_final_state_requirement,
        "repetition_target": definition.repetition_target,
        "live_status": definition.live_status.value,
        "requires_fresh_attestation": definition.requires_fresh_attestation,
        "empirical_status": "NOT_YET_LIVE_VERIFIED",
    }


def main(argv: list[str] | None = None) -> int:
    """Inspect closed plans offline; intentionally contains no execute command."""

    parser = argparse.ArgumentParser(description="Inspect closed ADR-026 Stage 3D/E/G plans")
    parser.add_argument("command", choices=("list", "plan"))
    parser.add_argument("--scenario", choices=tuple(item.value for item in ScenarioId))
    args = parser.parse_args(argv)
    if args.command == "plan" and args.scenario is None:
        parser.error("plan requires --scenario")
    selected = (
        [scenario_plan(ScenarioId(args.scenario))]
        if args.scenario is not None
        else [SCENARIOS[item] for item in ScenarioId]
    )
    print(
        json.dumps(
            {
                "semantic_unit": SEMANTIC_UNIT,
                "candidate": CANDIDATE,
                "plans": [sanitized_plan(item) for item in selected],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
