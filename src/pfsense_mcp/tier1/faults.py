"""Deterministic fault classification; never retries a mutation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .state_machine import RecoveryState


class MutationBoundary(str, Enum):
    BEFORE_SEND = "before_send"
    DURING_SEND = "during_send"
    AFTER_SEND = "after_send"
    DURING_ROLLBACK = "during_rollback"


class EffectKnowledge(str, Enum):
    PROVEN_NONE = "proven_none"
    VERIFIED_SUCCESS = "verified_success"
    AMBIGUOUS = "ambiguous"
    VERIFIED_FAILURE = "verified_failure"


@dataclass(frozen=True)
class FaultDecision:
    target_state: RecoveryState
    automatic_retry: bool = False
    manual_reconciliation: bool = False


def classify_fault(boundary: MutationBoundary, knowledge: EffectKnowledge) -> FaultDecision:
    if knowledge == EffectKnowledge.VERIFIED_SUCCESS:
        return FaultDecision(RecoveryState.VERIFIED)
    if knowledge in {EffectKnowledge.PROVEN_NONE, EffectKnowledge.VERIFIED_FAILURE}:
        return FaultDecision(RecoveryState.FAILED)
    if boundary in {MutationBoundary.DURING_SEND, MutationBoundary.AFTER_SEND, MutationBoundary.DURING_ROLLBACK}:
        return FaultDecision(RecoveryState.RECONCILIATION, manual_reconciliation=True)
    return FaultDecision(RecoveryState.FAILED)
