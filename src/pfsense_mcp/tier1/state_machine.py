"""Closed recovery state machine for future Tier 1 execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from .errors import IllegalTransitionError


class RecoveryState(str, Enum):
    PREPARING = "preparing"
    PREPARED = "prepared"
    EXECUTING = "executing"
    VERIFIED = "verified"
    FAILED = "failed"
    RECONCILIATION = "reconciliation"
    ROLLING_BACK = "rolling_back"
    ROLLED_BACK = "rolled_back"
    ROLLBACK_FAILED = "rollback_failed"
    EXPIRED = "expired"


@dataclass(frozen=True)
class TransitionRule:
    manual_only: bool = False


LEGAL_TRANSITIONS: dict[RecoveryState, dict[RecoveryState, TransitionRule]] = {
    RecoveryState.PREPARING: {
        RecoveryState.PREPARED: TransitionRule(),
        RecoveryState.FAILED: TransitionRule(),
        RecoveryState.EXPIRED: TransitionRule(),
    },
    RecoveryState.PREPARED: {
        RecoveryState.EXECUTING: TransitionRule(),
        RecoveryState.FAILED: TransitionRule(),
        RecoveryState.EXPIRED: TransitionRule(),
    },
    RecoveryState.EXECUTING: {
        RecoveryState.VERIFIED: TransitionRule(),
        RecoveryState.FAILED: TransitionRule(),
        RecoveryState.RECONCILIATION: TransitionRule(),
    },
    RecoveryState.VERIFIED: {RecoveryState.ROLLING_BACK: TransitionRule()},
    RecoveryState.ROLLING_BACK: {
        RecoveryState.ROLLED_BACK: TransitionRule(),
        RecoveryState.ROLLBACK_FAILED: TransitionRule(),
        RecoveryState.RECONCILIATION: TransitionRule(),
    },
    RecoveryState.RECONCILIATION: {
        RecoveryState.VERIFIED: TransitionRule(manual_only=True),
        RecoveryState.FAILED: TransitionRule(manual_only=True),
        RecoveryState.ROLLING_BACK: TransitionRule(manual_only=True),
        RecoveryState.ROLLED_BACK: TransitionRule(manual_only=True),
        RecoveryState.ROLLBACK_FAILED: TransitionRule(manual_only=True),
    },
}


def require_transition(current: RecoveryState, target: RecoveryState, *, manual: bool = False) -> None:
    rule = LEGAL_TRANSITIONS.get(current, {}).get(target)
    if rule is None or (rule.manual_only and not manual):
        raise IllegalTransitionError(f"Recovery transition {current.value} -> {target.value} is not authorized.")


def is_terminal(state: RecoveryState) -> bool:
    return state not in LEGAL_TRANSITIONS
