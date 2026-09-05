"""Closed recovery state machine for future Tier 1 execution."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

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


LEGAL_TRANSITIONS: Mapping[RecoveryState, Mapping[RecoveryState, TransitionRule]] = MappingProxyType(
    {
        RecoveryState.PREPARING: MappingProxyType(
            {
                RecoveryState.PREPARED: TransitionRule(),
                RecoveryState.FAILED: TransitionRule(),
                RecoveryState.EXPIRED: TransitionRule(),
            }
        ),
        RecoveryState.PREPARED: MappingProxyType(
            {
                RecoveryState.EXECUTING: TransitionRule(),
                RecoveryState.FAILED: TransitionRule(),
                RecoveryState.EXPIRED: TransitionRule(),
            }
        ),
        RecoveryState.EXECUTING: MappingProxyType(
            {
                RecoveryState.VERIFIED: TransitionRule(),
                RecoveryState.FAILED: TransitionRule(),
                RecoveryState.RECONCILIATION: TransitionRule(),
            }
        ),
        RecoveryState.VERIFIED: MappingProxyType({RecoveryState.ROLLING_BACK: TransitionRule()}),
        RecoveryState.ROLLING_BACK: MappingProxyType(
            {
                RecoveryState.ROLLED_BACK: TransitionRule(),
                RecoveryState.ROLLBACK_FAILED: TransitionRule(),
                RecoveryState.RECONCILIATION: TransitionRule(),
            }
        ),
        RecoveryState.RECONCILIATION: MappingProxyType(
            {
                RecoveryState.VERIFIED: TransitionRule(manual_only=True),
                RecoveryState.FAILED: TransitionRule(manual_only=True),
                RecoveryState.ROLLING_BACK: TransitionRule(manual_only=True),
                RecoveryState.ROLLED_BACK: TransitionRule(manual_only=True),
                RecoveryState.ROLLBACK_FAILED: TransitionRule(manual_only=True),
            }
        ),
    }
)


def require_transition(current: RecoveryState, target: RecoveryState, *, manual: bool = False) -> None:
    rule = LEGAL_TRANSITIONS.get(current, {}).get(target)
    if rule is None or (rule.manual_only and not manual):
        raise IllegalTransitionError(f"Recovery transition {current.value} -> {target.value} is not authorized.")


def is_terminal(state: RecoveryState) -> bool:
    return state not in LEGAL_TRANSITIONS


#: 2026-09-05 owner-directed design: the semantic-idempotency classification
#: is deliberately its own concept, distinct from `is_terminal()` above.
#: `is_terminal()` answers "does the state machine still permit a
#: transition out of this state" (e.g. `VERIFIED` is NOT terminal by that
#: definition -- it still permits `ROLLING_BACK`). This set answers a
#: narrower, security-relevant question: "does a historical contract in
#: this state mean the real-world effect of its semantic operation is not
#: yet fully, confidently resolved, such that a *second*, independently
#: authorized attempt at the exact same semantic operation must be refused
#: while this one exists." See docs/adr/<idempotency-retry-adr> for the
#: full per-state justification; the summary:
#:
#: - PREPARING/PREPARED/EXECUTING/RECONCILIATION/ROLLING_BACK/
#:   ROLLBACK_FAILED: blocking. Each represents an attempt whose real-world
#:   outcome is not yet fully known, or (PREPARING) whose own contract
#:   creation is not even known to have completed -- `_INTERRUPTED_STATES`
#:   in store.py only sweeps EXECUTING/ROLLING_BACK on restart, so a
#:   PREPARING row is not otherwise guaranteed to ever be revisited.
#: - VERIFIED: blocking, DELIBERATELY, even though the mutation is
#:   confirmed successful. Every capability adapter's own `prepare()`
#:   happens to already refuse a semantically-identical request as a
#:   no-op today (verified across all six adapters: alias-description and
#:   all five Batch-1 capabilities) -- but that is an adapter-authored
#:   convention, not a property this protocol/state machine structurally
#:   enforces for every future adapter. Blocking VERIFIED here means a
#:   deliberate re-application of an already-successful mutation (e.g.
#:   after legitimate external state drift outside this system) must go
#:   through an explicit `ROLLING_BACK` -> `ROLLED_BACK` cycle first --
#:   a conscious human acknowledgment that the prior success is being
#:   deliberately unwound -- rather than silently permitting a second,
#:   unrelated-looking contract to coexist with an unacknowledged
#:   verified one. This is exactly the class of "did I already do this?"
#:   confusion the field exists to prevent (ADR-025: "replay guard, not
#:   authorization proof").
#: - FAILED: permitted. ADR-037 (Recovery classification table) already
#:   documents FAILED as "proven zero effect" -- an established,
#:   pre-existing invariant of the fault-classification design this
#:   change does not revisit. (Observation, not a change: the
#:   "2xx received but not semantically verified" sub-case also reaches
#:   FAILED via its own explicit `classify_fault()` call in
#:   `executor.py::execute()`, a separate code path from the general
#:   boundary/knowledge switch -- worth its own future scrutiny, out of
#:   scope here.)
#: - ROLLED_BACK: permitted. An explicitly *verified* rollback proves the
#:   live target was confirmed reverted to its pre-mutation baseline; a
#:   fresh attempt afterward is a legitimate new intentional action, not
#:   a duplicate.
#: - EXPIRED: permitted. The state this design introduces specifically
#:   for a PREPARED contract that never began confirmation/execution --
#:   by construction (no legal transition into EXECUTING skips the
#:   confirmed+unexpired check in `store.transition()`), zero pfSense
#:   contact could ever have occurred for a contract expired while still
#:   PREPARED.
BLOCKING_IDEMPOTENCY_STATES = frozenset(
    {
        RecoveryState.PREPARING,
        RecoveryState.PREPARED,
        RecoveryState.EXECUTING,
        RecoveryState.VERIFIED,
        RecoveryState.RECONCILIATION,
        RecoveryState.ROLLING_BACK,
        RecoveryState.ROLLBACK_FAILED,
    }
)


def blocks_fresh_idempotency_attempt(state: RecoveryState) -> bool:
    """True if a historical contract in this state must prevent a fresh,
    independently-authorized attempt at the same semantic idempotency
    identity from being created. See `BLOCKING_IDEMPOTENCY_STATES`'s own
    module-level comment for the full per-state justification."""

    return state in BLOCKING_IDEMPOTENCY_STATES
