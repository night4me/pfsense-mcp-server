"""Capability/target/global rate and blast-radius containment for inert
Tier 1 execution.

Not constructed by production. Not an authorization mechanism --
`MutationPolicy` and the confirmation/reconciliation authorities remain
the only authorization; this exists so a single misbehaving, or fully
authorized but repeatedly invoked, caller cannot turn one approved
capability into unbounded mutation of it. See
docs/tier1/specs/rate_blast_radius_policy.md and docs/adr/ADR-015 for the
full specification and the provisional numeric defaults' status (pending
disposable-lab evidence, not final production values).
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from pfsense_mcp.capabilities import Capability

from .errors import RateLimitExceededError
from .state_machine import RecoveryState

#: A target reaching any of these states starts its cooldown window. Note
#: this deliberately differs from state_machine.is_terminal(): VERIFIED
#: can still legally transition to ROLLING_BACK, but the *original*
#: mutation has concluded, and the cooldown's purpose is to slow how soon
#: a *new, different* PREPARE for the same target is accepted next -- a
#: later rollback of the same contract is unaffected (it is not a new
#: PREPARE).
_COOLDOWN_STATES = frozenset(
    {RecoveryState.VERIFIED, RecoveryState.FAILED, RecoveryState.ROLLED_BACK, RecoveryState.ROLLBACK_FAILED}
)
_IN_FLIGHT_STATES = frozenset({RecoveryState.EXECUTING, RecoveryState.ROLLING_BACK})


def _is_utc(value: datetime) -> bool:
    return value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)


@dataclass(frozen=True)
class RateLimits:
    max_outstanding_prepared_per_target: int
    max_global_in_flight: int
    target_cooldown_seconds: int
    reconciliation_lockout_threshold: int

    def __post_init__(self) -> None:
        for name in (
            "max_outstanding_prepared_per_target",
            "max_global_in_flight",
            "target_cooldown_seconds",
            "reconciliation_lockout_threshold",
        ):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise RateLimitExceededError(f"Rate limit {name!r} must be a non-negative integer.")


class RatePolicy:
    """Every check runs against a connection the caller already holds
    inside an open transaction (store.py's create()/transition() BEGIN
    IMMEDIATE blocks) -- never a separately-opened connection, so a check
    and the state change it gates cannot race against each other."""

    def __init__(self, limits: RateLimits) -> None:
        self._limits = limits

    def check_prepare_allowed(
        self,
        connection: sqlite3.Connection,
        *,
        target_identity_digest: str,
        capability: Capability,
        now: datetime,
    ) -> None:
        """Raises RateLimitExceededError if the reconciliation lockout,
        outstanding-PREPARED, or cooldown limit would be violated.
        `capability` is accepted for forward extensibility (per-capability
        scoping is part of this spec's design) but is not yet gated by a
        distinct numeric limit -- ADR-015 authorized only the four
        RateLimits fields above; a per-capability limit awaits its own
        lab-evidenced default, same as every other number here."""

        if not _is_utc(now):
            raise RateLimitExceededError("Rate policy comparison time must be UTC.")

        reconciliation_count = connection.execute(
            "SELECT COUNT(*) FROM contracts WHERE state = ?", (RecoveryState.RECONCILIATION.value,)
        ).fetchone()[0]
        if reconciliation_count >= self._limits.reconciliation_lockout_threshold:
            raise RateLimitExceededError("Reconciliation lockout: too many contracts require operator resolution.")

        prepared_count = connection.execute(
            "SELECT COUNT(*) FROM contracts WHERE target_identity_digest = ? AND state = ?",
            (target_identity_digest, RecoveryState.PREPARED.value),
        ).fetchone()[0]
        if prepared_count >= self._limits.max_outstanding_prepared_per_target:
            raise RateLimitExceededError("Target already has the maximum outstanding PREPARED contracts.")

        row = connection.execute(
            "SELECT cooldown_until FROM rate_cooldowns WHERE target_identity_digest = ?",
            (target_identity_digest,),
        ).fetchone()
        if row is not None and now < datetime.fromisoformat(str(row[0])):
            raise RateLimitExceededError("Target is within its post-terminal cooldown window.")

    def check_execute_allowed(self, connection: sqlite3.Connection, *, now: datetime) -> None:
        """Raises RateLimitExceededError if max_global_in_flight would be
        exceeded by allowing one more EXECUTING/ROLLING_BACK contract."""

        if not _is_utc(now):
            raise RateLimitExceededError("Rate policy comparison time must be UTC.")

        in_flight = connection.execute(
            "SELECT COUNT(*) FROM contracts WHERE state IN (?, ?)",
            tuple(state.value for state in _IN_FLIGHT_STATES),
        ).fetchone()[0]
        if in_flight >= self._limits.max_global_in_flight:
            raise RateLimitExceededError("Global in-flight mutation limit reached.")

    def record_terminal(self, connection: sqlite3.Connection, *, target_identity_digest: str, now: datetime) -> None:
        """Records/refreshes the cooldown window for a target reaching
        one of _COOLDOWN_STATES. Called from store.py's _replace() for
        every state change, regardless of which method drove it."""

        if not _is_utc(now):
            raise RateLimitExceededError("Rate policy comparison time must be UTC.")

        cooldown_until = (now + timedelta(seconds=self._limits.target_cooldown_seconds)).isoformat()
        connection.execute(
            "INSERT INTO rate_cooldowns(target_identity_digest, cooldown_until) VALUES (?, ?) "
            "ON CONFLICT(target_identity_digest) DO UPDATE SET cooldown_until = excluded.cooldown_until",
            (target_identity_digest, cooldown_until),
        )


def is_cooldown_state(state: RecoveryState) -> bool:
    return state in _COOLDOWN_STATES
