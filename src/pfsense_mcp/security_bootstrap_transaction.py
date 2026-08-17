"""Bootstrap transaction state model (`ADR-033` implementation Phase B,
requirement 5). **Design/data model only -- no HTTP operations, no
pfSense contact, no provisioning of any kind.** Defines the lifecycle a
future bootstrap operation would move through and makes explicit,
checkable invariants about it -- in particular that the temporary
`api-v2-auth-key-post` bootstrap privilege must never appear in the
final steady-state account.

This module contains no code path capable of granting, revoking, or
observing anything on a real pfSense appliance. `BootstrapTransaction`
is a pure state container an *eventual*, separately-authorized
implementation would drive; this phase only defines the states, the
legal transitions between them, and the invariants that must hold at
each one.

No `pfsense_mcp.tier1` import -- this module is not part of, and has no
relationship to, Tier 1's `RecoveryContract`/authorization chain.
pfSense privilege provisioning and Tier 1's cryptographic mutation
authorization remain independent layers (`ADR-033` §7); this is a
transaction model for the former only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

#: The one bootstrap-only privilege this project has ever needed
#: (`ADR-026`, `ADR-033` §1C) -- required solely because pfSense's REST
#: API key model forces self-service key generation
#: (`username = $this->client->username`), so a brand-new identity
#: cannot obtain its first API key without briefly holding this.
BOOTSTRAP_ONLY_PRIVILEGE = "api-v2-auth-key-post"


class BootstrapState(str, Enum):
    """Ordered lifecycle a future bootstrap operation would move
    through, left to right. No state may be skipped going forward;
    `allowed_next_states()` is the single source of truth for legal
    transitions -- never inferred from enum ordering alone."""

    NOT_STARTED = "not_started"
    USER_CREATED = "user_created"
    BOOTSTRAP_PRIVILEGE_GRANTED = "bootstrap_privilege_granted"
    KEY_GENERATED = "key_generated"
    BOOTSTRAP_PRIVILEGE_REVOKED = "bootstrap_privilege_revoked"
    VERIFIED = "verified"
    #: Not a step on the happy path -- a distinct terminal state a
    #: future implementation would enter (never automatically leave;
    #: see module docstring's rollback stance) if any step fails.
    #: `allowed_next_states()` intentionally returns an empty set for
    #: it: only a human-reviewed, separately-authorized action resumes
    #: or tears down a failed transaction, never this model itself.
    FAILED = "failed"


_ALLOWED_TRANSITIONS: dict[BootstrapState, frozenset[BootstrapState]] = {
    BootstrapState.NOT_STARTED: frozenset({BootstrapState.USER_CREATED, BootstrapState.FAILED}),
    BootstrapState.USER_CREATED: frozenset({BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED, BootstrapState.FAILED}),
    BootstrapState.BOOTSTRAP_PRIVILEGE_GRANTED: frozenset({BootstrapState.KEY_GENERATED, BootstrapState.FAILED}),
    BootstrapState.KEY_GENERATED: frozenset({BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, BootstrapState.FAILED}),
    BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED: frozenset({BootstrapState.VERIFIED, BootstrapState.FAILED}),
    BootstrapState.VERIFIED: frozenset(),  # terminal, successful
    BootstrapState.FAILED: frozenset(),  # terminal, requires human review to resume/tear down
}


def allowed_next_states(current: BootstrapState) -> frozenset[BootstrapState]:
    """The only source of truth for legal transitions -- a future
    implementation must consult this rather than re-deriving transition
    logic ad hoc."""

    return _ALLOWED_TRANSITIONS[current]


def is_legal_transition(current: BootstrapState, target: BootstrapState) -> bool:
    return target in allowed_next_states(current)


class InvariantViolation(Exception):
    """Raised by `check_invariants()` -- never by any code path that
    would itself perform a mutation, since this module performs none."""


@dataclass(frozen=True)
class BootstrapTransaction:
    """A pure, in-memory record of a bootstrap transaction's state and
    the privileges observed at each checkpoint. `state`/`privileges` are
    what a future implementation would persist locally (never on the
    appliance) to survive a crash mid-sequence, per `ADR-033` §3's
    "partial failure" design -- this dataclass is that record's shape,
    not its persistence mechanism (a future implementation decision,
    `ADR-033` §11)."""

    state: BootstrapState
    #: The exact privilege set the account is understood to hold at
    #: this checkpoint -- e.g. after BOOTSTRAP_PRIVILEGE_GRANTED, this
    #: includes BOOTSTRAP_ONLY_PRIVILEGE; after
    #: BOOTSTRAP_PRIVILEGE_REVOKED/VERIFIED, it must not.
    privileges: frozenset[str] = field(default_factory=frozenset)
    #: Populated only when state is FAILED -- which step failed and why.
    failure_detail: str | None = None

    def transition(self, target: BootstrapState, *, privileges: frozenset[str]) -> BootstrapTransaction:
        """Returns a new `BootstrapTransaction` in `target` state.
        Raises `InvariantViolation` (not merely returning an error
        value) for an illegal transition or a state/privilege
        combination that violates §"Invariants" below -- a future
        implementation must not be able to construct a
        `BootstrapTransaction` that silently holds an impossible
        state."""

        if not is_legal_transition(self.state, target):
            raise InvariantViolation(f"illegal transition: {self.state.value} -> {target.value}")

        candidate = BootstrapTransaction(state=target, privileges=privileges)
        check_invariants(candidate)
        return candidate

    def fail(self, detail: str) -> BootstrapTransaction:
        """The one transition that may be taken from any non-terminal
        state -- recorded explicitly rather than silently discarding
        which step was in progress when the failure occurred."""

        if self.state in (BootstrapState.VERIFIED, BootstrapState.FAILED):
            raise InvariantViolation(f"cannot fail from terminal state {self.state.value}")
        return BootstrapTransaction(state=BootstrapState.FAILED, privileges=self.privileges, failure_detail=detail)


def check_invariants(transaction: BootstrapTransaction) -> None:
    """Raises `InvariantViolation` if `transaction` violates any
    required invariant for its own `state`. The one this phase was
    explicitly asked to make explicit: **the temporary bootstrap
    privilege must never be present once the transaction has left
    `BOOTSTRAP_PRIVILEGE_GRANTED`/`KEY_GENERATED`** -- in particular, it
    must be absent by `BOOTSTRAP_PRIVILEGE_REVOKED` and remain absent at
    `VERIFIED`, the only state that represents a legitimate final
    steady-state account."""

    has_bootstrap_priv = BOOTSTRAP_ONLY_PRIVILEGE in transaction.privileges

    if transaction.state in (BootstrapState.NOT_STARTED, BootstrapState.USER_CREATED) and has_bootstrap_priv:
        raise InvariantViolation(
            f"{transaction.state.value}: bootstrap privilege must not be present before it is granted"
        )

    if (
        transaction.state in (BootstrapState.BOOTSTRAP_PRIVILEGE_REVOKED, BootstrapState.VERIFIED)
        and has_bootstrap_priv
    ):
        raise InvariantViolation(
            f"{transaction.state.value}: bootstrap privilege must not be present in the steady-state account "
            "-- this is the one invariant this transaction model exists to enforce (ADR-033 §5)"
        )


def is_steady_state_privilege_set(privileges: frozenset[str]) -> bool:
    """A standalone, easily-unit-tested predicate expressing the same
    invariant `check_invariants()` enforces for `VERIFIED`/
    `BOOTSTRAP_PRIVILEGE_REVOKED` -- usable independently of the
    transaction state machine (e.g. by a future `doctor` drift check
    that only has an account's current privilege list, not a
    `BootstrapTransaction`)."""

    return BOOTSTRAP_ONLY_PRIVILEGE not in privileges
