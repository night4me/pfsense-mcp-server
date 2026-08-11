"""ADR-022 Phase E, Slice E2 (per `docs/adr/ADR-024-execution-authorization-coordination.md`):
the `ExecutionCoordinator` skeleton, through successful one-time
authorization consumption -- and nothing past it.

**The one invariant this slice establishes**: *an execution attempt may
reach the consumed state only after all currently available
pre-execution authorization gates succeed, in this exact order:
signature validity, expiry/currentness, exact plan-digest + authorized-
step membership, full freshness re-check, then durable one-time
`authorization_id` consumption.* Reaching the end of a successful call
means exactly that and nothing more -- no `RecoveryContract` is
created, `MutationExecutor` is never invoked, and `tier1/state_machine.py`
is never touched, anywhere in this module.

**Owner scope, fixed for this slice**: coordinator placement is
`tier1/execution_coordinator.py` (an explicit owner decision, not this
module's own choice); it must not call `MutationExecutor`; it must not
create a `RecoveryContract`; it must not alter Tier 1 state-machine
state; it must not expose any WRITE surface; it must not add
`target_identity_digest`/`netgate_id`/`pfhostid` or any substitute for
appliance-identity binding (the gap named in `ADR-024` remains open,
unresolved, and untouched here).

## Composed primitives, composed once, never re-implemented

This module contains no cryptography, no canonicalization, no hashing,
no discovery logic, and no persistence logic of its own. It composes,
in the fixed order below, five already-shipped primitives:

1. `security_authorization_verifier.verify_plan_authorization_signature()`
   (Phase D) -- signature validity.
2. `security_authorization_verifier.plan_authorization_is_current()`
   (Phase D) -- expiry/currentness.
3. `security_authorization_verifier.plan_authorization_authorizes_step()`
   (Phase D) -- exact plan-digest + authorized-step membership, checked
   against a caller-supplied `(requested_plan_digest, requested_step_id)`
   reference (never a tautological self-comparison against `authz`'s
   own fields -- see "Why `requested_plan_digest` is a separate
   parameter" below).
4. `security_plan_freshness.plan_authorization_is_fresh()` (Phase E,
   Slice E1) -- full freshness re-check via real plan regeneration and
   exact `plan_digest` recomputation. **This also structurally subsumes
   anchor/capability-appropriateness**: `ADR-024`'s own text notes an
   invalid target combination never reaches
   `generate_security_posture_plan()`'s output at all, and any anchor
   regression since authorization time changes the freshly regenerated
   plan's own digest -- so a separate, redundant anchor check is
   deliberately not added here (the coordinator's own "MUST NOT
   duplicate any check another component already owns" responsibility,
   per `ADR-024`'s responsibility matrix).
5. `tier1.authorization_consumption_store.AuthorizationConsumptionStore.try_consume()`
   (Phase D) -- durable one-time consumption. The *only* state-changing
   call in this module, and the *last* one -- see "Consumption
   semantics" below.

## Why `requested_plan_digest` is a separate parameter

`plan_authorization_authorizes_step(authz, plan_digest=..., step_id=...)`
checks that `authz.plan_digest` exactly matches the supplied
`plan_digest` *and* that the supplied `step_id` is an authorized
member. Passing `authz.plan_digest` back as its own comparison target
would be a tautology (always true) and would defeat the check's actual
purpose: confirming that *what the caller believes they are requesting*
(`requested_plan_digest`/`requested_step_id` -- the same `(plan_digest,
step_id)`-shaped reference `ADR-022`'s own "MCP WRITE boundary" section
names as the only thing a future WRITE tool may ever accept from a
caller) matches *what `authz` actually authorizes*. This closes a
confused-deputy class of error: presenting a valid `authz` for Plan A
while claiming (accidentally or otherwise) to be requesting a step from
Plan B.

## Consumption semantics (unchanged from `ADR-024`'s owner-approved decision)

"One authorization permits one attempt to create a `RecoveryContract`."
This slice does not create a `RecoveryContract` at all -- so a
successful call here represents strictly less than that: *all
pre-execution gates passed, and the authorization has been durably
consumed.* No `claim`/`commit`, no pending/reservation state, no
consumption rollback, and no retry-after-consumption semantics are
implemented, added, or implied. The crash/availability tradeoff
`ADR-024` already named and accepted for v1 (a crash between
consumption and whatever comes next loses the authorization with
nothing to show for it) is unchanged and unaddressed by this slice --
this slice does not even reach the point that gap describes, since it
stops at consumption itself.

## Failure semantics -- one sanitized outcome, never which gate failed

Every failed gate raises the same `PreExecutionAuthorizationDenied`,
with a fixed, generic message -- this module never reveals *which*
gate failed in the exception it raises, matching this codebase's
existing "sanitized failure class" discipline
(`ConfirmationEvidence`/`confirmation_authority.md`'s own I4 invariant:
verification failures never leak *why*, only that they failed).
Composed primitives' own indeterminate-outcome exceptions
(`SecurityAuthorizationError`, `security_plan_freshness.PlanFreshnessError`,
`AuthorizationConsumptionError`) are caught internally and folded into
the same ordinary "gate failed" outcome -- never leaked with their
original, potentially path/config-bearing message text. **A failed
gate, of any kind, before consumption is guaranteed to leave the
authorization unconsumed** -- every gate in the ordering above runs to
completion (or fails) *before* `try_consume()` is ever called; there is
no code path that reaches consumption without every earlier gate having
already returned `True`.

## Bypass resistance -- explicit limitation, not a claim of more than exists

**Python has no language-level mechanism preventing a caller who holds
a reference to this coordinator's own composed dependencies
(`PinnedAuthoritySet`, `AuthorizationConsumptionStore`) from calling
those primitives directly, bypassing this coordinator entirely.** This
module does not claim otherwise. What it *does* provide, matching
`ADR-024`'s own "construction-site and process/review-level guarantee"
framing exactly: this module never itself constructs or imports
`MutationExecutor`, `tier1.state_machine`, `RecoveryContract`, or
`SqliteRecoveryContractStore` (proved by
`tests/tier1/test_execution_coordinator_isolation.py`), so it cannot,
by construction, be a path *toward* execution even if someone did
bypass it -- there is nothing on the far side of this module to reach.
Direct-executor bypass resistance for a real future execution path
remains exactly the open, review-time/AST-test-time boundary `ADR-024`'s
own "Direct-executor bypass resistance (E7)" section already describes
-- this slice does not change, strengthen, or weaken that analysis.
"""

from __future__ import annotations

from datetime import datetime

from ..security_authorization import PlanAuthorization, SecurityAuthorizationError
from ..security_authorization_verifier import (
    plan_authorization_authorizes_step,
    plan_authorization_is_current,
    verify_plan_authorization_signature,
)
from ..security_discovery import AnchorAssurance, CapabilityPosture
from ..security_plan_freshness import PlanFreshnessError, plan_authorization_is_fresh
from .authorization_consumption_store import AuthorizationConsumptionStore
from .ed25519_authority import PinnedAuthoritySet
from .errors import AuthorizationConsumptionError

__all__ = [
    "ExecutionCoordinator",
    "PreExecutionAuthorizationDenied",
    "PreExecutionAuthorizationGranted",
]

_DENIED_MESSAGE = "Pre-execution authorization denied."


class PreExecutionAuthorizationDenied(Exception):
    """Raised for every failed pre-execution gate, uniformly -- never
    reveals which gate failed. The authorization is guaranteed not
    consumed whenever this is raised (see module docstring)."""


class PreExecutionAuthorizationGranted:
    """The only successful outcome `ExecutionCoordinator.authorize_and_consume()`
    can produce. Its existence means exactly one thing: every
    pre-execution gate passed and `authorization_id` was durably,
    atomically consumed. It is **not** a `RecoveryContract`, **not** an
    execution capability, and carries no method resembling `execute()`/
    `apply()`/`is_authorized_for_runtime()` -- deliberately an inert
    marker, nothing more."""

    __slots__ = ("authorization_id",)

    def __init__(self, *, authorization_id: str) -> None:
        self.authorization_id = authorization_id


class ExecutionCoordinator:
    """Composes the five gates listed in the module docstring, in that
    fixed order, ending at authorization consumption. Constructed with
    its two dependencies injected (never global state, mirroring
    `MutationExecutor`'s own constructor-injection convention) -- not
    constructed by production anywhere in this repository."""

    def __init__(
        self,
        *,
        authorities: PinnedAuthoritySet,
        consumption_store: AuthorizationConsumptionStore,
    ) -> None:
        self._authorities = authorities
        self._consumption_store = consumption_store

    def authorize_and_consume(
        self,
        authz: PlanAuthorization,
        *,
        requested_plan_digest: str,
        requested_step_id: str,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        now: datetime,
        env: dict[str, str] | None = None,
    ) -> PreExecutionAuthorizationGranted:
        """Runs every gate in the module docstring's fixed order.
        Raises `PreExecutionAuthorizationDenied` (sanitized, uniform) on
        the first gate that fails -- every earlier gate has already
        returned `True` by the time a later one runs, and
        `try_consume()` is never reached unless all four prior gates
        passed. Returns a `PreExecutionAuthorizationGranted` marker,
        carrying only `authorization_id`, on success."""

        # 1. Structural/required input validation -- cheapest, no I/O,
        # no cryptography. Runs before anything else.
        if (
            not isinstance(authz, PlanAuthorization)
            or not isinstance(requested_plan_digest, str)
            or not isinstance(requested_step_id, str)
            or not requested_step_id
            or not isinstance(target_capability_posture, CapabilityPosture)
            or not isinstance(target_anchor_assurance, AnchorAssurance)
            or not isinstance(now, datetime)
        ):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        # 2. Signature verification -- pure, cheap, no I/O.
        if not verify_plan_authorization_signature(authz, self._authorities):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        # 3. Expiry / currentness -- pure, cheap, no I/O.
        if not self._is_current(authz, now):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        # 4. Exact plan digest + authorized step membership -- pure,
        # cheap, no I/O. See module docstring for why
        # `requested_plan_digest` is a caller-supplied reference, never
        # authz.plan_digest compared against itself.
        if not plan_authorization_authorizes_step(authz, plan_digest=requested_plan_digest, step_id=requested_step_id):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        # 5. Full freshness re-check -- the one read-only I/O boundary
        # in this method. Only reached once every cheaper, pure check
        # above has already passed.
        if not self._is_fresh(authz, target_capability_posture, target_anchor_assurance, env):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        # 6. Durable one-time consumption -- the only state-changing
        # call in this method, and the last gate. Nothing before this
        # point ever mutates anything.
        if not self._try_consume(authz.authorization_id):
            raise PreExecutionAuthorizationDenied(_DENIED_MESSAGE)

        return PreExecutionAuthorizationGranted(authorization_id=authz.authorization_id)

    def _is_current(self, authz: PlanAuthorization, now: datetime) -> bool:
        try:
            return plan_authorization_is_current(authz, now=now)
        except SecurityAuthorizationError:
            return False

    def _is_fresh(
        self,
        authz: PlanAuthorization,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        env: dict[str, str] | None,
    ) -> bool:
        try:
            return plan_authorization_is_fresh(
                target_capability_posture=target_capability_posture,
                target_anchor_assurance=target_anchor_assurance,
                expected_plan_digest=authz.plan_digest,
                env=env,
            )
        except PlanFreshnessError:
            return False

    def _try_consume(self, authorization_id: str) -> bool:
        try:
            return self._consumption_store.try_consume(authorization_id)
        except AuthorizationConsumptionError:
            return False
