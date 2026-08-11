"""ADR-022 Phase D: pure `PlanAuthorization` verification -- signature,
expiry, and plan/step-scope checks only. See `docs/adr/
ADR-023-authorization-verification-boundary.md` for the accepted Phase D
scope this module implements, and its own "Owner decisions" section
(2026-08-11) for the exact boundary this module deliberately does not
cross.

**This module produces no runtime effect and connects to nothing that
mutates anything.** It does NOT consume/replay-track an authorization
(see `tier1/authorization_consumption_store.py` for that, a wholly
separate concern with its own module), does NOT re-check freshness
against current evidence (`ADR-022`'s Phase E, not this phase), does
NOT create a `RecoveryContract`, and is NEVER imported by
`MutationExecutor`, `tier1/state_machine.py`, `WriteApiClient`,
`WriteEndpoints`, or any other execution-shaped code path in this
repository (proved by `tests/test_security_authorization_verifier_isolation.py`).
There is no `execute()`, `apply()`, or `is_authorized_for_runtime()`
method anywhere in this module.

## Three independent, composable primitives -- deliberately not one combined check

Per the owner's explicit Phase D scope decision: "Prefer narrow new
types/functions over expanding existing execution classes." This module
exposes three separate functions rather than one "verify everything"
entry point, so each of the following stays independently true and
independently testable, never silently implied by another:

- **Signature validity must not imply freshness.** `verify_plan_authorization_signature()`
  says nothing about whether current evidence still matches what was
  reviewed -- that is Phase E's job entirely.
- **Signature validity must not imply successful consumption.**
  Nothing in this module records or checks whether an `authorization_id`
  has ever been used; see `tier1/authorization_consumption_store.py`.
- **Expiry must be checked independently.** `plan_authorization_is_current()`
  is a separate function, never folded into signature verification.
- **Step authorization is exact membership**, never a wildcard, prefix,
  coercive, inferred, or subset-expansion check.

A caller (still not built anywhere in this repository -- Phase D adds
no such caller) is expected to call all of the relevant primitives
itself and require every one it needs to pass; this module deliberately
never composes them, so that composing them remains a decision made at
the point real consumption/execution wiring is eventually, separately
authorized (Phase F/G/H), not accidentally baked in here.

## Signature verification

`verify_plan_authorization_signature()` mirrors
`tier1.confirmation_providers.Ed25519ConfirmationVerifier.verify()`
exactly: checks `authz.algorithm` against the one accepted value, then
delegates to `tier1.ed25519_authority.PinnedAuthoritySet.verify_signature()`
-- the same, already-reviewed, already-tested mechanism
`ConfirmationEvidence`/`ReconciliationEvidence` verification already
reuses twice. **Reused, not duplicated or forked** (the owner's explicit
instruction): this module contains no signature-checking code of its
own beyond that one delegated call.

`PinnedAuthoritySet.verify_signature()` already fails closed for an
unknown or inactive `authority_id` (returns `False`, never raises), and
`PinnedAuthoritySet.__init__()` already refuses to construct with zero
authorities (raises `Tier1Error`) -- both reused unchanged, satisfying
"Verification must fail closed for an unknown or unconfigured
authority" without this module reimplementing either check.

The message actually verified is `plan_authorization_signing_payload(
plan_authorization_payload_of(authz))` -- **always recomputed from
`authz`'s own fields, never trusted from a caller-supplied payload** --
the same "recompute, never trust" discipline `verify_plan_digest()`
established in Phase B.

### Trust-policy separability (owner decision 2, 2026-08-11)

This module never imports, constructs, or references
`confirmation_providers.py`/`reconciliation_providers.py`'s own pinned
authorities in any way. `verify_plan_authorization_signature()` takes a
`PinnedAuthoritySet` as an explicit parameter -- the caller decides
whether to pass the same instance used for confirmation/reconciliation
or a separate one populated with different `PinnedAuthority` entries.
Nothing in this module assumes the roles are interchangeable, and
nothing in this module makes them exclusive either; both remain equally
possible without any code change here. **This is deliberately as far as
this module goes**: no production configuration-loading mechanism for
*any* pinned-authority table exists anywhere in this repository yet
(`confirmation_providers.py`'s own spec explicitly defers that to a
"Phase 3" wiring decision this project has not made for any artifact
type) -- inventing one here, for `PlanAuthorization` specifically, would
be exactly the "broadening scope" the owner's decision explicitly
forbade. **Remaining, explicitly undecided configuration question**:
whether a real deployment eventually configures one shared
pinned-authority table across all three artifact types or a second,
`PlanAuthorization`-specific one is left for that future, separate
activation-time decision -- this module's own signature (accepting a
`PinnedAuthoritySet` value, not loading one) is compatible with either
answer.

## Expiry

`plan_authorization_is_current()` checks only `now < authz.expires_at`,
against a caller-supplied `now` (never `datetime.now()` called
internally -- this module performs no I/O and has no notion of "the
real current time" of its own, mirroring `SqliteRecoveryContractStore._now()`'s
own injectable-clock discipline, reused as a parameter here rather than
a class attribute since this module holds no state). `now` must be a
timezone-aware UTC `datetime`; anything else is refused
(`SecurityAuthorizationError`), never silently coerced. The boundary is
exclusive both ways deliberately: `now == authz.expires_at` is treated
as already expired (`not (now < expires_at)`), matching
`RecoveryContract.is_expired()`'s own existing `current >=
self.expires_at` convention exactly (`tier1/contract.py`) -- reused, not
invented fresh.

**Deliberately does not check `now` against `authz.issued_at`.** Nothing
in `ADR-022`'s accepted `PlanAuthorization` design specifies a
"not-yet-valid before `issued_at`" concept, and the owner's own
adversarial-test list explicitly warns against silently inventing
freshness policy beyond "the currently defined Phase D contract." This
omission is deliberate, not an oversight -- recorded here so a future
reviewer does not mistake it for a gap.

## Plan/step scope

`plan_authorization_authorizes_step()` requires **both**
`authz.plan_digest == plan_digest` (exact string equality, in constant
time via `hmac.compare_digest`, matching every other digest comparison
in this codebase) **and** `step_id in authz.authorized_step_ids` (exact
membership in the signed, immutable tuple). ADR-022's own text: "binding
is always both, never `step_id` membership alone" -- `step_id`s are
stable, human-readable strings deliberately reused across every plan
that contains that step, so checking `step_id` membership without also
requiring the exact `plan_digest` match would let an authorization
issued for one plan silently satisfy a same-named step in a different,
later plan. No wildcard, prefix, or subset-expansion path exists in
this function; `step_id not in authz.authorized_step_ids` is always
tested as exact set membership over an already-validated,
duplicate-free tuple.
"""

from __future__ import annotations

import hmac
from datetime import datetime, timezone

from .security_authorization import (
    AUTHORIZATION_SIGNING_ALGORITHM,
    PlanAuthorization,
    PlanAuthorizationV2,
    SecurityAuthorizationError,
    plan_authorization_payload_of,
    plan_authorization_signing_payload,
    plan_authorization_v2_payload_of,
    plan_authorization_v2_signing_payload,
)
from .tier1.ed25519_authority import PinnedAuthoritySet

__all__ = [
    "plan_authorization_authorizes_step",
    "plan_authorization_is_current",
    "plan_authorization_v2_authorizes_execution",
    "verify_plan_authorization_signature",
    "verify_plan_authorization_v2_signature",
]


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def verify_plan_authorization_signature(authz: PlanAuthorization, authorities: PinnedAuthoritySet) -> bool:
    """`True` only if `authz.proof` is a valid Ed25519 signature, by a
    currently-active pinned authority, over `authz`'s own canonical
    signing payload -- recomputed from `authz`, never trusted from
    anywhere else. Never raises for ordinary malformed/invalid input
    (mirrors `Ed25519ConfirmationVerifier.verify()`'s own contract
    exactly); a malformed `authz` object would already have failed to
    construct (`PlanAuthorization.__post_init__`), so this function
    only ever receives a structurally valid artifact and need not
    re-validate its shape. Says nothing about expiry, consumption, or
    freshness -- see module docstring."""

    if not isinstance(authz, PlanAuthorization) or authz.algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
        return False
    message = plan_authorization_signing_payload(plan_authorization_payload_of(authz))
    return authorities.verify_signature(authority_id=authz.authority_id, message=message, signature=authz.proof)


def verify_plan_authorization_v2_signature(authz: PlanAuthorizationV2, authorities: PinnedAuthoritySet) -> bool:
    """Verify only the signature over one structurally valid v2 artifact."""

    if not isinstance(authz, PlanAuthorizationV2) or authz.algorithm != AUTHORIZATION_SIGNING_ALGORITHM:
        return False
    message = plan_authorization_v2_signing_payload(plan_authorization_v2_payload_of(authz))
    return authorities.verify_signature(authority_id=authz.authority_id, message=message, signature=authz.proof)


def plan_authorization_is_current(authz: PlanAuthorization | PlanAuthorizationV2, *, now: datetime) -> bool:
    """`True` only if `now` is strictly before `authz.expires_at`. `now`
    must be a caller-supplied, timezone-aware UTC `datetime` -- this
    function performs no clock read of its own. Raises
    `SecurityAuthorizationError` for a non-UTC or non-`datetime` `now`,
    never silently treats it as valid. Independent of signature
    verification and of authorization-consumption state; see module
    docstring for why `issued_at` is deliberately not checked here."""

    if not _is_utc(now):
        raise SecurityAuthorizationError("plan_authorization_is_current() requires a timezone-aware UTC 'now'.")
    return now < authz.expires_at


def plan_authorization_authorizes_step(authz: PlanAuthorization, *, plan_digest: str, step_id: str) -> bool:
    """`True` only if `authz.plan_digest` exactly matches `plan_digest`
    (constant-time comparison) *and* `step_id` is an exact member of
    `authz.authorized_step_ids`. Never a wildcard, prefix, coercive,
    inferred, or subset-expansion check -- both conditions are required,
    matching ADR-022's own "binding is always both, never step_id
    membership alone" text exactly."""

    if not isinstance(plan_digest, str) or not isinstance(step_id, str):
        return False
    digest_matches = hmac.compare_digest(authz.plan_digest, plan_digest)
    step_matches = step_id in authz.authorized_step_ids
    return digest_matches and step_matches


def plan_authorization_v2_authorizes_execution(
    authz: PlanAuthorizationV2,
    *,
    plan_digest: str,
    step_id: str,
    execution_intent_digest: str,
) -> bool:
    """Exact v2 plan plus step/digest membership; never recomputes intent."""

    if not isinstance(authz, PlanAuthorizationV2) or not all(
        isinstance(value, str) for value in (plan_digest, step_id, execution_intent_digest)
    ):
        return False
    if not hmac.compare_digest(authz.plan_digest, plan_digest):
        return False
    return any(
        binding.step_id == step_id and hmac.compare_digest(binding.execution_intent_digest, execution_intent_digest)
        for binding in authz.authorized_executions
    )
