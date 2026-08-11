"""ADR-022 Phase E, Slice E1 (per `docs/adr/ADR-024-execution-authorization-coordination.md`):
the freshness/precondition re-check primitive, and nothing else.

**The one invariant this module establishes**: *a previously authorized
security posture plan is considered fresh only when a newly discovered
authoritative posture, passed through the existing deterministic
plan-generation path and canonical plan-digest computation, reproduces
the exact authorized `plan_digest`.* No weaker proxy (in particular,
`PlanAuthorization.evidence_fingerprint` alone) is sufficient -- see
"Why not `evidence_fingerprint`" below.

**This module produces no runtime effect connected to anything that
mutates anything.** It does NOT consume/replay-track an authorization
(`tier1/authorization_consumption_store.py`, untouched, unimported),
does NOT verify a signature (`security_authorization_verifier.py`,
untouched, unimported), does NOT create a `RecoveryContract`, and is
NEVER imported by `MutationExecutor`, `tier1/state_machine.py`,
`WriteApiClient`, `WriteEndpoints`, MCP tool registration, or any future
`ExecutionCoordinator` (proved by
`tests/test_security_plan_freshness_isolation.py`). There is no
`execute()`, `apply()`, `consume()`, or `is_authorized_for_runtime()`
method anywhere in this module.

## Why not `evidence_fingerprint`

`PlanAuthorization.evidence_fingerprint` (already-shipped, Phase C) is
a compact, six-field copy of the *current*-state fields
`compute_plan_digest()` also hashes. It is explicitly **not**
sufficient as the authoritative freshness gate, because it does not
cover the `steps` list -- `steps` participates in `plan_digest`
(`security_plan_digest.py`'s own participates-list) but is not one of
`evidence_fingerprint`'s six fields. If `security_plan.py`'s
step-generation logic ever changed between authorization time and a
later freshness check (a code change, not a live-evidence change),
`evidence_fingerprint` would show no difference even though
`plan_digest` would. This module therefore never even reads
`evidence_fingerprint` -- it always recomputes and compares the full
`plan_digest`, the only check ADR-024 identifies as authoritative.

## Impure acquisition vs. pure comparison

The one public function this module exposes,
`plan_authorization_is_fresh()`, is a thin wrapper composing two
already-existing, already-tested primitives, in this fixed order:

1. **Impure**: `security_plan.generate_security_posture_plan(target_capability_posture,
   target_anchor_assurance, env)` -- the *existing*, canonical,
   deterministic planner. This module performs exactly this one I/O
   call (itself calling `discover_security_posture()` internally,
   unchanged) and no other. It never re-implements discovery or
   planning.
2. **Pure**: `security_plan_digest.verify_plan_digest(fresh_plan,
   expected_plan_digest)` -- the *existing* Phase B primitive, already
   proven (`tests/test_security_plan_digest.py`) to always
   independently recompute `compute_plan_digest(fresh_plan)` and never
   trust a caller-supplied digest as its own computation input. This
   module adds **no second hashing/canonicalization implementation** --
   it calls this one, unchanged.

No public symbol in this module accepts a pre-built `SecurityPosturePlan`
from a caller, and no public symbol accepts a caller-supplied "recomputed
digest" standing in for the fresh plan. `plan_authorization_is_fresh()`
takes only the *target parameters* (what was originally requested --
`target_capability_posture`/`target_anchor_assurance`, both plain enum
values with no security-sensitive content of their own) and the
*expected* digest to check against -- it always derives the actual fresh
digest itself, internally, via the one call chain above. This makes "a
caller substitutes a plan for a digest, or vice versa" structurally
impossible: there is no parameter shaped like either a plan or a
recomputed digest for a caller to supply in the first place.

## Failure semantics

- **Ordinary mismatch** (the fresh plan's digest genuinely differs from
  `expected_plan_digest`, or `expected_plan_digest` is a malformed/
  wrong-type value): returns `False`. Matches `verify_plan_digest()`'s
  own "never raises for malformed input" contract, extended here to
  non-`str` `expected_plan_digest` values too (a case
  `verify_plan_digest()`'s own `hmac.compare_digest()` call would
  otherwise raise `TypeError` for -- caught and normalized to `False`
  here, without modifying `security_plan_digest.py` itself).
- **Discovery or plan-generation failure** (an exception from
  `generate_security_posture_plan()`/`discover_security_posture()` --
  not an ordinary "evidence indeterminate" result, which that layer
  already represents as a typed, non-raising outcome, but a genuine,
  unexpected failure): raises `PlanFreshnessError`, a new, narrowly-scoped
  exception local to this module. Never silently returns `False` for
  this case and never lets the original exception (which could carry a
  raw path/config detail) propagate unsanitized -- mirrors
  `store.confirm()`'s own `except Exception: raise ...Error(...) from
  None` sanitization discipline exactly.
- **Digest-generation failure** (an exception from
  `compute_plan_digest()`, reached via `verify_plan_digest()`, for a
  pathological plan shape): also raises `PlanFreshnessError`, caught by
  the same `try`/`except` block as discovery/plan-generation failures --
  this module does not attempt to distinguish *where* in the call chain
  an unexpected exception originated, only that one occurred.
- **Fail-closed, uniformly**: every one of the above is "not
  authorized to proceed" from a caller's perspective -- `False` for a
  determinate "no," a raised `PlanFreshnessError` for an indeterminate
  "cannot tell." Neither is ever treated as "assume fresh."

## What this module deliberately does not do

- Does not classify a mismatch as ordinary `STALE` vs. a security
  anomaly (`ADR-022`'s own `PlanOverallStatus` classification already
  exists on the freshly-generated `SecurityPosturePlan` object itself,
  for a future caller to inspect if it wants that distinction -- this
  module's own contract is the binary freshness gate only, per
  `ADR-024`'s own Slice E1 scope).
- Does not consume, mark, or otherwise touch any `PlanAuthorization` or
  `authorization_id` -- it never imports
  `tier1.authorization_consumption_store` or
  `security_authorization`/`security_authorization_verifier` at all.
- Does not construct, call, or reference `MutationExecutor`,
  `tier1.state_machine`, `RecoveryContract`,
  `SqliteRecoveryContractStore`, `WriteApiClient`, or `WriteEndpoints`.
- Does not implement `ExecutionCoordinator` or any composition of this
  primitive with any other Phase D primitive -- that composition
  remains Slice E2/E3's own, separately-authorized job
  (`ADR-024`'s own explicit warning against a combined
  `verify_and_consume()`-shaped convenience function applies equally
  here to a hypothetical `verify_and_check_freshness()`).

## Isolation

Zero `pfsense_mcp.tier1` imports -- mirrors `security_plan.py`'s own
existing invariant exactly (no new tier1-isolation exemption is needed
or introduced by this file). The only relative imports are
`.security_discovery` (for `CapabilityPosture`/`AnchorAssurance`, the
same defining module `security_plan.py` itself imports them from) and
`.security_plan`/`.security_plan_digest` (the two existing primitives
this module composes). See
`tests/test_security_plan_freshness_isolation.py` for the AST-based
proof, including that no production module imports this one yet.
"""

from __future__ import annotations

from .security_discovery import AnchorAssurance, CapabilityPosture
from .security_plan import generate_security_posture_plan
from .security_plan_digest import verify_plan_digest

__all__ = ["PlanFreshnessError", "plan_authorization_is_fresh"]


class PlanFreshnessError(Exception):
    """Freshness could not be determined -- an unexpected failure during
    discovery, plan generation, or digest computation, never an
    ordinary "the plan differs" outcome (that case returns `False`).
    Never raised for a caller-supplied `expected_plan_digest` of the
    wrong type or format -- see module docstring "Failure semantics"."""


def plan_authorization_is_fresh(
    *,
    target_capability_posture: CapabilityPosture,
    target_anchor_assurance: AnchorAssurance,
    expected_plan_digest: str,
    env: dict[str, str] | None = None,
) -> bool:
    """`True` only if a freshly generated `SecurityPosturePlan` for the
    given target parameters -- via the existing, canonical
    `generate_security_posture_plan()` -- produces, via the existing,
    canonical `compute_plan_digest()` (called internally by
    `verify_plan_digest()`, never re-implemented here), a digest that
    exactly matches `expected_plan_digest`.

    `expected_plan_digest` is never trusted as an input to any
    computation -- it is only ever the right-hand side of an equality
    check against an independently, freshly recomputed value. A
    malformed or wrong-type `expected_plan_digest` returns `False`,
    never raises.

    Raises `PlanFreshnessError` -- sanitized, no original exception
    detail retained -- if discovery, plan generation, or digest
    computation fails unexpectedly. This is a distinct outcome from
    `False`: `False` means "freshness was checked and the plan is not
    fresh"; a raised `PlanFreshnessError` means "freshness could not be
    checked at all." A caller must treat both as "not authorized to
    proceed" -- neither is ever a signal to proceed.

    Performs exactly one read-only call chain
    (`generate_security_posture_plan()`, which itself calls
    `discover_security_posture()` exactly once) and no other I/O.
    Mutates nothing -- `SecurityPosturePlan`/`PlanStep` are frozen
    dataclasses, and neither `generate_security_posture_plan()` nor
    `verify_plan_digest()` performs any write."""

    if not isinstance(expected_plan_digest, str):
        return False
    try:
        fresh_plan = generate_security_posture_plan(target_capability_posture, target_anchor_assurance, env)
        return verify_plan_digest(fresh_plan, expected_plan_digest)
    except Exception:
        raise PlanFreshnessError("Unable to determine plan authorization freshness.") from None
