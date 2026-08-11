"""ADR-022 Phase B: canonical, deterministic `PlanDigest` computation.

Gives every `SecurityPosturePlan` (`security_plan.py`, ADR-021/022) a
deterministic, immutable identity a *future* authorization artifact can
bind to. **This module computes/verifies plan identity only.** It does
NOT create authorization artifacts, grant authorization, validate
operator approval, execute anything, provision anything, or enable
WRITE -- none of those exist anywhere in this repository yet, and this
module does not build any of them. See `docs/adr/
ADR-022-execution-authorization-boundary.md`'s "PlanDigest" section
(Decision item 3) for the accepted design this module implements
exactly.

**A `PlanDigest` is plan identity. It is NOT authorization, a secret, a
bearer token, proof of operator consent, or execution permission.** It
exists to prevent exactly one failure: a plan reviewed by an operator
(Plan A) being silently substituted, before or during a future
authorization step, by a different plan (Plan B) that happens to share
some superficial similarity -- by making any digest-participating
change to a plan produce a different, unrelated digest. A matching
digest only ever means "this is identity-equal to the plan that was
computed," nothing more.

This is the second, narrow, explicit exception (alongside
`security_discovery.py`) to `pfsense_mcp.tier1` never being imported
from outside its own package for `security_plan.py`'s own family of
modules -- and unlike `security_discovery.py`, the only thing imported
from `pfsense_mcp.tier1` here is `canonical.py`: pure, stateless
canonicalization and hashing with zero I/O, zero SQLite, zero TPM/store
access, and zero mutation capability of any kind. `tests/tier1/
test_isolation.py`'s exemption list now names this file explicitly, and
`tests/test_security_plan_digest_isolation.py` proves, by direct AST
inspection, that the only `pfsense_mcp.tier1` import here is
`canonical`, nothing else.

Computes the digest from an already-generated `SecurityPosturePlan`
object only -- reuses `security_plan.py`'s own, already-mutation-free
`generate_security_posture_plan()` as the sole source of plan content;
this module never calls `discover_security_posture()` (or anything
else) itself, and therefore never performs a second, independent
discovery pass just to compute a hash.
"""

from __future__ import annotations

import hmac

from .security_plan import (
    PlanStep,
    SecurityPosturePlan,
)
from .tier1.canonical import CanonicalValue, DigestPurpose, digest_value

#: Bumped whenever a digest-participating field is added, removed, or
#: reinterpreted -- an old digest computed under a prior schema version
#: can never silently be treated as valid under a new one, because the
#: version itself is hashed as part of the payload (see `_plan_payload()`):
#: any version change alone already changes every future digest, with
#: no separate version-compatibility check required to "fail safely."
PLAN_DIGEST_SCHEMA_VERSION = 1

#: The exact `PlanStep` fields ADR-022 ("PlanDigest -- what participates")
#: names as security-relevant -- the fields that determine *what an
#: authorization for this step would actually permit*. `action`/
#: `description`/`blocked_reason`/`evidence`/`implementation_available`/
#: `reversible`/`security_impact`/`prerequisite_satisfied`/`blocked` are
#: deliberately excluded: human-readable prose or presentation/ordering-
#: derived fields whose change must never silently invalidate an
#: already-reviewed authorization. See this module's own docstring and
#: ADR-022 Decision item 3 for the full accepted reasoning.
_STEP_DIGEST_FIELDS = ("step_id", "order", "axis", "mutation_class", "authorization_required")


def _step_payload(step: PlanStep) -> dict[str, CanonicalValue]:
    return {
        "step_id": step.step_id,
        "order": step.order,
        "axis": step.axis,
        "mutation_class": step.mutation_class.value,
        "authorization_required": step.authorization_required.value,
    }


def _evidence_fingerprint(plan: SecurityPosturePlan) -> dict[str, CanonicalValue]:
    """The compact, *structured* evidence fingerprint ADR-022 requires --
    `capability_posture.value`/`anchor_assurance.{value, evidence_state,
    baseline, witness_value, provisioned_at}` -- the same fields
    `security_plan.py` itself already treats as authoritative, never the
    raw prose `evidence` tuples (which would make the digest fragile to
    non-semantic wording changes in `security_discovery.py`, exactly the
    failure mode ADR-022 explicitly rejects)."""

    anchor = plan.current.anchor_assurance
    return {
        "capability_posture_value": plan.current.capability_posture.value.value,
        "anchor_assurance_value": anchor.value.value,
        "anchor_evidence_state": anchor.evidence_state.value,
        "anchor_baseline": anchor.baseline,
        "anchor_witness_value": anchor.witness_value,
        "anchor_provisioned_at": anchor.provisioned_at,
    }


def _plan_payload(plan: SecurityPosturePlan) -> dict[str, CanonicalValue]:
    """The complete canonical payload `PlanDigest` hashes -- every key
    ADR-022 names as participating, and nothing it names as excluded.
    Every optional value is represented explicitly as `null` when absent
    (never an omitted key), so "no value" and "key not present" can
    never be confused with each other. No key here is ever named
    `plan_digest`/`digest`/anything digest-shaped -- the digest is never
    computed over itself; see `compute_plan_digest()`."""

    return {
        "schema_version": PLAN_DIGEST_SCHEMA_VERSION,
        "target_capability_posture": plan.target_capability_posture.value,
        "target_anchor_assurance": plan.target_anchor_assurance.value,
        "target_validity": plan.target_validity.value,
        "steps": [_step_payload(step) for step in plan.steps],
        "evidence_fingerprint": _evidence_fingerprint(plan),
        "overall_status": plan.overall_status.value,
        "safe_to_proceed": plan.safe_to_proceed,
    }


def compute_plan_digest(plan: SecurityPosturePlan) -> str:
    """Pure, deterministic, and total over every `SecurityPosturePlan`
    `generate_security_posture_plan()` can produce. No I/O of any kind;
    no SQLite, TPM, witness, pfSense, Proxmox, environment, or
    filesystem access; never mutates `plan` or anything else. Computing
    this digest is not authorization, does not require authorization,
    and grants nothing -- it only names a plan.

    Deterministic across process restarts, dict-insertion order, and
    repeated invocations against identical evidence, because the payload
    is built as an explicit, ordered structure (this function's own
    code, not `plan.__dict__`/`dataclasses.asdict()`/`repr()`) and
    hashed via `tier1.canonical.digest_value()`/`canonical_json()`,
    which already guarantees key-sorted, whitespace-free, Unicode-
    normalized JSON encoding -- the same primitive
    `RecoveryContract.idempotency_key` already relies on, reused here
    rather than reinvented."""

    return digest_value(DigestPurpose.PLAN, _plan_payload(plan))


def verify_plan_digest(plan: SecurityPosturePlan, expected_digest: str) -> bool:
    """Pure. Never mutates `plan` or any other state. Never trusts
    `expected_digest` as an input to its own computation -- always
    independently recomputes the digest from `plan` alone via
    `compute_plan_digest()`, then compares, in constant time
    (`hmac.compare_digest()`, the same comparison discipline
    `ConfirmationEvidence.verify_bindings()` already uses for its own
    digest fields). `expected_digest` is caller-supplied and untrusted:
    a malformed, empty, or non-hex string is never treated as a match
    and never raises -- it simply fails verification, exactly like any
    other mismatch. "Fails safely on unsupported schema versions" holds
    structurally, not via a special-cased check: `schema_version` is
    itself hashed as part of the payload (see `_plan_payload()`), so a
    digest computed under any other schema version can never equal a
    digest computed under this module's current
    `PLAN_DIGEST_SCHEMA_VERSION` -- verification of it fails the same
    ordinary way any other content mismatch does, without this function
    needing to know anything about prior schema versions at all.

    This is plan-identity verification only -- it never validates
    operator approval, never checks an authorization artifact's
    signature/expiry/scope, and never executes anything. No
    authorization-verification primitive exists anywhere in this
    repository yet."""

    return hmac.compare_digest(compute_plan_digest(plan), expected_digest)
