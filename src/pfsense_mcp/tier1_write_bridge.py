"""Narrow production wiring boundary: the alias-description first-WRITE
product surface's ONLY connection to `pfsense_mcp.tier1`.

This is the SIXTH, and narrowest possible, explicit exception to
`pfsense_mcp.tier1` never being imported from outside its own package --
exempted by name in `tests/tier1/test_isolation.py::
test_tier1_is_not_imported_outside_its_inert_package`, alongside
`tier1_anchor_check.py` (the first), `security_discovery.py` (second),
`security_plan_digest.py` (third), `security_authorization.py` (fourth),
and `security_authorization_verifier.py` (fifth). Neither `tools/registry.py`
nor `tools/write/set_firewall_alias_description.py` import
`pfsense_mcp.tier1` at all; they only ever call the two functions this
module exposes, keeping the exemption's surface to exactly this one file
-- mirroring `tier1_anchor_check.py`'s own precedent exactly.

What this module exposes, and nothing more:

  - `can_construct_write_runtime()` -- a registration-time probe for W3
    Slice 4's activation-gate condition C ("the complete fail-closed
    production runtime successfully constructs"). Builds a fresh runtime,
    discards it immediately, returns a bare `bool`. Never caches or
    reuses a runtime across calls -- matches `production_runtime.py`'s
    own "every call constructs entirely fresh process-local objects"
    convention.
  - `request_alias_description_change(*, alias_name, description)` -- the
    sole entry point the MCP tool handler calls. Builds a fresh runtime,
    constructs the two-field model-facing request, derives this
    operation's fixed, non-model-controlled authorization expectation
    (see "Plan/step expectation" below), calls the existing, unmodified
    `ProductionAliasDescriptionRuntime.request_alias_description_change()`
    exactly once, and projects its `ProductOutcome` into this module's
    own, non-tier1 `AliasDescriptionWriteResult` model -- no contract
    identifier, no digest, no internal `RecoveryState`, no authorization
    or confirmation artifact detail ever leaves this function.

This module is wiring only. It does not verify a `PlanAuthorizationV2`
signature, does not verify a confirmation, does not create a
`RecoveryContract`, does not call `MutationExecutor`, does not touch
`WriteApiClient` or `WriteEndpoints` directly, and does not perform its
own authorization/confirmation logic of any kind -- every one of those
remains exactly the already-composed
`ProductionAliasDescriptionRuntime.request_alias_description_change()`'s
(W3 Slice 3, unmodified) responsibility. No private signing key is
loaded, accepted, or even referenced anywhere in this module.

## Plan/step expectation -- one shared, security-owned constant source

`request_alias_description_change()` requires `requested_plan_digest`/
`requested_step_id` as CALLER-supplied parameters, deliberately distinct
from whatever a signed `PlanAuthorizationV2` artifact itself claims
(ADR-024: "passing `authz.plan_digest` back as its own comparison target
would be a tautology; the real check is that what the caller believes
they are requesting matches what `authz` actually authorizes"). Since the
MCP tool's model-visible input is only `alias_name`/`description` (no
plan/step selection is model-visible, per this slice's explicit schema
restriction), this module derives them itself, deterministically, from
`security_plan.py`'s own EXISTING, unmodified step-generation logic --
never a caller-selectable or model-supplied value:

  - `target_capability_posture`/`target_anchor_assurance` are
    `security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE`/
    `security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE` --
    imported, not locally re-declared: there is exactly one way this
    operation is ever meant to run, and exactly one place (`security_plan.py`)
    that names what that is.
  - `requested_step_id` is `security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID`
    (value: `"capability_posture.milestone_9_activation"`) -- also
    imported, not locally re-declared. `security_plan.py`'s own existing
    step, named for exactly this purpose ("Obtain the Milestone-9-class
    WRITE activation decision (TIER1_ROADMAP.md) ... then register the
    corresponding WRITE tool(s)"), and now also the value
    `security_plan.py`'s own step-emission code constructs its `PlanStep`
    with -- one constant, two consumers, never two independently-typed
    literals that could drift. No new `security_plan.py` step is
    introduced. That step's `blocked=True`/`implementation_available=False`
    markers are `security_plan.py`'s own discovery-layer advisories
    (informing an operator/CLI what is not yet available) --
    `build_plan_authorization_v2_payload()` does not itself consult either
    field, only `authorization_required`, so referencing this step in an
    authorization request is not a bypass of anything.
  - `requested_plan_digest = compute_plan_digest(generate_security_posture_plan(
    target_capability_posture, target_anchor_assurance))` -- computed
    fresh, every call, via the exact same deterministic, already-existing
    functions `plan_authorization_is_fresh()` itself uses for its own
    independent re-derivation. A future signing-side tool (W3 Slice 5,
    not yet built) must derive this identical `(plan_digest, step_id)`
    pair the same way for its signed `PlanAuthorizationV2` to ever
    satisfy `plan_authorization_v2_authorizes_execution()`'s check
    against what this module independently expects -- it should import
    the three `security_plan.ALIAS_DESCRIPTION_WRITE_*` constants above
    rather than re-typing matching literals a third time.

W3 Slice 4 originally declared these three values as this module's own
private constants -- a genuine design decision flagged for owner review at
the time. A dedicated review
(`reports-ai/handoff/20260815T-w3-slice4-plan-digest-derivation-review.md`)
confirmed the derivation itself is correct and endorsed exactly this
change (verdict B): the values are unchanged, only their ownership moved
to `security_plan.py`, the module that already emits the step they name.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from .models.write_outcome import AliasDescriptionWriteResult
from .security_plan import (
    ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS,
    ALIAS_DESCRIPTION_WRITE_STEP_ID,
    ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
    ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
    generate_security_posture_plan,
)
from .security_plan_digest import compute_plan_digest
from .tier1.alias_description import AliasDescriptionChangeV1
from .tier1.production_runtime import ProductOutcomeState, build_production_runtime

__all__ = ["can_construct_write_runtime", "request_alias_description_change"]

_TARGET_CAPABILITY_POSTURE = ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE
_TARGET_ANCHOR_ASSURANCE = ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE
_REQUESTED_STEP_ID = ALIAS_DESCRIPTION_WRITE_STEP_ID
_REQUIRED_RISK_CLASS = ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS


class _WriteProductState(str, Enum):
    """Private mirror of `production_runtime.ProductOutcomeState`'s five
    values -- exists only so this module's own projection step is total
    and exhaustive-checked by mypy; never imported by anything outside
    this file."""

    REQUESTED = "requested"
    AWAITING_CONFIRMATION = "awaiting_confirmation"
    VERIFIED = "verified"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    REFUSED = "refused"


_PROJECTION: dict[ProductOutcomeState, _WriteProductState] = {
    ProductOutcomeState.REQUESTED: _WriteProductState.REQUESTED,
    ProductOutcomeState.AWAITING_CONFIRMATION: _WriteProductState.AWAITING_CONFIRMATION,
    ProductOutcomeState.VERIFIED: _WriteProductState.VERIFIED,
    ProductOutcomeState.RECONCILIATION_REQUIRED: _WriteProductState.RECONCILIATION_REQUIRED,
    ProductOutcomeState.REFUSED: _WriteProductState.REFUSED,
}


def can_construct_write_runtime() -> bool:
    """Registration-time-only probe for activation-gate condition C.
    Never raises; any failure (unconfigured, partially configured, or a
    genuine construction error) is reported as `False` -- "any single
    condition failing means the tool is simply absent, never degraded"
    (ADR-028). The constructed runtime, if any, is immediately discarded
    -- never cached, never reused, matching `build_production_runtime()`'s
    own fresh-per-call convention."""

    try:
        return build_production_runtime() is not None
    except Exception:
        return False


def _requested_plan_digest() -> str:
    plan = generate_security_posture_plan(_TARGET_CAPABILITY_POSTURE, _TARGET_ANCHOR_ASSURANCE)
    return compute_plan_digest(plan)


def request_alias_description_change(*, alias_name: str, description: str) -> AliasDescriptionWriteResult:
    """The sole entry point the MCP tool handler calls. Builds a fresh
    production runtime; if it cannot be constructed (unconfigured or
    misconfigured), returns `refused` -- the same uniform, no-detail
    outcome `request_alias_description_change()` itself already returns
    for every other fail-closed case, so a caller cannot distinguish
    "not configured" from any other refusal."""

    runtime = build_production_runtime()
    if runtime is None:
        return AliasDescriptionWriteResult(state=_WriteProductState.REFUSED.value)

    request = AliasDescriptionChangeV1(alias_name=alias_name, description=description)
    outcome = runtime.request_alias_description_change(
        request,
        requested_plan_digest=_requested_plan_digest(),
        requested_step_id=_REQUESTED_STEP_ID,
        required_risk_class=_REQUIRED_RISK_CLASS,
        target_capability_posture=_TARGET_CAPABILITY_POSTURE,
        target_anchor_assurance=_TARGET_ANCHOR_ASSURANCE,
        now=datetime.now(timezone.utc),
    )
    return AliasDescriptionWriteResult(state=_PROJECTION[outcome.state].value)
