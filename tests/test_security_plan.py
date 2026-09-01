"""Regression tests for `pfsense_mcp.security_plan` -- the
`DISCOVER -> SELECT TARGET -> EVALUATE VALIDITY -> ASSESS PREREQUISITES
-> GENERATE PLAN` slice, stopping before `PROVISIONING`. Reuses
`tests.test_security_discovery`'s fixtures (temp store + key material +
fake witness anchor) rather than duplicating them, since this module's
only source of live evidence is `discover_security_posture()` itself.
"""

from __future__ import annotations

import sqlite3

import pytest

import pfsense_mcp.security_plan as security_plan
from pfsense_mcp.security_discovery import (
    AnchorAssurance,
    AnchorAssuranceDiscovery,
    AnchorEvidenceState,
    CapabilityPosture,
    CapabilityPostureDiscovery,
    SecurityPostureDiscovery,
)
from pfsense_mcp.security_plan import (
    AuthorizationLevel,
    AxisTransitionKind,
    MutationClass,
    PlanOverallStatus,
    TargetValidity,
    generate_security_posture_plan,
)
from tests.test_security_discovery import (
    _WITNESS_ENV,
    _FakeAnchor,
    _patch_witness_anchor,
    _provisioned_store_env,
    _store_env,
)

_ALL_CAPABILITY_POSTURES = tuple(CapabilityPosture)
_ALL_TARGET_ANCHOR_ASSURANCES = tuple(m for m in AnchorAssurance if m is not AnchorAssurance.UNKNOWN)


def _synthetic_discovery(
    *,
    capability_value: CapabilityPosture,
    anchor_value: AnchorAssurance,
    evidence_state: AnchorEvidenceState = AnchorEvidenceState.PROVISIONED_VERIFIED,
) -> SecurityPostureDiscovery:
    """A hand-built `SecurityPostureDiscovery` for scenarios real
    discovery can never actually produce in this build --
    `write_protected` capability posture, specifically. This build's own
    `discover_capability_posture()` can only ever resolve `read_only`
    (0 *_WRITE capabilities active, empty WriteEndpoints, always, by the
    same invariant `make quick`/`make validate` themselves assert) --
    the downgrade-path plan logic (ADR-021 question 4) is still real,
    specified behavior this module must get right, so it is exercised
    here via a monkeypatched `discover_security_posture()` rather than
    left untested because this build cannot reach it live."""

    capability = CapabilityPostureDiscovery(
        value=capability_value,
        configured_profile_name="engineer" if capability_value is CapabilityPosture.WRITE_PROTECTED else "auditor",
        configured_profile_valid=True,
        write_capabilities_active=1 if capability_value is CapabilityPosture.WRITE_PROTECTED else 0,
        write_capabilities_total=3,
        allow_list_entries=("synthetic_endpoint",) if capability_value is CapabilityPosture.WRITE_PROTECTED else (),
        evidence=("synthetic test fixture",),
    )
    configured = anchor_value is not AnchorAssurance.NONE
    hardware = anchor_value is AnchorAssurance.HARDWARE_WITNESS
    anchor = AnchorAssuranceDiscovery(
        value=anchor_value,
        evidence_state=evidence_state,
        store_configured=configured,
        store_exists=configured or None,
        seeded=configured or None,
        complete=configured or None,
        handle="0x01500000" if configured else None,
        baseline=2 if configured else None,
        provisioned_at="2026-08-10T00:00:00+00:00" if configured else None,
        witness_configured=hardware,
        witness_reachable=True if hardware else None,
        witness_value=2 if hardware else None,
        witness_matches_baseline=True if hardware else None,
        evidence=("synthetic test fixture",),
    )
    return SecurityPostureDiscovery(capability_posture=capability, anchor_assurance=anchor)


def _patch_current(monkeypatch: pytest.MonkeyPatch, discovery: SecurityPostureDiscovery) -> None:
    monkeypatch.setattr(security_plan, "discover_security_posture", lambda env=None: discovery)


# ---------------------------------------------------------------------------
# 1. Already-satisfied targets
# ---------------------------------------------------------------------------


def test_default_environment_read_only_none_is_already_satisfied(monkeypatch):
    for name in list(__import__("os").environ):
        if name.startswith("PFSENSE_TIER1_") or name == "PFSENSE_PROFILE":
            monkeypatch.delenv(name, raising=False)

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, {})

    assert plan.overall_status is PlanOverallStatus.ALREADY_SATISFIED
    assert plan.safe_to_proceed is True
    assert plan.capability_posture_transition is AxisTransitionKind.NO_CHANGE
    assert plan.anchor_assurance_transition is AxisTransitionKind.NO_CHANGE
    assert {s.mutation_class for s in plan.steps} == {MutationClass.NONE}


def test_read_only_plus_provisioned_hardware_witness_is_already_satisfied(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.overall_status is PlanOverallStatus.ALREADY_SATISFIED
    assert plan.safe_to_proceed is True
    no_change = next(s for s in plan.steps if s.axis == "anchor_assurance")
    assert "clean, verified basis" in no_change.description


# ---------------------------------------------------------------------------
# 2. Hardware witness never implies write_protected
# ---------------------------------------------------------------------------


def test_hardware_witness_does_not_imply_write_protected(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.target_capability_posture is CapabilityPosture.READ_ONLY
    assert plan.capability_posture_transition is AxisTransitionKind.NO_CHANGE
    assert not any(s.axis == "capability_posture" and s.mutation_class != MutationClass.NONE for s in plan.steps)


def test_upgrading_to_write_protected_requires_its_own_explicit_target(monkeypatch, tmp_path):
    """Reaching hardware_witness must never auto-select write_protected --
    it must always require its own separate --capability-posture target."""

    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.capability_posture_transition is AxisTransitionKind.UPGRADE
    capability_steps = [s for s in plan.steps if s.axis == "capability_posture"]
    assert len(capability_steps) == 3
    assert all(s.authorization_required is not AuthorizationLevel.NONE_REQUIRED for s in capability_steps)


# ---------------------------------------------------------------------------
# 3. Validity constraint rejection
# ---------------------------------------------------------------------------


def test_write_protected_plus_none_is_rejected_as_invalid(monkeypatch, tmp_path):
    env = _store_env(tmp_path)

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.NONE, env)

    assert plan.target_validity is TargetValidity.INVALID_COMBINATION
    assert plan.overall_status is PlanOverallStatus.BLOCKED_INVALID_TARGET
    assert plan.safe_to_proceed is False
    assert plan.steps == ()
    assert plan.validity_evidence
    assert plan.blocking_findings == plan.validity_evidence


def test_write_protected_plus_none_is_rejected_even_when_currently_write_protected(monkeypatch):
    """The validity constraint applies to the *target*, regardless of
    current state -- even a (synthetic) currently-write_protected state
    cannot select none as its anchor-assurance target."""

    _patch_current(
        monkeypatch,
        _synthetic_discovery(
            capability_value=CapabilityPosture.WRITE_PROTECTED, anchor_value=AnchorAssurance.HARDWARE_WITNESS
        ),
    )

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.NONE)

    assert plan.target_validity is TargetValidity.INVALID_COMBINATION
    assert plan.steps == ()


def test_unknown_anchor_assurance_is_rejected_as_a_target():
    with pytest.raises(ValueError, match="not a valid plan target"):
        generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.UNKNOWN, {})


def test_raw_string_targets_do_not_bypass_the_validity_constraint(monkeypatch, tmp_path):
    """Adversarial-review regression: CapabilityPosture/AnchorAssurance
    are (str, Enum) hybrids, so a caller passing a plain, value-equal
    string instead of the actual enum member (e.g. from a future,
    less-careful caller that skips the CLI's own explicit enum
    construction) must not silently bypass ADR-021's validity
    constraint via an `is`-vs-`==` mismatch."""

    env = _store_env(tmp_path)

    plan = generate_security_posture_plan("write_protected", "none", env)  # type: ignore[arg-type]

    assert plan.target_validity is TargetValidity.INVALID_COMBINATION
    assert plan.overall_status is PlanOverallStatus.BLOCKED_INVALID_TARGET
    assert plan.steps == ()


def test_raw_string_targets_are_coerced_to_the_canonical_enum_member(tmp_path):
    env = _store_env(tmp_path)

    plan = generate_security_posture_plan("read_only", "none", env)  # type: ignore[arg-type]

    assert plan.target_capability_posture is CapabilityPosture.READ_ONLY
    assert plan.target_anchor_assurance is AnchorAssurance.NONE


# ---------------------------------------------------------------------------
# 4. Valid-but-not-implemented (software backend) distinguished from invalid
# ---------------------------------------------------------------------------


def test_write_protected_plus_software_is_valid_but_not_implemented(monkeypatch, tmp_path):
    env = _store_env(tmp_path)

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.SOFTWARE, env)

    assert plan.target_validity is TargetValidity.VALID_NOT_IMPLEMENTED
    assert plan.overall_status is PlanOverallStatus.BLOCKED_NOT_IMPLEMENTED
    assert plan.safe_to_proceed is False
    # Distinguished from INVALID: steps ARE still generated (honest disclosure of what
    # would be needed), unlike the invalid-combination case, which generates none.
    assert plan.steps != ()
    anchor_step = next(s for s in plan.steps if s.axis == "anchor_assurance")
    assert anchor_step.implementation_available is False
    assert anchor_step.mutation_class is MutationClass.ANCHOR_PROVISIONING


def test_read_only_plus_software_is_also_valid_but_not_implemented(monkeypatch, tmp_path):
    env = _store_env(tmp_path)

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.SOFTWARE, env)

    assert plan.target_validity is TargetValidity.VALID_NOT_IMPLEMENTED
    assert plan.overall_status is PlanOverallStatus.BLOCKED_NOT_IMPLEMENTED


# ---------------------------------------------------------------------------
# 5. Ordering: anchor axis before capability-posture axis on upgrade
# ---------------------------------------------------------------------------


def test_none_to_write_protected_hardware_witness_orders_anchor_before_capability(monkeypatch, tmp_path):
    env = _store_env(tmp_path)  # configured, but never provisioned -> anchor assurance = none

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.overall_status is PlanOverallStatus.PLAN_GENERATED
    orders_by_axis = [(s.axis, s.order) for s in plan.steps]
    anchor_orders = [o for axis, o in orders_by_axis if axis == "anchor_assurance"]
    capability_orders = [o for axis, o in orders_by_axis if axis == "capability_posture"]
    assert max(anchor_orders) < min(capability_orders)
    # Every capability-posture step must be blocked pending the anchor axis.
    capability_steps = [s for s in plan.steps if s.axis == "capability_posture"]
    assert all(s.blocked for s in capability_steps)
    assert all(s.prerequisite_satisfied is False for s in capability_steps)
    assert all("anchor" in (s.blocked_reason or "").lower() for s in capability_steps)
    # Steps are a contiguous, gapless, 1-based ordering.
    assert sorted(s.order for s in plan.steps) == list(range(1, len(plan.steps) + 1))


def test_write_tool_activation_step_is_always_blocked_pending_its_own_decision(monkeypatch, tmp_path):
    """Even when the anchor axis is already fully satisfied, the final
    WRITE-activation step must always remain `blocked=True` -- it names a
    recurring, per-operation authorization decision (a signed
    PlanAuthorizationV2) this read-only planning module never performs
    itself, never a one-time deployment gap. W3 Slice 5B correction: the
    step's `implementation_available` is now `True` (the WRITE tool
    implementation has existed since W3 Slice 4) and its `blocked_reason`
    no longer claims otherwise -- the prior text describing
    `tools/write/` as "a deliberately empty placeholder" became false the
    moment Slice 4 shipped `set_firewall_alias_description_v1`."""

    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    activation_step = next(s for s in plan.steps if s.step_id == "capability_posture.milestone_9_activation")
    assert activation_step.implementation_available is True
    assert activation_step.blocked is True
    assert activation_step.prerequisite_satisfied is True
    assert "tools/write/" not in activation_step.blocked_reason
    assert "per-operation" in activation_step.blocked_reason
    # But the earlier, mechanically-real config steps are NOT blocked by this --
    # the anchor is already satisfied, so only the final activation step is
    # (permanently, by design) gated behind its own separate decision.
    earlier_steps = [
        s
        for s in plan.steps
        if s.step_id != "capability_posture.milestone_9_activation" and s.axis == "capability_posture"
    ]
    assert all(not s.blocked for s in earlier_steps)
    assert all(s.implementation_available for s in earlier_steps)


# ---------------------------------------------------------------------------
# 5b. W3 Slice 5B regression: write_protected + NO_CHANGE must still expose
# the milestone-9 activation step, never silently drop it
# ---------------------------------------------------------------------------


def test_write_protected_no_change_still_requires_milestone_9_activation_REGRESSION(monkeypatch, tmp_path):
    """The exact defect W3 Slice 5 found and reproduced: when the
    deployment's OWN capability posture already equals the WRITE_PROTECTED
    target (e.g. `PFSENSE_PROFILE=write_protected` -- precisely the
    configuration required for the WRITE MCP tool to be reachable at
    all), `generate_security_posture_plan()` must still emit the
    `capability_posture.milestone_9_activation` step -- never silently
    collapse the capability_posture axis to a bare `no_change` step that
    omits it. Before the fix, this exact scenario produced a plan with
    `capability_posture.no_change` and NOTHING else on that axis --
    making it structurally impossible for an off-host signer to ever
    bind the step production's own freshness check requires."""

    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.capability_posture_transition is AxisTransitionKind.NO_CHANGE
    step_ids = {s.step_id for s in plan.steps}
    assert "capability_posture.no_change" in step_ids
    assert "capability_posture.milestone_9_activation" in step_ids  # the regression
    activation_step = next(s for s in plan.steps if s.step_id == "capability_posture.milestone_9_activation")
    assert activation_step.axis == "capability_posture"
    assert activation_step.mutation_class is MutationClass.ACTIVATION
    assert activation_step.authorization_required is AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION
    assert activation_step.blocked is True
    assert activation_step.prerequisite_satisfied is True  # anchor is ready in this scenario


def test_read_only_target_no_change_never_gains_the_activation_step(monkeypatch, tmp_path):
    """Confirms the fix is scoped exactly to `target is WRITE_PROTECTED`
    -- READ-only/default behavior must not be accidentally broadened.
    A READ_ONLY target, even when current posture is already read_only
    (the default, unconfigured case), must never emit
    `capability_posture.milestone_9_activation` -- that step's very
    existence would incorrectly imply a WRITE-activation decision is
    relevant to a READ-only target."""

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, {})

    assert plan.capability_posture_transition is AxisTransitionKind.NO_CHANGE
    step_ids = {s.step_id for s in plan.steps}
    assert step_ids == {"anchor_assurance.no_change", "capability_posture.no_change"}
    assert "capability_posture.milestone_9_activation" not in step_ids


def test_downgrade_transition_never_gains_the_activation_step(monkeypatch, tmp_path):
    """The fix is scoped to the NO_CHANGE branch only -- DOWNGRADE
    (write_protected -> read_only) must remain exactly as before, never
    gaining an activation step of its own (there is nothing to
    "activate" when moving away from write_protected)."""

    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.capability_posture_transition is AxisTransitionKind.DOWNGRADE
    step_ids = {s.step_id for s in plan.steps}
    assert "capability_posture.milestone_9_activation" not in step_ids
    assert "capability_posture.deactivate_write_protection" in step_ids


def test_production_and_signer_processes_agree_on_the_activation_plan_digest(monkeypatch, tmp_path):
    """Simulates two independent processes (production's own
    `tier1_write_bridge.py` at request time, and an off-host signer at
    signing time) each independently calling `generate_security_posture_plan()`
    against the SAME live evidence -- both must derive the identical
    plan, and therefore the identical digest, with `PFSENSE_PROFILE=
    write_protected` active in both (the actual live-deployment
    configuration this fix targets)."""

    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    production_plan = generate_security_posture_plan(
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
        env,
    )
    signer_plan = generate_security_posture_plan(
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
        env,
    )

    from pfsense_mcp.security_plan_digest import compute_plan_digest

    assert compute_plan_digest(production_plan) == compute_plan_digest(signer_plan)
    assert security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID in {s.step_id for s in production_plan.steps}


def test_changed_witness_evidence_changes_the_digest_even_when_no_change_transition(monkeypatch, tmp_path):
    """Freshness must not be weakened by this fix: even in the newly-fixed
    NO_CHANGE+write_protected scenario, a change in the live witness
    evidence (e.g. the anchor value drifting from what was persisted)
    still changes the plan digest -- the exact mechanism
    `plan_authorization_is_fresh()` relies on to invalidate a stale
    authorization when the security posture changes between signing and
    consumption."""

    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        **_WITNESS_ENV,
        "PFSENSE_PROFILE": "write_protected",
    }
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))
    matching_plan = generate_security_posture_plan(
        CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env
    )

    _patch_witness_anchor(monkeypatch, _FakeAnchor(7))  # drifted from the persisted baseline (2)
    mismatched_plan = generate_security_posture_plan(
        CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env
    )

    from pfsense_mcp.security_plan_digest import compute_plan_digest

    assert compute_plan_digest(matching_plan) != compute_plan_digest(mismatched_plan)


def test_alias_description_write_constants_are_the_single_source_of_the_activation_step(monkeypatch, tmp_path):
    """`ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE`/
    `ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE`/
    `ALIAS_DESCRIPTION_WRITE_STEP_ID` are public, security_plan-owned
    constants (pre-Slice-5 duplication-removal refactor); the emitted
    `capability_posture` activation step's `step_id` is literally the same
    object/value as `ALIAS_DESCRIPTION_WRITE_STEP_ID`, never a second,
    independently-typed copy of the string. ADR-036 W0:
    `ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS` must likewise match that
    same step's own `authorization_required` exactly -- if a future edit
    changes `_milestone_9_activation_step()`'s literal without updating
    the constant, this assertion (not just the docstring) catches the
    drift."""

    assert security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE is CapabilityPosture.WRITE_PROTECTED
    assert security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE is AnchorAssurance.HARDWARE_WITNESS
    assert security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID == "capability_posture.milestone_9_activation"
    assert (
        security_plan.ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS
        is security_plan.AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION
    )

    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))
    plan = generate_security_posture_plan(
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
        security_plan.ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
        env,
    )
    activation_step = next(s for s in plan.steps if s.step_id == security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID)
    assert activation_step.step_id == security_plan.ALIAS_DESCRIPTION_WRITE_STEP_ID
    assert activation_step.authorization_required is security_plan.ALIAS_DESCRIPTION_WRITE_REQUIRED_RISK_CLASS


# ---------------------------------------------------------------------------
# 6. Downgrade: DEACTIVATE, never DEPROVISION; retain-not-delete
# ---------------------------------------------------------------------------


def test_hardware_witness_to_none_downgrade_is_deactivate_not_deprovision(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)

    assert plan.anchor_assurance_transition is AxisTransitionKind.DOWNGRADE
    step = next(s for s in plan.steps if s.axis == "anchor_assurance")
    assert step.mutation_class is MutationClass.DEACTIVATION
    assert step.mutation_class is not MutationClass.DESTRUCTIVE_DEPROVISIONING
    assert step.reversible is True
    assert "DEPROVISION" in step.description
    assert "not included in this plan" in step.description
    assert "TPM NV" in step.description


def test_joint_downgrade_orders_capability_posture_before_anchor_assurance(monkeypatch):
    """Downgrading both axes at once must deactivate WRITE first, never
    leaving the disallowed write_protected + none combination reachable
    even momentarily (ADR-021 question 4)."""

    _patch_current(
        monkeypatch,
        _synthetic_discovery(
            capability_value=CapabilityPosture.WRITE_PROTECTED, anchor_value=AnchorAssurance.HARDWARE_WITNESS
        ),
    )

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE)

    assert plan.capability_posture_transition is AxisTransitionKind.DOWNGRADE
    assert plan.anchor_assurance_transition is AxisTransitionKind.DOWNGRADE
    capability_orders = [s.order for s in plan.steps if s.axis == "capability_posture"]
    anchor_orders = [s.order for s in plan.steps if s.axis == "anchor_assurance"]
    assert max(capability_orders) < min(anchor_orders)


def test_capability_posture_downgrade_does_not_touch_anchor_assurance_steps(monkeypatch):
    _patch_current(
        monkeypatch,
        _synthetic_discovery(
            capability_value=CapabilityPosture.WRITE_PROTECTED, anchor_value=AnchorAssurance.HARDWARE_WITNESS
        ),
    )

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS)

    assert plan.anchor_assurance_transition is AxisTransitionKind.NO_CHANGE
    anchor_step = next(s for s in plan.steps if s.axis == "anchor_assurance")
    assert anchor_step.mutation_class is MutationClass.NONE
    capability_step = next(s for s in plan.steps if s.axis == "capability_posture")
    assert capability_step.mutation_class is MutationClass.DEACTIVATION
    assert "not touch the anchor-assurance axis" in capability_step.description


# ---------------------------------------------------------------------------
# 7. Configured-but-unreachable is distinguished from verified
# ---------------------------------------------------------------------------


def test_unreachable_witness_target_matches_but_is_not_verified(tmp_path):
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": "https://127.0.0.1:1",
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": str(tmp_path / "does-not-exist-client.crt"),
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": str(tmp_path / "does-not-exist-client.key"),
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
    }

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    # Nominally matches (store evidence alone justifies hardware_witness) --
    # transition-wise this is still "no_change" -- but the step's own
    # description must flag that it is not a clean/verified basis.
    assert plan.anchor_assurance_transition is AxisTransitionKind.NO_CHANGE
    assert plan.overall_status is PlanOverallStatus.ALREADY_SATISFIED
    assert plan.safe_to_proceed is True
    step = next(s for s in plan.steps if s.axis == "anchor_assurance")
    assert "not a fully verified/clean state" in step.description
    assert "nominally reached, not confirmed" in step.description


# ---------------------------------------------------------------------------
# 8. Store/witness mismatch blocks progression -- not an ordinary "proceed"
# ---------------------------------------------------------------------------


def test_mismatch_blocks_even_an_already_satisfied_looking_target(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(7))  # deliberately mismatched

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.overall_status is PlanOverallStatus.BLOCKED_ANOMALY_DETECTED
    assert plan.overall_status is not PlanOverallStatus.ALREADY_SATISFIED
    assert plan.safe_to_proceed is False
    assert any("mismatch" in f.lower() for f in plan.blocking_findings)


def test_mismatch_forces_every_mutating_step_blocked(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(7))  # deliberately mismatched

    plan = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.overall_status is PlanOverallStatus.BLOCKED_ANOMALY_DETECTED
    mutating_steps = [s for s in plan.steps if s.mutation_class is not MutationClass.NONE]
    assert mutating_steps  # sanity: there are real mutating steps in this scenario
    assert all(s.blocked for s in mutating_steps)
    assert all("mismatch" in (s.blocked_reason or "").lower() for s in mutating_steps)


# ---------------------------------------------------------------------------
# 8b. Indeterminate current state (unavailable evidence) must never be
#     treated as a clean-slate success -- adversarial-review regression.
# ---------------------------------------------------------------------------


def test_malformed_store_current_state_blocks_the_whole_plan(tmp_path):
    """A foreign/malformed SQLite file already at the configured store
    path resolves discovery's own current anchor-assurance value to
    UNKNOWN (evidence_state=store_error) -- the plan must not silently
    treat this as 'nothing provisioned yet, safe to provision', which
    would paper over a real anomaly at that exact path."""

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    key_file = tmp_path / "key" / "integrity.json"
    key_file.parent.mkdir(mode=0o700)
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    assert plan.overall_status is security_plan.PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE
    assert plan.safe_to_proceed is False
    assert plan.steps == ()
    assert any("indeterminate" in f.lower() for f in plan.blocking_findings)


def test_indeterminate_current_state_blocks_every_target_combination(tmp_path):
    """Not specific to one target -- an indeterminate current anchor
    state must block regardless of what was requested, including a
    target that (superficially) looks like a no-op."""

    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    key_file = tmp_path / "key" / "integrity.json"
    key_file.parent.mkdir(mode=0o700)
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    for target_cap in _ALL_CAPABILITY_POSTURES:
        for target_anchor in _ALL_TARGET_ANCHOR_ASSURANCES:
            plan = generate_security_posture_plan(target_cap, target_anchor, env)
            if plan.target_validity is TargetValidity.INVALID_COMBINATION:
                continue  # a different, already-covered blocking reason takes precedence
            assert plan.overall_status is security_plan.PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE
            assert plan.safe_to_proceed is False
            assert plan.steps == ()


# ---------------------------------------------------------------------------
# 9. A generated plan is never authorization
# ---------------------------------------------------------------------------


def test_plan_always_states_it_is_not_authorization(monkeypatch, tmp_path):
    env = _store_env(tmp_path)
    for target_cap in _ALL_CAPABILITY_POSTURES:
        for target_anchor in _ALL_TARGET_ANCHOR_ASSURANCES:
            plan = generate_security_posture_plan(target_cap, target_anchor, env)
            assert any("NOT authorization" in note for note in plan.notes)


def test_security_posture_plan_docstring_clarifies_safe_to_proceed_meaning():
    """ADR-022 owner review (2026-08-11): safe_to_proceed's published
    behavior/schema is unchanged; only its documentation was clarified.
    Pins the exact clarifying language (whitespace-normalized, since the
    docstring wraps across source lines) so a future edit cannot
    silently drop it."""

    doc = security_plan.SecurityPosturePlan.__doc__
    assert doc is not None
    normalized = " ".join(doc.split())
    assert "means **only**" in normalized
    assert "not** mean authorized, approved, executable" in normalized
    assert "never grants anything" in normalized


# ---------------------------------------------------------------------------
# 10. Mutation-free hard boundary
# ---------------------------------------------------------------------------


def test_generate_plan_calls_discovery_exactly_once(monkeypatch, tmp_path):
    env = _store_env(tmp_path)
    call_count = {"n": 0}
    real = security_plan.discover_security_posture

    def _counting(e=None):
        call_count["n"] += 1
        return real(e)

    monkeypatch.setattr(security_plan, "discover_security_posture", _counting)

    generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.NONE, env)

    assert call_count["n"] == 1


def test_plan_generation_performs_no_io_of_its_own(monkeypatch):
    """After the one discover_security_posture() call (replaced here with
    a synthetic, zero-I/O discovery), plan generation must be pure
    computation -- no sqlite3 connection, no file open."""

    _patch_current(
        monkeypatch,
        _synthetic_discovery(capability_value=CapabilityPosture.READ_ONLY, anchor_value=AnchorAssurance.NONE),
    )

    def _boom_sqlite(*args, **kwargs):
        raise AssertionError("security_plan must perform no SQLite I/O of its own.")

    def _boom_open(*args, **kwargs):
        raise AssertionError("security_plan must perform no file I/O of its own.")

    monkeypatch.setattr(sqlite3, "connect", _boom_sqlite)
    monkeypatch.setattr("builtins.open", _boom_open)

    # Must complete normally for every target combination -- if plan
    # generation ever touched sqlite3.connect or open(), _boom_* above
    # would raise and fail this test.
    for target_cap in _ALL_CAPABILITY_POSTURES:
        for target_anchor in _ALL_TARGET_ANCHOR_ASSURANCES:
            generate_security_posture_plan(target_cap, target_anchor)


def test_no_step_is_ever_destructive_deprovisioning(monkeypatch, tmp_path):
    """DESTRUCTIVE_DEPROVISIONING/SEPARATE_DEPROVISION_AUTHORIZATION are
    declared for future schema forward-compatibility only -- this slice
    must never actually emit either, across every reachable target
    combination and a representative sweep of current states."""

    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    scenarios = [
        _store_env(tmp_path / "a"),
        _provisioned_store_env(tmp_path / "b", value=2, handle="0x01500000"),
    ]
    for env in scenarios:
        for target_cap in _ALL_CAPABILITY_POSTURES:
            for target_anchor in _ALL_TARGET_ANCHOR_ASSURANCES:
                plan = generate_security_posture_plan(target_cap, target_anchor, env)
                for step in plan.steps:
                    assert step.mutation_class is not MutationClass.DESTRUCTIVE_DEPROVISIONING
                    assert step.authorization_required is not AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION

    for capability_value in CapabilityPosture:
        for anchor_value in (AnchorAssurance.NONE, AnchorAssurance.HARDWARE_WITNESS):
            _patch_current(
                monkeypatch,
                _synthetic_discovery(capability_value=capability_value, anchor_value=anchor_value),
            )
            for target_cap in _ALL_CAPABILITY_POSTURES:
                for target_anchor in _ALL_TARGET_ANCHOR_ASSURANCES:
                    try:
                        plan = generate_security_posture_plan(target_cap, target_anchor)
                    except ValueError:
                        continue
                    for step in plan.steps:
                        assert step.mutation_class is not MutationClass.DESTRUCTIVE_DEPROVISIONING
                        assert step.authorization_required is not AuthorizationLevel.SEPARATE_DEPROVISION_AUTHORIZATION


# ---------------------------------------------------------------------------
# 12. No secret/path/URL leakage in this module's own new fields (steps,
#     blocking_findings, notes, validity_evidence). `current` is
#     security_discovery.py's own already-audited evidence and is not
#     re-checked here.
# ---------------------------------------------------------------------------


def _plan_own_text_blob(plan) -> str:
    parts = list(plan.validity_evidence) + list(plan.blocking_findings) + list(plan.notes)
    for step in plan.steps:
        parts.append(step.action)
        parts.append(step.description)
        if step.blocked_reason:
            parts.append(step.blocked_reason)
    return " ".join(parts)


def test_unreachable_witness_paths_never_leak_into_plan_fields(tmp_path):
    bad_cert = str(tmp_path / "does-not-exist-client.crt")
    bad_key = str(tmp_path / "does-not-exist-client.key")
    bad_url = "https://127.0.0.1:1"
    env = {
        **_provisioned_store_env(tmp_path, value=2, handle="0x01500000"),
        "PFSENSE_TIER1_WITNESS_BASE_URL": bad_url,
        "PFSENSE_TIER1_WITNESS_CLIENT_CERT_FILE": bad_cert,
        "PFSENSE_TIER1_WITNESS_CLIENT_KEY_FILE": bad_key,
        "PFSENSE_TIER1_WITNESS_SERVER_CA_FILE": str(tmp_path / "does-not-exist-server.crt"),
    }

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    blob = _plan_own_text_blob(plan)
    assert bad_cert not in blob
    assert bad_key not in blob
    assert bad_url not in blob
    assert str(tmp_path) not in blob


def test_malformed_store_configured_paths_never_leak_into_plan_fields(tmp_path):
    store_dir = tmp_path / "store"
    store_dir.mkdir(mode=0o700)
    malformed = store_dir / "anchor.sqlite3"
    malformed.write_bytes(b"not a sqlite database")
    key_file = tmp_path / "key" / "integrity.json"
    key_file.parent.mkdir(mode=0o700)
    key_file.write_text('{"key_id": "x", "epoch": 0, "material_hex": "' + "ab" * 32 + '"}')
    env = {"PFSENSE_TIER1_STORE_PATH": str(malformed), "PFSENSE_TIER1_STORE_KEY_FILE": str(key_file)}

    plan = generate_security_posture_plan(CapabilityPosture.READ_ONLY, AnchorAssurance.HARDWARE_WITNESS, env)

    blob = _plan_own_text_blob(plan)
    assert str(malformed) not in blob
    assert str(key_file) not in blob


# ---------------------------------------------------------------------------
# 11. Determinism
# ---------------------------------------------------------------------------


def test_plan_is_deterministic_for_identical_environment(monkeypatch, tmp_path):
    env = {**_provisioned_store_env(tmp_path, value=2, handle="0x01500000"), **_WITNESS_ENV}
    _patch_witness_anchor(monkeypatch, _FakeAnchor(2))

    first = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)
    second = generate_security_posture_plan(CapabilityPosture.WRITE_PROTECTED, AnchorAssurance.HARDWARE_WITNESS, env)

    assert first == second
