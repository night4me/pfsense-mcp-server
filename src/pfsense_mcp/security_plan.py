"""ADR-021 posture-selection planning: `DISCOVER -> SELECT TARGET ->
EVALUATE VALIDITY -> ASSESS PREREQUISITES -> GENERATE PLAN`, and STOP
before `PROVISIONING`.

Bridges "what security state do I currently have?"
(`security_discovery.discover_security_posture()`, ADR-021 Phase B) to
"what would need to happen to reach a selected target state?" --
entirely observational/planning. **This module never provisions,
activates, deactivates, repairs, mutates, or reconfigures anything.**

Deliberately does NOT import `pfsense_mcp.tier1` at all -- unlike
`security_discovery.py` (the first and only module that needs to,
because it is the one place that actually reads the Tier 1 store/TPM
witness), this module's only source of live evidence is
`discover_security_posture()` itself. Everything past that call is pure,
deterministic computation over already-collected evidence: comparing it
against an explicit target, checking `ADR-021`'s one validity
constraint, and describing (never performing) an ordered sequence of
future actions. No new `pfsense_mcp.tier1` isolation exemption is
needed or introduced by this file -- `tests/tier1/test_isolation.py`'s
exemption list stays exactly `{"tier1_anchor_check.py",
"security_discovery.py"}`.

**Critical invariant, encoded here and nowhere silently assumed
elsewhere: a generated `SecurityPosturePlan` is never authorization to
execute it.** Selecting a target is intent, not execution authorization.
Plan generation is analysis, not execution authorization. Every
mutating step this module ever describes remains gated behind its own
separate, future, explicitly-scoped authorization -- exactly as
`ADR-021`'s "User consent boundaries" and "Safety invariants" already
require. This module performs none of them; see `PlanStep.blocked`/
`authorization_required` for how each future step's own gate is
represented, and `SecurityPosturePlan.notes` for where this invariant
is restated in every plan's own output.

No SQL, no TPM command, no `WriteEndpoints` mutation, no environment or
configuration write, no HTTP `advance()` call, no `RecoveryContract`/
`MutationExecutor`/`WriteApiClient` construction -- this module contains
no I/O of its own beyond the one `discover_security_posture()` call it
delegates to, and everything after that is dataclass construction over
already-collected, already-read-only evidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .security_discovery import (
    AnchorAssurance,
    AnchorEvidenceState,
    CapabilityPosture,
    SecurityPostureDiscovery,
    discover_security_posture,
)

_PLAN_IS_NOT_AUTHORIZATION_NOTE = (
    "This plan is analysis only. It is NOT authorization to execute any step listed below. "
    "Selecting a target is intent, not execution authorization. Every mutating step remains "
    "gated behind its own separate, future, explicitly-scoped authorization (ADR-021's User "
    "consent boundaries and Safety invariants) -- none of them were performed to produce this "
    "plan, and none are performed by generating or reading it."
)

_NO_WRITE_TOOL_IMPLEMENTATION_NOTE = (
    "src/pfsense_mcp/tools/write/ is a deliberately empty placeholder and "
    "SUPPORTED_CAPABILITIES_THIS_BUILD excludes every *_WRITE Capability in this build -- no WRITE "
    "tool implementation exists to register, regardless of configuration or authorization state."
)

#: The single first-WRITE product surface's (`set_firewall_alias_description_v1`,
#: W3 Slice 4) plan-target identity -- the exact `(target_capability_posture,
#: target_anchor_assurance)` pair that step `ALIAS_DESCRIPTION_WRITE_STEP_ID`
#: below is generated under. Public and importable so that every consumer
#: needing this operation's plan/step identity (currently
#: `tier1_write_bridge.py`; a future, separately-authorized Slice 5 signing
#: tool will need the identical values) shares one definition instead of
#: independently re-typing matching literals. Values are unchanged from what
#: W3 Slice 4 already used -- this is a duplication-removal refactor only, not
#: a new derivation and not a new target.
ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE = CapabilityPosture.WRITE_PROTECTED
ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE = AnchorAssurance.HARDWARE_WITNESS

#: The one existing plan step (emitted below by `_capability_posture_steps()`)
#: whose semantics match the first-WRITE product surface: "obtain the
#: Milestone-9-class WRITE activation decision, then register the
#: corresponding WRITE tool(s)". Not a new step and not alias-description-
#: specific on its own -- per-operation specificity is carried by the
#: separate `execution_intent_digest` binding (ADR-025 B2), not by this
#: step_id.
ALIAS_DESCRIPTION_WRITE_STEP_ID = "capability_posture.milestone_9_activation"


class TargetValidity(str, Enum):
    """Whether a requested (capability_posture, anchor_assurance) target
    is a legal point in ADR-021's accepted two-axis model, and if so,
    whether this repository can currently act on it. Deliberately three
    values, not two -- collapsing `VALID_NOT_IMPLEMENTED` into either
    `VALID` or `INVALID_COMBINATION` would erase exactly the distinction
    ADR-021 itself draws: "valid design state" is not the same claim as
    "currently implementable target"."""

    VALID = "valid"
    INVALID_COMBINATION = "invalid_combination"
    VALID_NOT_IMPLEMENTED = "valid_not_implemented"


class AxisTransitionKind(str, Enum):
    """What moving from an axis's current value to its target value
    would require. `LATERAL` covers a same-axis change between two
    non-`none`/non-`read_only` values that is neither a strict upgrade
    nor a strict downgrade (e.g. `hardware_witness` -> `software`) --
    not reachable through real discovery today (Phase B never resolves
    `AnchorAssurance.SOFTWARE` as a *current* value), but a real,
    explicitly requestable *target* transition this module must still
    describe correctly, not misclassify as an upgrade or downgrade."""

    NO_CHANGE = "no_change"
    UPGRADE = "upgrade"
    DOWNGRADE = "downgrade"
    LATERAL = "lateral"


class MutationClass(str, Enum):
    """What *kind* of future action a step would be, if and when
    separately authorized and executed. `DESTRUCTIVE_DEPROVISIONING` is
    declared for schema forward-compatibility with a possible future,
    separately-authorized DEPROVISION-planning slice -- **this module
    never emits a step with this class**; see
    `tests/test_security_plan.py::test_no_step_is_ever_destructive_deprovisioning`."""

    NONE = "none"
    CONFIGURATION = "configuration"
    ANCHOR_PROVISIONING = "anchor_provisioning"
    SERVICE_DEPLOYMENT = "service_deployment"
    ACTIVATION = "activation"
    DEACTIVATION = "deactivation"
    DESTRUCTIVE_DEPROVISIONING = "destructive_deprovisioning"


class AuthorizationLevel(str, Enum):
    """The future authorization boundary a step would cross -- deliberately
    granular, mirroring ADR-021's "every mutating step, on either axis,
    requires its own explicit, distinct confirmation -- never one blanket
    approval for a whole preset". `SEPARATE_DEPROVISION_AUTHORIZATION` is
    declared for the same forward-compatibility reason as
    `MutationClass.DESTRUCTIVE_DEPROVISIONING` and is, likewise, never
    emitted by this module."""

    NONE_REQUIRED = "none_required"
    CONFIGURATION_CHANGE = "configuration_change"
    INTERACTIVE_HARDWARE_CONFIRMATION = "interactive_hardware_confirmation"
    MILESTONE_9_ACTIVATION_DECISION = "milestone_9_activation_decision"
    SEPARATE_DEPROVISION_AUTHORIZATION = "separate_deprovision_authorization"
    UNDETERMINED_NOT_IMPLEMENTED = "undetermined_not_implemented"


class SecurityImpact(str, Enum):
    NONE = "none"
    INCREASES_ASSURANCE = "increases_assurance"
    DECREASES_ASSURANCE = "decreases_assurance"
    ENABLES_MUTATION_CAPABILITY = "enables_mutation_capability"
    DISABLES_MUTATION_CAPABILITY = "disables_mutation_capability"


class PlanOverallStatus(str, Enum):
    """A single, deterministic top-level summary a caller can branch on
    without parsing `steps` or `notes` -- deliberately distinct from
    `TargetValidity` (which only judges the *target*): this also folds
    in the *current* state's own health (a store/witness mismatch blocks
    progression regardless of how valid the target is)."""

    ALREADY_SATISFIED = "already_satisfied"
    PLAN_GENERATED = "plan_generated"
    BLOCKED_INVALID_TARGET = "blocked_invalid_target"
    BLOCKED_NOT_IMPLEMENTED = "blocked_not_implemented"
    BLOCKED_ANOMALY_DETECTED = "blocked_anomaly_detected"
    BLOCKED_INDETERMINATE_CURRENT_STATE = "blocked_indeterminate_current_state"


@dataclass(frozen=True)
class PlanStep:
    """One prospective future action. Never executed by this module --
    every field describes what the step *would* be, for a human or a
    later, separately-authorized phase to reason about without parsing
    prose. `mutation_class`/`authorization_required` are the two fields
    a future authorization gate would key off of; `blocked`/
    `blocked_reason`/`prerequisite_satisfied` describe *ordering*
    (e.g. "the anchor-assurance axis must reach its target first"), not
    a judgment that the step itself is unsafe."""

    step_id: str
    order: int
    axis: str
    action: str
    description: str
    mutation_class: MutationClass
    authorization_required: AuthorizationLevel
    implementation_available: bool
    reversible: bool | None
    security_impact: SecurityImpact
    prerequisite_satisfied: bool | None
    blocked: bool
    blocked_reason: str | None
    evidence: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class SecurityPosturePlan:
    """The complete output of `generate_security_posture_plan()` --
    never itself authorization; see this module's own docstring and
    every plan's own `notes` field, which restates that explicitly.

    `safe_to_proceed` (ADR-022 "safe_to_proceed clarification", reviewed
    and confirmed correct 2026-08-11) means **only**: the requested
    target is architecturally valid (`target_validity is
    TargetValidity.VALID`) and current evidence shows no detected
    anomaly/indeterminacy that blocks planning (no store/witness
    mismatch, no indeterminate anchor state) -- i.e., it is reasonable
    to continue reviewing/preparing this plan. It does **not** mean
    authorized, approved, executable, that mutation is permitted, that
    operator consent was obtained, that every prerequisite is
    implemented, or that every step is unblocked. `True` is fully
    compatible with individual `steps` still showing `blocked=True`
    (ordinary sequencing, e.g. "the anchor-assurance axis must reach its
    target first") or `implementation_available=False` (e.g. no WRITE
    tool exists yet) -- `safe_to_proceed` judges the *plan*, never any
    individual step's own readiness, and never grants anything."""

    current: SecurityPostureDiscovery
    target_capability_posture: CapabilityPosture
    target_anchor_assurance: AnchorAssurance
    target_validity: TargetValidity
    validity_evidence: tuple[str, ...]
    capability_posture_transition: AxisTransitionKind
    anchor_assurance_transition: AxisTransitionKind
    overall_status: PlanOverallStatus
    safe_to_proceed: bool
    blocking_findings: tuple[str, ...]
    steps: tuple[PlanStep, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)


def _evaluate_target_validity(
    capability_posture: CapabilityPosture, anchor_assurance: AnchorAssurance
) -> tuple[TargetValidity, tuple[str, ...]]:
    if capability_posture is CapabilityPosture.WRITE_PROTECTED and anchor_assurance is AnchorAssurance.NONE:
        return TargetValidity.INVALID_COMBINATION, (
            "write_protected + none violates ADR-021's validity constraint, directly sourced from "
            "ADR-011's own accepted text ('if neither [TPM nor remote witness] is available, mutation "
            "must stay blocked'). This combination can never be a valid target.",
        )
    if anchor_assurance is AnchorAssurance.SOFTWARE:
        return TargetValidity.VALID_NOT_IMPLEMENTED, (
            "anchor_assurance=software is a valid point in the accepted ADR-021 two-axis model, but the "
            "software (remote append-only witness) backend has no implementation anywhere in this "
            "repository today (docs/SECURITY_POSTURE_PROVISIONING.md's Phase G, unimplemented). This is "
            "a valid design state, not a currently implementable target.",
        )
    return TargetValidity.VALID, ()


def _anchor_transition_kind(current: AnchorAssurance, target: AnchorAssurance) -> AxisTransitionKind:
    if current == target:
        return AxisTransitionKind.NO_CHANGE
    if current is AnchorAssurance.NONE:
        return AxisTransitionKind.UPGRADE
    if target is AnchorAssurance.NONE:
        return AxisTransitionKind.DOWNGRADE
    return AxisTransitionKind.LATERAL


def _capability_transition_kind(current: CapabilityPosture, target: CapabilityPosture) -> AxisTransitionKind:
    if current == target:
        return AxisTransitionKind.NO_CHANGE
    if target is CapabilityPosture.WRITE_PROTECTED:
        return AxisTransitionKind.UPGRADE
    return AxisTransitionKind.DOWNGRADE


def _anchor_evidence_is_clean(evidence_state: AnchorEvidenceState, target: AnchorAssurance) -> bool:
    """Whether the *current* anchor-assurance evidence is trustworthy
    enough to treat as satisfying `target` outright -- distinct from
    merely having the same `.value`. A `hardware_witness` value whose
    evidence state is e.g. `provisioned_unreachable` matches the target
    *value* but is not yet a clean basis for downstream steps to
    silently treat as ready."""

    if target is AnchorAssurance.NONE:
        return evidence_state is AnchorEvidenceState.UNCONFIGURED
    return evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED


def _anchor_assurance_steps(
    current: SecurityPostureDiscovery, target: AnchorAssurance, transition: AxisTransitionKind, order_start: int
) -> tuple[tuple[PlanStep, ...], int]:
    current_value = current.anchor_assurance.value
    order = order_start
    steps: list[PlanStep] = []

    if transition is AxisTransitionKind.NO_CHANGE:
        clean = _anchor_evidence_is_clean(current.anchor_assurance.evidence_state, target)
        description = f"Anchor assurance is already at the target value ({target.value})."
        description += (
            " Current evidence is a clean, verified basis for this."
            if clean
            else (
                f" Current evidence state is {current.anchor_assurance.evidence_state.value}, not a fully "
                "verified/clean state -- treat this as the target being nominally reached, not confirmed."
            )
        )
        steps.append(
            PlanStep(
                step_id="anchor_assurance.no_change",
                order=order,
                axis="anchor_assurance",
                action="No change required",
                description=description,
                mutation_class=MutationClass.NONE,
                authorization_required=AuthorizationLevel.NONE_REQUIRED,
                implementation_available=True,
                reversible=None,
                security_impact=SecurityImpact.NONE,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=current.anchor_assurance.evidence,
            )
        )
        return tuple(steps), order + 1

    if transition is AxisTransitionKind.DOWNGRADE:
        implementation_available = current_value is AnchorAssurance.HARDWARE_WITNESS
        description = (
            "Stop and disable the witness daemon (systemctl stop/disable). TPM NV counter value and the "
            "guest-side store's high-water-mark/provisioning record remain untouched -- fully reversible "
            "by re-enabling and restarting later. TPM NV index deletion and guest-side "
            "store/integrity-key deletion (DEPROVISION) are never part of this routine downgrade and are "
            "not included in this plan; they would require their own separate, narrowly-scoped "
            "authorization if ever sought (ADR-021 question 4 -- retain-not-delete default)."
        )
        if not implementation_available:
            description = (
                f"Downgrade {current_value.value} -> none requested, but no deactivation mechanism exists "
                f"for anchor-assurance value {current_value.value!r} in this repository today."
            )
        steps.append(
            PlanStep(
                step_id="anchor_assurance.deactivate_anchor",
                order=order,
                axis="anchor_assurance",
                action="Deactivate anchor (DEACTIVATE, not DEPROVISION)",
                description=description,
                mutation_class=MutationClass.DEACTIVATION,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
                implementation_available=implementation_available,
                reversible=True if implementation_available else None,
                security_impact=SecurityImpact.DECREASES_ASSURANCE,
                prerequisite_satisfied=True,
                blocked=not implementation_available,
                blocked_reason=None if implementation_available else "No implemented deactivation mechanism.",
                evidence=current.anchor_assurance.evidence,
            )
        )
        return tuple(steps), order + 1

    # UPGRADE or LATERAL: provision the target backend. A LATERAL
    # transition first deactivates whatever backend is currently
    # active (if any real, implemented one is), then provisions the
    # target -- described as two steps, never one step that silently
    # does both. Only current_value is AnchorAssurance.HARDWARE_WITNESS
    # ever gets an explicit deactivate step here: AnchorAssurance.SOFTWARE
    # is never resolved as a *current* value by security_discovery.py
    # (grep confirms -- no discovery code path assigns it), so a LATERAL
    # transition away from a "current" software value is unreachable
    # through any real discovery result. This also means the only
    # LATERAL transition reachable in practice is hardware_witness ->
    # software, and target=software is always TargetValidity.VALID_NOT_IMPLEMENTED
    # (blocked, safe_to_proceed=False) regardless -- so the theoretical
    # "momentarily no anchor while still write_protected" hazard a LATERAL
    # deactivate+reprovision sequence could otherwise pose is already
    # covered by that separate block, not coincidentally relied upon here.
    if transition is AxisTransitionKind.LATERAL and current_value is AnchorAssurance.HARDWARE_WITNESS:
        steps.append(
            PlanStep(
                step_id="anchor_assurance.deactivate_current_anchor",
                order=order,
                axis="anchor_assurance",
                action="Deactivate current anchor before switching backend",
                description=(
                    "Stop and disable the current witness daemon before provisioning a different "
                    "anchor-assurance backend. TPM NV counter value and guest-side store/high-water-mark "
                    "remain untouched (DEACTIVATE, not DEPROVISION)."
                ),
                mutation_class=MutationClass.DEACTIVATION,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
                implementation_available=True,
                reversible=True,
                security_impact=SecurityImpact.DECREASES_ASSURANCE,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=current.anchor_assurance.evidence,
            )
        )
        order += 1

    if target is AnchorAssurance.HARDWARE_WITNESS:
        steps.append(
            PlanStep(
                step_id="anchor_assurance.provision_hardware_witness_anchor",
                order=order,
                axis="anchor_assurance",
                action="Provision hardware TPM witness anchor",
                description=(
                    "Generate secret, define NV index, first increment, seed store, mark complete -- the "
                    "already-specified provisioning state machine in "
                    "docs/tier1/specs/anti_rollback_tpm_host_witness.md, reused not reinvented; each step "
                    "individually confirmed, interactive-only (ADR-021: physical TPM state changes are "
                    "never declarative)."
                ),
                mutation_class=MutationClass.ANCHOR_PROVISIONING,
                authorization_required=AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION,
                implementation_available=True,
                reversible=False,
                security_impact=SecurityImpact.INCREASES_ASSURANCE,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=(),
            )
        )
        order += 1
        steps.append(
            PlanStep(
                step_id="anchor_assurance.deploy_witness_daemon",
                order=order,
                axis="anchor_assurance",
                action="Deploy persistent witness daemon",
                description=(
                    "Install and enable the persistent systemd-managed witness daemon "
                    "(witness_daemon/systemd/pfsense-mcp-tpm-witness.service) -- ADR-011's Deployment "
                    "model decision, not a manually-started process."
                ),
                mutation_class=MutationClass.SERVICE_DEPLOYMENT,
                authorization_required=AuthorizationLevel.INTERACTIVE_HARDWARE_CONFIRMATION,
                implementation_available=True,
                reversible=True,
                security_impact=SecurityImpact.INCREASES_ASSURANCE,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=(),
            )
        )
        order += 1
    elif target is AnchorAssurance.SOFTWARE:
        steps.append(
            PlanStep(
                step_id="anchor_assurance.provision_software_witness_anchor",
                order=order,
                axis="anchor_assurance",
                action="Provision software (remote append-only) witness anchor",
                description=(
                    "ADR-011's own accepted 'mandatory fallback' backend for hosts without a TPM has no "
                    "implementation anywhere in this repository today "
                    "(docs/SECURITY_POSTURE_PROVISIONING.md's Phase G, unimplemented). Valid per the "
                    "accepted two-axis model; not currently implementable."
                ),
                mutation_class=MutationClass.ANCHOR_PROVISIONING,
                authorization_required=AuthorizationLevel.UNDETERMINED_NOT_IMPLEMENTED,
                implementation_available=False,
                reversible=None,
                security_impact=SecurityImpact.INCREASES_ASSURANCE,
                prerequisite_satisfied=False,
                blocked=True,
                blocked_reason="The software anchor-assurance backend is not implemented in this repository (Phase G).",
                evidence=(),
            )
        )
        order += 1

    return tuple(steps), order


def _capability_posture_steps(
    current: SecurityPostureDiscovery,
    target: CapabilityPosture,
    transition: AxisTransitionKind,
    anchor_ready_now: bool,
    anchor_target: AnchorAssurance,
    order_start: int,
) -> tuple[tuple[PlanStep, ...], int]:
    order = order_start
    steps: list[PlanStep] = []

    if transition is AxisTransitionKind.NO_CHANGE:
        steps.append(
            PlanStep(
                step_id="capability_posture.no_change",
                order=order,
                axis="capability_posture",
                action="No change required",
                description=f"Capability posture is already at the target value ({target.value}).",
                mutation_class=MutationClass.NONE,
                authorization_required=AuthorizationLevel.NONE_REQUIRED,
                implementation_available=True,
                reversible=None,
                security_impact=SecurityImpact.NONE,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=current.capability_posture.evidence,
            )
        )
        return tuple(steps), order + 1

    if transition is AxisTransitionKind.DOWNGRADE:
        steps.append(
            PlanStep(
                step_id="capability_posture.deactivate_write_protection",
                order=order,
                axis="capability_posture",
                action="Deactivate WRITE (capability posture downgrade)",
                description=(
                    "Revert PFSENSE_PROFILE to auditor and clear WriteEndpoints allow-list entries. Does "
                    "not touch the anchor-assurance axis, including daemon/service state -- a provisioned "
                    "anchor is left exactly as it is (ADR-021: capability-posture downgrade never touches "
                    "anchor state)."
                ),
                mutation_class=MutationClass.DEACTIVATION,
                authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
                implementation_available=True,
                reversible=True,
                security_impact=SecurityImpact.DISABLES_MUTATION_CAPABILITY,
                prerequisite_satisfied=True,
                blocked=False,
                blocked_reason=None,
                evidence=current.capability_posture.evidence,
            )
        )
        return tuple(steps), order + 1

    # UPGRADE (read_only -> write_protected).
    blocked_reason = None
    if not anchor_ready_now:
        blocked_reason = (
            f"Anchor-assurance axis has not yet reached the target ({anchor_target.value}) -- current: "
            f"{current.anchor_assurance.value.value}/{current.anchor_assurance.evidence_state.value}. "
            "Complete the anchor_assurance steps above first."
        )
    steps.append(
        PlanStep(
            step_id="capability_posture.populate_write_endpoints",
            order=order,
            axis="capability_posture",
            action="Populate WriteEndpoints allow-list",
            description=(
                "Populate the WriteEndpoints allow-list per the separately-governed WRITE endpoint risk "
                "process (WRITE_ENDPOINT_RISK_MATRIX.md, ADR-020) -- one shared allow-list across both "
                "write_protected presets (ADR-021 question 3)."
            ),
            mutation_class=MutationClass.CONFIGURATION,
            authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            implementation_available=True,
            reversible=True,
            security_impact=SecurityImpact.ENABLES_MUTATION_CAPABILITY,
            prerequisite_satisfied=anchor_ready_now,
            blocked=not anchor_ready_now,
            blocked_reason=blocked_reason,
            evidence=current.capability_posture.evidence,
        )
    )
    order += 1
    steps.append(
        PlanStep(
            step_id="capability_posture.set_profile_engineer",
            order=order,
            axis="capability_posture",
            action="Set PFSENSE_PROFILE=engineer",
            description="Set the PFSENSE_PROFILE environment variable to engineer (ADR-004).",
            mutation_class=MutationClass.CONFIGURATION,
            authorization_required=AuthorizationLevel.CONFIGURATION_CHANGE,
            implementation_available=True,
            reversible=True,
            security_impact=SecurityImpact.ENABLES_MUTATION_CAPABILITY,
            prerequisite_satisfied=anchor_ready_now,
            blocked=not anchor_ready_now,
            blocked_reason=blocked_reason,
            evidence=(),
        )
    )
    order += 1
    activation_reason_parts = [_NO_WRITE_TOOL_IMPLEMENTATION_NOTE]
    if not anchor_ready_now:
        activation_reason_parts.append(blocked_reason or "")
    steps.append(
        PlanStep(
            step_id=ALIAS_DESCRIPTION_WRITE_STEP_ID,
            order=order,
            axis="capability_posture",
            action="Obtain Milestone-9-class WRITE activation decision",
            description=(
                "Obtain the Milestone-9-class WRITE activation decision (TIER1_ROADMAP.md) -- its own "
                "explicit approval, separate from every PROVISIONING step's confirmation above -- then "
                "register the corresponding WRITE tool(s)."
            ),
            mutation_class=MutationClass.ACTIVATION,
            authorization_required=AuthorizationLevel.MILESTONE_9_ACTIVATION_DECISION,
            implementation_available=False,
            reversible=None,
            security_impact=SecurityImpact.ENABLES_MUTATION_CAPABILITY,
            prerequisite_satisfied=anchor_ready_now,
            blocked=True,
            blocked_reason=" ".join(p for p in activation_reason_parts if p),
            evidence=(),
        )
    )
    order += 1
    return tuple(steps), order


def _reorder(steps: tuple[PlanStep, ...], start: int) -> tuple[PlanStep, ...]:
    reordered = []
    for offset, step in enumerate(steps):
        reordered.append(
            PlanStep(
                step_id=step.step_id,
                order=start + offset,
                axis=step.axis,
                action=step.action,
                description=step.description,
                mutation_class=step.mutation_class,
                authorization_required=step.authorization_required,
                implementation_available=step.implementation_available,
                reversible=step.reversible,
                security_impact=step.security_impact,
                prerequisite_satisfied=step.prerequisite_satisfied,
                blocked=step.blocked,
                blocked_reason=step.blocked_reason,
                evidence=step.evidence,
            )
        )
    return tuple(reordered)


def _block_for_mismatch(step: PlanStep) -> PlanStep:
    if step.mutation_class is MutationClass.NONE:
        return step
    mismatch_reason = (
        "Store/witness mismatch detected in the current state (evidence_state=provisioned_mismatch) -- a "
        "security-relevant anomaly. No further progression is planned as safe until it is investigated."
    )
    combined_reason = mismatch_reason if not step.blocked_reason else f"{step.blocked_reason} {mismatch_reason}"
    return PlanStep(
        step_id=step.step_id,
        order=step.order,
        axis=step.axis,
        action=step.action,
        description=step.description,
        mutation_class=step.mutation_class,
        authorization_required=step.authorization_required,
        implementation_available=step.implementation_available,
        reversible=step.reversible,
        security_impact=step.security_impact,
        prerequisite_satisfied=False,
        blocked=True,
        blocked_reason=combined_reason,
        evidence=step.evidence,
    )


def generate_security_posture_plan(
    target_capability_posture: CapabilityPosture,
    target_anchor_assurance: AnchorAssurance,
    env: dict[str, str] | None = None,
) -> SecurityPosturePlan:
    """Read-only. Calls `discover_security_posture()` exactly once, then
    performs only pure computation. Never provisions, activates,
    deactivates, repairs, mutates, or reconfigures anything -- see this
    module's own docstring for the full mutation-free argument.

    `AnchorAssurance.UNKNOWN` is evidence-only (returned by discovery to
    mean "could not determine"); it is never a legal *target* and is
    rejected here defensively, independent of whatever validation an
    upstream CLI layer may already perform on raw argument strings.

    Both targets are coerced through their Enum constructor before any
    other logic runs. This is not mere type-hint decoration: `CapabilityPosture`
    and `AnchorAssurance` are `(str, Enum)` hybrids, so a caller passing a
    plain, value-equal string (e.g. `"write_protected"`) instead of the
    actual enum member would satisfy every `==` comparison but silently
    fail every `is` comparison this module uses throughout -- including
    the one guarding ADR-021's validity constraint -- without raising,
    letting a malformed target reach `TargetValidity.VALID` when it
    should have been rejected. `CapabilityPosture(x)`/`AnchorAssurance(x)`
    is idempotent for an already-correct enum member and raises
    `ValueError` for anything that is not a real value of either enum,
    closing this off for every caller, not only this module's own CLI
    (which already only ever constructs real enum members)."""

    target_capability_posture = CapabilityPosture(target_capability_posture)
    target_anchor_assurance = AnchorAssurance(target_anchor_assurance)

    if target_anchor_assurance is AnchorAssurance.UNKNOWN:
        raise ValueError(
            "AnchorAssurance.UNKNOWN is not a valid plan target -- it is an evidence-only value meaning "
            "'could not determine', never a legitimate target selection."
        )

    current = discover_security_posture(env)

    validity, validity_evidence = _evaluate_target_validity(target_capability_posture, target_anchor_assurance)
    notes = (_PLAN_IS_NOT_AUTHORIZATION_NOTE,)

    if validity is TargetValidity.INVALID_COMBINATION:
        return SecurityPosturePlan(
            current=current,
            target_capability_posture=target_capability_posture,
            target_anchor_assurance=target_anchor_assurance,
            target_validity=validity,
            validity_evidence=validity_evidence,
            capability_posture_transition=AxisTransitionKind.NO_CHANGE,
            anchor_assurance_transition=AxisTransitionKind.NO_CHANGE,
            overall_status=PlanOverallStatus.BLOCKED_INVALID_TARGET,
            safe_to_proceed=False,
            blocking_findings=validity_evidence,
            steps=(),
            notes=notes,
        )

    if current.anchor_assurance.value is AnchorAssurance.UNKNOWN:
        # The anchor-assurance axis's *current* value could not be
        # determined (evidence_state configuration_invalid or
        # store_error -- e.g. a malformed/legacy/foreign file already
        # sitting at the configured store path, or an invalid witness
        # client configuration). Generating an ordinary transition plan
        # here would silently treat "we don't know what's there" as "a
        # clean slate, safe to provision on top of" -- unavailable
        # evidence must never be treated as a success/no-op condition.
        # Blocks the whole plan (both axes), the same shape as an
        # invalid target: no steps, only the finding.
        finding = (
            "Anchor-assurance axis current state is indeterminate (evidence_state="
            f"{current.anchor_assurance.evidence_state.value}) -- its value could not be determined. No "
            "plan can safely be generated against an indeterminate current state; investigate via "
            "`pfsense-mcp-security discover` first."
        )
        return SecurityPosturePlan(
            current=current,
            target_capability_posture=target_capability_posture,
            target_anchor_assurance=target_anchor_assurance,
            target_validity=validity,
            validity_evidence=validity_evidence,
            capability_posture_transition=AxisTransitionKind.NO_CHANGE,
            anchor_assurance_transition=AxisTransitionKind.NO_CHANGE,
            overall_status=PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE,
            safe_to_proceed=False,
            blocking_findings=(finding,),
            steps=(),
            notes=notes,
        )

    capability_transition = _capability_transition_kind(current.capability_posture.value, target_capability_posture)
    anchor_transition = _anchor_transition_kind(current.anchor_assurance.value, target_anchor_assurance)

    anchor_ready_now = current.anchor_assurance.value == target_anchor_assurance and _anchor_evidence_is_clean(
        current.anchor_assurance.evidence_state, target_anchor_assurance
    )

    anchor_steps, _ = _anchor_assurance_steps(current, target_anchor_assurance, anchor_transition, order_start=1)
    capability_steps, _ = _capability_posture_steps(
        current,
        target_capability_posture,
        capability_transition,
        anchor_ready_now=anchor_ready_now,
        anchor_target=target_anchor_assurance,
        order_start=1,
    )

    capability_must_go_first = (
        capability_transition is AxisTransitionKind.DOWNGRADE
        and target_anchor_assurance is AnchorAssurance.NONE
        and anchor_transition is not AxisTransitionKind.NO_CHANGE
    )
    if capability_must_go_first:
        capability_steps = _reorder(capability_steps, start=1)
        anchor_steps = _reorder(anchor_steps, start=1 + len(capability_steps))
        ordered_steps = capability_steps + anchor_steps
    else:
        anchor_steps = _reorder(anchor_steps, start=1)
        capability_steps = _reorder(capability_steps, start=1 + len(anchor_steps))
        ordered_steps = anchor_steps + capability_steps

    mismatch = current.anchor_assurance.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH
    blocking_findings: list[str] = list(validity_evidence)
    if mismatch:
        blocking_findings.append(
            "Store/witness mismatch detected in current state (evidence_state=provisioned_mismatch) -- "
            "this is a security-relevant anomaly. Every prospective mutating step below is marked "
            "blocked as a result."
        )
        ordered_steps = tuple(_block_for_mismatch(step) for step in ordered_steps)

    safe_to_proceed = validity is TargetValidity.VALID and not mismatch

    if mismatch:
        overall_status = PlanOverallStatus.BLOCKED_ANOMALY_DETECTED
    elif validity is TargetValidity.VALID_NOT_IMPLEMENTED:
        overall_status = PlanOverallStatus.BLOCKED_NOT_IMPLEMENTED
    elif capability_transition is AxisTransitionKind.NO_CHANGE and anchor_transition is AxisTransitionKind.NO_CHANGE:
        overall_status = PlanOverallStatus.ALREADY_SATISFIED
    else:
        overall_status = PlanOverallStatus.PLAN_GENERATED

    return SecurityPosturePlan(
        current=current,
        target_capability_posture=target_capability_posture,
        target_anchor_assurance=target_anchor_assurance,
        target_validity=validity,
        validity_evidence=validity_evidence,
        capability_posture_transition=capability_transition,
        anchor_assurance_transition=anchor_transition,
        overall_status=overall_status,
        safe_to_proceed=safe_to_proceed,
        blocking_findings=tuple(blocking_findings),
        steps=ordered_steps,
        notes=notes,
    )
