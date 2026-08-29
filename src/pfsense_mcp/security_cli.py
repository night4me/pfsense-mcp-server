"""`pfsense-mcp-security` -- the guided security-posture provisioning
CLI named in `ADR-021` (Accepted). This file implements:

  - `discover` (`docs/SECURITY_POSTURE_PROVISIONING.md`'s Phase B):
    read-only discovery of both accepted axes' current state.
  - `plan` (also Phase-B-class, entirely mutation-free): `DISCOVER ->
    SELECT TARGET -> EVALUATE VALIDITY -> ASSESS PREREQUISITES ->
    GENERATE PLAN`, stopping before `PROVISIONING`. Bridges "what state
    do I have?" to "what would need to happen to reach a selected
    target?" without performing any of it -- see `security_plan.py`'s
    own module docstring for the full mutation-free argument and the
    "a plan is never authorization" invariant.
  - `doctor` (`docs/ROADMAP.md`'s doctor/preflight item): read-only
    Tier 1 ceremony readiness check -- artifact-exchange path
    cleanliness plus witness readiness, one deterministic READY/
    NOT_READY verdict. See `security_doctor.py`'s own module docstring
    for the full design and its explicit, documented limitations.
  - `bootstrap` (ADR-033 CLI Integration Slice 3): journal-aware,
    locking, deterministic ADR-033 least-privilege service-account
    provisioning orchestration. Composes the already-implemented, already-reviewed
    security-bootstrap stack (fixed administrative context, crash-safe
    journal, exclusive lock, `provision_service_account()`) via the one
    function `security_bootstrap_orchestration.run_bootstrap_from_environment()`
    exposes -- see that module's own docstring for the full control
    flow, and for why this file must never import any of the
    lower-level bootstrap-stack modules it composes directly. This file
    is deliberately kept isolated from all of them, an isolation
    boundary enforced by a dedicated regression test asserting on the
    literal absence of their module names from this file's source text
    -- so this docstring intentionally does not name them either.
    **Verified offline (synthetic/fake HTTP fixtures) and, once, live**
    against a disposable LAB appliance under an explicit,
    ceremony-specific owner authorization (2026-08-26) -- that
    authorization was scoped to that one ceremony only and does not
    stand for any future run; every live invocation still requires its
    own fresh, ceremony-specific authorization. `pfsense-mcp-security
    setup` (a user-facing, non-mutating discovery/planning wizard; see
    below) never runs `bootstrap` itself -- `bootstrap` remains the
    deterministic, non-interactive, lower-level command underneath it
    (composed by `setup apply --capability-posture write_protected`).
  - `recover`: ADR-033 recovery-execution orchestration -- inspects the
    existing bootstrap incident and, only with an explicit `--execute
    <ACTION>` plus the exact confirmation token a prior inspection just
    printed, executes one of the two closed recovery actions
    (`revoke_failed_bootstrap_api_key()`/`delete_dedicated_recovery_user()`).
    Standalone -- not folded into `bootstrap` or `setup`. Composes
    `security_recovery_orchestration.run_recovery_from_environment()`,
    the one function this file imports for it, exactly mirroring
    `bootstrap`'s own isolation discipline. **Verified offline, and its
    read-only inspection path live** (a standalone `recover --json`
    inspection against the 2026-08-26 LAB ceremony's own resulting
    state returned `no_recovery_needed`) -- the mutating `--execute`
    recovery actions themselves remain offline-verified only.
  - `setup` (`pfsense-mcp-security setup`): non-mutating,
    interactive-by-default discovery + plan-only wizard. Composes
    `discover`/`plan`'s own already-implemented machinery plus ADR-033
    account/privilege content via the one bridge module
    `security_setup_plan.py` exposes -- performs zero I/O of its own
    (no filesystem, no network) and never constructs an administrative
    context, so it cannot detect ADR-033 `RECOVERY_REQUIRED` state; the
    generated plan says so explicitly and points at `recover`. Selecting
    a target is intent for a human to review, never execution
    authorization -- bare `setup` never mutates anything, and there is
    no inline "continue and apply" path from it.
  - `setup apply` (Slice 2 read_only + Slice 3 write_protected + Slice
    4 inline recovery delegation): a wholly separate, explicit command
    -- never reachable from bare `setup`'s own flow -- that recomputes
    the plan fresh, refuses a stale `--plan-digest`, refuses a
    wrong/missing `--confirm` token, and only then acts. For
    `read_only`: one read-only connectivity check against the
    operator's existing runtime pfSense configuration, never a
    mutation. For `write_protected`: composes `security_bootstrap_orchestration.
    run_bootstrap_from_environment()` -- the exact same sole gateway
    `bootstrap` itself uses -- to provision (or verify/repair) the one
    fixed ADR-033 service account; for `anchor_assurance=hardware_witness`
    specifically, `doctor` is checked and must be ready *before* that
    composed call is ever made. If bootstrap composition itself reports
    a prior operation needs attention, `security_recovery_orchestration.
    run_recovery_from_environment()` is additionally composed --
    read-only inspection only, never `--execute`/a confirmation token
    -- to surface the exact recovery detail inline, sparing the
    operator a second command just to see it; only the operator's own
    separate `recover --execute/--confirm` invocation can ever resolve
    it. Composes `security_setup_apply.run_setup_apply_from_environment()`,
    the one function this file imports for it.

`discover`, `plan`, `doctor`, and bare `setup` perform no provisioning,
repair, or mutation. `bootstrap`, `recover`, and `setup apply` (for
`write_protected` only) are the only subcommands that can mutate
pfSense state (when later run against a real appliance) -- and even
then, only ever the one fixed, least-privilege `pfsense-mcp` service
account this codebase's ADR-033 architecture already scopes all three
to. `setup apply` never introduces a second mutating primitive of its
own: its `write_protected` branch is pure composition of the exact
same `run_bootstrap_from_environment()` standalone `bootstrap` already
calls, and its `read_only` branch's one live call is a harmless GET.
Provisioning this account through `setup apply` does not, by itself,
make any new WRITE tool reachable through the MCP server -- the public
MCP contract (95 READ + 1 guidance + 0 default-reachable WRITE) is
unaffected; see `security_setup_apply.py`'s own module docstring for
why.

This file does not import `pfsense_mcp.tier1` directly, or at all --
every axis-discovery call goes through the one function
`security_discovery.discover_security_posture()` exposes (`plan` calls
it only indirectly, via `security_plan.generate_security_posture_plan()`;
`doctor` calls it only indirectly, via
`security_doctor.run_doctor_checks()`; `setup` calls it only
indirectly, via `security_setup_plan.generate_setup_plan()`), keeping
the tier1-package-isolation exemption's surface to exactly
`security_discovery.py`, matching `tier1_anchor_check.py`'s own
established discipline for `application.py`.
"""

from __future__ import annotations

import argparse
import json
import os
import shlex
import shutil
import sys
import textwrap
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, TextIO
from urllib.parse import urlsplit

from .security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    BootstrapOrchestrationResult,
    run_bootstrap_from_environment,
)
from .security_client_config_write import WriteOutcome, WriteResult, run_client_config_write_from_environment
from .security_discovery import (
    AnchorAssurance,
    AnchorAssuranceDiscovery,
    AnchorEvidenceState,
    CapabilityPosture,
    CapabilityPostureDiscovery,
    SecurityPostureDiscovery,
    discover_capability_posture,
    discover_security_posture,
)
from .security_doctor import CheckStatus, DoctorCheck, DoctorResult, run_doctor_checks
from .security_plan import (
    PlanOverallStatus,
    PlanStep,
    SecurityPosturePlan,
    generate_security_posture_plan,
)
from .security_plan_digest import PLAN_DIGEST_SCHEMA_VERSION, compute_plan_digest
from .security_recovery_orchestration import (
    RecoveryAction,
    RecoveryOrchestrationOutcome,
    RecoveryOrchestrationResult,
    run_recovery_from_environment,
)
from .security_setup_apply import ApplyOutcome, ApplyResult, run_setup_apply_from_environment
from .security_setup_confirm_key import (
    DEFAULT_CONFIRM_KEY_FILE,
    InitConfirmKeyOutcome,
    InitConfirmKeyResult,
    create_confirm_key,
)
from .security_setup_plan import (
    INTENDED_SERVICE_ACCOUNT_IDENTITY,
    PrivilegePlan,
    SetupPlan,
    TargetDescriptor,
    VersionEvidence,
    generate_setup_plan,
)
from .security_setup_plan_digest import SETUP_PLAN_DIGEST_SCHEMA_VERSION, compute_setup_plan_digest

_MISMATCH_EXIT_CODE = 2
_BLOCKED_TARGET_EXIT_CODE = 2
# Deliberately distinct from the two above: `doctor`'s whole purpose is
# a binary readiness gate for automation, unlike discover/plan (which
# exit 0 even when "unconfigured"). 1 = one or more checks failed;
# argparse's own existing exit 2 remains reserved for usage errors
# (main()'s no-subcommand-matched fallback, unchanged below).
_DOCTOR_NOT_READY_EXIT_CODE = 1

# `bootstrap`'s exit-code model deliberately distinguishes more categories
# than a generic "failed" -- see BootstrapOrchestrationOutcome's own
# docstring for what each category actually proves. Codes are chosen to
# not collide with argparse's own usage-error convention (2) or the
# other subcommands' exit codes above, though `bootstrap`'s codes are
# only meaningful relative to its own epilog, not shared across
# subcommands.
_BOOTSTRAP_EXIT_CODES: dict[BootstrapOrchestrationOutcome, int] = {
    BootstrapOrchestrationOutcome.ALREADY_COMPLETE: 0,
    BootstrapOrchestrationOutcome.COMPLETED: 0,
    BootstrapOrchestrationOutcome.PROVISIONING_FAILED: 1,
    BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED: 2,
    BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION: 3,
    BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION: 4,
    BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE: 5,
    BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR: 6,
}

# `recover`'s exit-code model, independently numbered from `bootstrap`'s
# (matching that command's own established precedent that each
# subcommand's codes are only meaningful relative to its own epilog, not
# shared across subcommands) -- see RecoveryOrchestrationOutcome's own
# docstring for what each category actually proves. Every member of that
# enum has an explicit entry here on purpose: a KeyError on an
# unhandled outcome would be a genuine defect, not something to guard
# with a silent default.
_RECOVERY_EXIT_CODES: dict[RecoveryOrchestrationOutcome, int] = {
    RecoveryOrchestrationOutcome.NO_RECOVERY_NEEDED: 0,
    RecoveryOrchestrationOutcome.RECOVERY_ALREADY_COMPLETE: 0,
    RecoveryOrchestrationOutcome.RECOVERY_COMPLETED: 0,
    RecoveryOrchestrationOutcome.RECOVERY_NEEDED: 1,
    RecoveryOrchestrationOutcome.EXECUTE_ACTION_MISMATCH: 2,
    RecoveryOrchestrationOutcome.BLOCKED_LOCK_CONTENTION: 3,
    RecoveryOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR: 4,
    RecoveryOrchestrationOutcome.RECOVERY_EXECUTION_FAILED: 5,
    RecoveryOrchestrationOutcome.EXECUTE_TOKEN_INVALID: 6,
    RecoveryOrchestrationOutcome.BLOCKED_CANDIDATE_NOT_IDENTIFIABLE: 7,
    RecoveryOrchestrationOutcome.BLOCKED_AMBIGUOUS_RECOVERY_STATE: 8,
    RecoveryOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE: 9,
}

# `setup apply`'s exit-code model, independently numbered from every
# other subcommand's (same established per-subcommand-own-epilog
# convention). Every member of `ApplyOutcome` has an explicit entry
# here on purpose -- a KeyError on an unhandled outcome would be a
# genuine defect, not something to guard with a silent default.
_SETUP_APPLY_EXIT_CODES: dict[ApplyOutcome, int] = {
    ApplyOutcome.APPLY_COMPLETED: 0,
    ApplyOutcome.INSPECT_PLAN_CURRENT: 1,
    ApplyOutcome.PLAN_STALE: 2,
    ApplyOutcome.CONFIRM_TOKEN_INVALID: 3,
    # 4 is deliberately retired, not reused: Slice 2's NOT_SUPPORTED_FOR_POSTURE
    # occupied it and was removed once Slice 3 made write_protected apply
    # exist too -- see ApplyOutcome's own docstring.
    ApplyOutcome.BLOCKED_CONFIGURATION_ERROR: 5,
    ApplyOutcome.CONNECTIVITY_FAILED: 6,
    ApplyOutcome.DOCTOR_NOT_READY: 7,
    # write_protected, via run_bootstrap_from_environment() composition (Slice 3):
    ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE: 0,
    ApplyOutcome.BOOTSTRAP_COMPLETED: 0,
    ApplyOutcome.BOOTSTRAP_LOCK_CONTENTION: 8,
    ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED: 9,
    ApplyOutcome.BOOTSTRAP_CORRUPT_LOCAL_STATE: 10,
    ApplyOutcome.BOOTSTRAP_PREFLIGHT_DERIVATION_FAILED: 11,
    ApplyOutcome.BOOTSTRAP_PROVISIONING_FAILED: 12,
}

# `setup write-client-config`'s own exit-code model (Phase C), independently
# numbered under its own epilog. 2 (PLAN_STALE) is assigned at the CLI-wiring
# layer, not by `WriteOutcome` itself -- see `_run_setup_write_client_config()`
# -- since only that layer regenerates the plan and can detect staleness.
_CLIENT_CONFIG_WRITE_EXIT_CODES: dict[WriteOutcome, int] = {
    WriteOutcome.WRITE_COMPLETED: 0,
    WriteOutcome.INSPECT_CURRENT: 1,
    WriteOutcome.CONFIRM_TOKEN_INVALID: 3,
    WriteOutcome.BLOCKED_CONFIGURATION_ERROR: 4,
    WriteOutcome.BLOCKED_MALFORMED_EXISTING_CONFIG: 5,
    WriteOutcome.BLOCKED_PATH_UNSAFE: 6,
    WriteOutcome.WRITE_VALIDATION_FAILED_ROLLED_BACK: 7,
}
_CLIENT_CONFIG_WRITE_PLAN_STALE_EXIT_CODE = 2

# `setup init-confirm-key`'s own exit-code model. CREATED and
# ALREADY_EXISTS both exit 0 -- idempotent by design (see
# `security_setup_confirm_key.create_confirm_key()`'s own docstring):
# an operator re-running this command after already having a key is
# not an error, it is the safe, expected no-op that still reports the
# path to export.
_INIT_CONFIRM_KEY_EXIT_CODES: dict[InitConfirmKeyOutcome, int] = {
    InitConfirmKeyOutcome.CREATED: 0,
    InitConfirmKeyOutcome.ALREADY_EXISTS: 0,
    InitConfirmKeyOutcome.BLOCKED_UNSAFE_PATH: 1,
    InitConfirmKeyOutcome.FAILED: 2,
}

# `setup`'s own exit-code model, independently numbered under its own
# epilog like every other subcommand here. 3 is deliberately distinct
# from `plan`'s reused 2 (invalid/anomalous target): it means
# interactive prompting was abandoned (EOF, or the operator supplied no
# value for a required prompt) before a plan could even be generated --
# a materially different, non-mutating outcome from "a plan was
# generated but the target itself is invalid."
_SETUP_ABORTED_EXIT_CODE = 3

_CAPABILITY_POSTURE_CHOICES = [member.value for member in CapabilityPosture]
# AnchorAssurance.UNKNOWN is deliberately excluded -- it is an
# evidence-only value ("could not determine"), never a legal target;
# excluding it from argparse's own choices= means an attempt to select
# it is rejected before it can ever reach generate_security_posture_plan().
_ANCHOR_ASSURANCE_CHOICES = [member.value for member in AnchorAssurance if member is not AnchorAssurance.UNKNOWN]


def _capability_posture_to_dict(discovery: CapabilityPostureDiscovery) -> dict[str, Any]:
    return {
        "value": discovery.value.value,
        "configured_profile_name": discovery.configured_profile_name,
        "configured_profile_valid": discovery.configured_profile_valid,
        "write_capabilities_active": discovery.write_capabilities_active,
        "write_capabilities_total": discovery.write_capabilities_total,
        "allow_list_entries": list(discovery.allow_list_entries),
        "evidence": list(discovery.evidence),
    }


def _anchor_assurance_to_dict(discovery: AnchorAssuranceDiscovery) -> dict[str, Any]:
    return {
        "value": discovery.value.value,
        "evidence_state": discovery.evidence_state.value,
        "store_configured": discovery.store_configured,
        "store_exists": discovery.store_exists,
        "seeded": discovery.seeded,
        "complete": discovery.complete,
        "handle": discovery.handle,
        "baseline": discovery.baseline,
        "provisioned_at": discovery.provisioned_at,
        "witness_configured": discovery.witness_configured,
        "witness_reachable": discovery.witness_reachable,
        "witness_value": discovery.witness_value,
        "witness_matches_baseline": discovery.witness_matches_baseline,
        "evidence": list(discovery.evidence),
    }


def _discovery_to_dict(discovery: SecurityPostureDiscovery) -> dict[str, Any]:
    return {
        "capability_posture": _capability_posture_to_dict(discovery.capability_posture),
        "anchor_assurance": _anchor_assurance_to_dict(discovery.anchor_assurance),
        "notes": [
            "read_only + hardware_witness is a valid, representable combination in the accepted ADR-021 "
            "two-axis model even though it is not one of the three curated setup presets -- see "
            "docs/SECURITY_POSTURE_PROVISIONING.md's advanced/staged path.",
            "This report is read-only discovery only. No provisioning, repair, or mutation was performed "
            "or is available in this CLI yet (ADR-021 Phase B).",
        ],
    }


def _format_human(discovery: SecurityPostureDiscovery) -> str:
    cap = discovery.capability_posture
    anchor = discovery.anchor_assurance
    lines = [
        "pfsense-mcp-security: security posture discovery (read-only)",
        "",
        f"Capability posture: {cap.value.value}",
        f"  configured profile name:    {cap.configured_profile_name} (valid={cap.configured_profile_valid})",
        f"  write capabilities active:  {cap.write_capabilities_active} of {cap.write_capabilities_total}",
        f"  allow-list entries:         {len(cap.allow_list_entries)}",
    ]
    lines.extend(_wrap(line, indent="    ", initial_indent="  - ") for line in cap.evidence)
    lines.extend(
        [
            "",
            f"Anchor assurance:    {anchor.value.value}",
            f"  evidence state:              {anchor.evidence_state.value}",
            f"  store configured:            {anchor.store_configured}",
            f"  store exists:                {anchor.store_exists}",
            f"  seeded / complete:           {anchor.seeded} / {anchor.complete}",
            f"  handle:                      {anchor.handle}",
            f"  baseline:                    {anchor.baseline}",
            f"  provisioned_at:              {anchor.provisioned_at}",
            f"  witness configured:          {anchor.witness_configured}",
            f"  witness reachable:           {anchor.witness_reachable}",
            f"  witness value:               {anchor.witness_value}",
            f"  witness matches baseline:    {anchor.witness_matches_baseline}",
        ]
    )
    lines.extend(_wrap(line, indent="    ", initial_indent="  - ") for line in anchor.evidence)
    lines.append("")
    if anchor.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH:
        lines.append(
            _wrap(
                "WARNING: witness/store mismatch detected -- this is a security-relevant anomaly. "
                "Reported only; no reconciliation was attempted."
            )
        )
    else:
        lines.append(
            _wrap(
                "Note: read_only + hardware_witness is a valid, representable combination in the accepted "
                "ADR-021 two-axis model -- not one of the three curated setup presets, but fully supported."
            )
        )
    lines.append(
        _wrap(
            "This report is read-only discovery only (ADR-021 Phase B). Provisioning happens only through "
            "the separate `bootstrap`/`setup apply`/`recover` subcommands, never this one."
        )
    )
    return "\n".join(lines)


def _plan_step_to_dict(step: PlanStep) -> dict[str, Any]:
    return {
        "step_id": step.step_id,
        "order": step.order,
        "axis": step.axis,
        "action": step.action,
        "description": step.description,
        "mutation_class": step.mutation_class.value,
        "authorization_required": step.authorization_required.value,
        "implementation_available": step.implementation_available,
        "reversible": step.reversible,
        "security_impact": step.security_impact.value,
        "prerequisite_satisfied": step.prerequisite_satisfied,
        "blocked": step.blocked,
        "blocked_reason": step.blocked_reason,
        "evidence": list(step.evidence),
    }


def _plan_to_dict(plan: SecurityPosturePlan) -> dict[str, Any]:
    return {
        "current": _discovery_to_dict(plan.current),
        "target": {
            "capability_posture": plan.target_capability_posture.value,
            "anchor_assurance": plan.target_anchor_assurance.value,
        },
        "target_validity": plan.target_validity.value,
        "validity_evidence": list(plan.validity_evidence),
        "capability_posture_transition": plan.capability_posture_transition.value,
        "anchor_assurance_transition": plan.anchor_assurance_transition.value,
        "overall_status": plan.overall_status.value,
        "safe_to_proceed": plan.safe_to_proceed,
        "blocking_findings": list(plan.blocking_findings),
        "steps": [_plan_step_to_dict(step) for step in plan.steps],
        "notes": list(plan.notes),
        # ADR-022 Phase B: plan identity only -- never authorization. See
        # security_plan_digest.py's own module docstring. A future,
        # separately-authorized authorization artifact would reference
        # this value; nothing in this build accepts, verifies, or acts
        # on one.
        "plan_digest": compute_plan_digest(plan),
        "plan_digest_schema_version": PLAN_DIGEST_SCHEMA_VERSION,
    }


def _format_plan_human(plan: SecurityPosturePlan) -> str:
    lines = [
        "pfsense-mcp-security: security posture plan (analysis only -- not authorization)",
        "",
        f"Plan digest (schema v{PLAN_DIGEST_SCHEMA_VERSION}): {compute_plan_digest(plan)}  "
        "(plan identity only -- not authorization)",
        f"Current:  capability_posture={plan.current.capability_posture.value.value}  "
        f"anchor_assurance={plan.current.anchor_assurance.value.value} "
        f"({plan.current.anchor_assurance.evidence_state.value})",
        f"Target:   capability_posture={plan.target_capability_posture.value}  "
        f"anchor_assurance={plan.target_anchor_assurance.value}",
        f"Target validity:      {plan.target_validity.value}",
        f"Overall status:       {plan.overall_status.value}",
        f"Safe to proceed:      {plan.safe_to_proceed}  "
        "(plan validity only -- not authorization or execution readiness; see notes below)",
        f"capability_posture:   {plan.capability_posture_transition.value}",
        f"anchor_assurance:     {plan.anchor_assurance_transition.value}",
        "",
    ]
    for line in plan.validity_evidence:
        lines.append(_wrap(line, indent="    ", initial_indent="  - "))
    for line in plan.blocking_findings:
        lines.append(_wrap(line, indent="          ", initial_indent="BLOCKING: "))
    if plan.steps:
        lines.append("")
        lines.append("Steps (ordered; none executed):")
        for step in plan.steps:
            lines.append(f"  [{step.order}] ({step.axis}) {step.action}")
            lines.append(f"      id:                     {step.step_id}")
            lines.append(_wrap(step.description, indent=" " * 30, initial_indent="      description:            "))
            lines.append(f"      mutation_class:         {step.mutation_class.value}")
            lines.append(f"      authorization_required: {step.authorization_required.value}")
            lines.append(f"      implementation_available: {step.implementation_available}")
            lines.append(f"      reversible:             {step.reversible}")
            lines.append(f"      security_impact:        {step.security_impact.value}")
            lines.append(f"      prerequisite_satisfied: {step.prerequisite_satisfied}")
            lines.append(f"      blocked:                {step.blocked}")
            if step.blocked_reason:
                lines.append(
                    _wrap(step.blocked_reason, indent=" " * 30, initial_indent="      blocked_reason:         ")
                )
    lines.append("")
    for line in plan.notes:
        lines.append(_wrap(line))
    return "\n".join(lines)


def _doctor_check_to_dict(check: DoctorCheck) -> dict[str, Any]:
    return {
        "check_id": check.check_id,
        "description": check.description,
        "status": check.status.value,
        "detail": check.detail,
    }


def _doctor_result_to_dict(result: DoctorResult, posture: CapabilityPostureDiscovery) -> dict[str, Any]:
    return {
        "ready": result.ready,
        # v1.0 Product/UX arc: these checks are about the OPTIONAL
        # protected-change capability, not about read-only access at
        # all -- `capability_posture` lets a caller (human or script)
        # tell whether `ready: false` actually matters for their own
        # configured mode, rather than reading it as a general-purpose
        # "is this installation broken" signal it was never meant to be.
        "capability_posture": posture.value.value,
        "checks": [_doctor_check_to_dict(check) for check in result.checks],
        "notes": [
            "Diagnostic only -- no artifact was deleted, moved, or repaired, and no witness/store state "
            "was changed. Checks only artifact-exchange path cleanliness and witness readiness, not the "
            "full build_production_runtime() prerequisite set (store/authority-key configuration, etc.).",
            "These checks are about the optional protected-change (write_protected) capability. "
            "Read-only access does not require any of them to be ready.",
        ],
    }


_STATUS_SYMBOL = {
    CheckStatus.PASS: "OK",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.NOT_CONFIGURED: "NOT CONFIGURED",
}


def _format_doctor_human(result: DoctorResult, posture: CapabilityPostureDiscovery) -> str:
    lines = ["pfsense-mcp-security doctor -- protected-change readiness check", ""]
    # v1.0 Product/UX arc: this command's checks (artifact-exchange
    # cleanliness, TPM witness) are entirely about the OPTIONAL
    # protected-change ceremony -- irrelevant to the read-only access
    # most users actually have. Framing "Overall: NOT READY" with no
    # context made every read-only user's doctor run look alarming for
    # something they never opted into. The underlying READY/NOT READY
    # computation and per-check detail are unchanged; only this
    # explanatory framing is new.
    if posture.value is CapabilityPosture.READ_ONLY:
        lines.append(
            _wrap(
                "You're using read-only access (the default, and what most users want). The "
                "checks below are about a separate, optional capability -- protected changes -- "
                "and do not affect your read-only access either way."
            )
        )
        lines.append("")
    lines.append(f"Overall: {'READY' if result.ready else 'NOT READY'}")
    lines.append("")
    for check in result.checks:
        marker = f"  [{_STATUS_SYMBOL[check.status]}] "
        lines.append(_wrap(f"{check.description} ({check.check_id})", indent="      ", initial_indent=marker))
        lines.append(_wrap(check.detail, indent="        ", initial_indent="        "))
    lines.append("")
    lines.append(
        _wrap(
            "Diagnostic only -- no artifact was deleted, moved, or repaired, and no witness/store state was "
            "changed. Checks artifact-exchange path cleanliness and witness readiness only, not the full "
            "build_production_runtime() prerequisite set."
        )
    )
    return "\n".join(lines)


def _bootstrap_result_to_dict(result: BootstrapOrchestrationResult) -> dict[str, Any]:
    return {
        "outcome": result.outcome.value,
        # Already sanitized upstream (never a raw response body, never a
        # secret) -- see security_bootstrap_orchestration.py's own
        # docstring for the sanitization discipline this relies on.
        "detail": result.detail,
        "operation_id": result.operation_id,
        "restart_decision": (
            {
                "classification": result.restart_decision.classification.value,
                "operation_id": result.restart_decision.operation_id,
                "recovery_action": (
                    result.restart_decision.recovery_action.value if result.restart_decision.recovery_action else None
                ),
            }
            if result.restart_decision is not None
            else None
        ),
        "provisioning_outcome": result.provisioning_outcome.value if result.provisioning_outcome else None,
        "provisioning_detail": result.provisioning_detail,
        "notes": [
            "This subcommand (along with `recover`) can mutate pfSense state. Verified offline "
            "(synthetic/fake HTTP fixtures) and, once, live against a disposable LAB appliance under "
            "an explicit, ceremony-specific owner authorization (2026-08-26) that does not stand for "
            "any future run.",
            "Never prints or logs an API key, password, or any other secret value. A freshly generated "
            "service-account key is written only to the configured PFSENSE_SERVICE_API_KEY_FILE custody "
            "path (owner-only permissions), never to stdout/stderr/JSON output.",
        ],
    }


def _format_bootstrap_human(result: BootstrapOrchestrationResult) -> str:
    lines = [
        "pfsense-mcp-security: ADR-033 least-privilege service-account bootstrap orchestration",
        "",
        f"Outcome: {result.outcome.value}",
        _wrap(result.detail, indent="         ", initial_indent="Detail:  "),
    ]
    if result.operation_id is not None:
        lines.append(f"Operation id: {result.operation_id}")
    if result.restart_decision is not None:
        decision = result.restart_decision
        lines.append(f"Restart classification: {decision.classification.value}")
        if decision.recovery_action is not None:
            lines.append(f"Recovery action needed: {decision.recovery_action.value}")
    if result.provisioning_outcome is not None:
        lines.append(f"Engine outcome: {result.provisioning_outcome.value}")
        lines.append(_wrap(result.provisioning_detail or "", indent=" " * 16, initial_indent="Engine detail:  "))
    lines.append("")
    lines.append(
        _wrap(
            "This subcommand (along with `recover`) can mutate pfSense state. Verified offline "
            "(synthetic/fake HTTP fixtures) and, once, live against a disposable LAB appliance under an "
            "explicit, ceremony-specific owner authorization (2026-08-26) that does not stand for any "
            "future run."
        )
    )
    lines.append(
        _wrap(
            "Never prints or logs an API key, password, or any other secret value. A freshly generated "
            "service-account key is written only to the configured PFSENSE_SERVICE_API_KEY_FILE custody "
            "path (owner-only permissions), never to stdout/stderr/JSON output."
        )
    )
    return "\n".join(lines)


def _recover_result_to_dict(result: RecoveryOrchestrationResult) -> dict[str, Any]:
    evidence = result.evidence
    return {
        "outcome": result.outcome.value,
        # Already sanitized upstream -- see security_recovery_orchestration.py's
        # own docstring for the sanitization discipline this relies on.
        "detail": result.detail,
        "operation_id": result.operation_id,
        "recovery_action": result.recovery_action.value if result.recovery_action is not None else None,
        # A derived confirmation artifact, never a credential.
        "confirmation_token": result.confirmation_token,
        "evidence": (
            {
                "object_kind": evidence.object_kind,
                "selected_id": evidence.selected_id,
                "objects_before": evidence.objects_before,
                "objects_after": evidence.objects_after,
                "verified_absent": evidence.verified_absent,
                "unrelated_objects_preserved": evidence.unrelated_objects_preserved,
            }
            if evidence is not None
            else None
        ),
        "notes": [
            "Default (no --execute) is read-only inspection only -- makes no pfSense mutation.",
            "Execution requires both --execute <ACTION> and the exact confirmation token this "
            "inspection just printed; a missing, wrong, stale, or cross-target/object/action/incident "
            "token is refused before any mutating HTTP call.",
            "Never prints or logs an API key, password, or any other secret value.",
        ],
    }


def _format_recover_human(result: RecoveryOrchestrationResult) -> str:
    lines = [
        "pfsense-mcp-security: ADR-033 recovery-execution orchestration",
        "",
        f"Outcome: {result.outcome.value}",
        _wrap(result.detail, indent="         ", initial_indent="Detail:  "),
    ]
    if result.operation_id is not None:
        lines.append(f"Operation id: {result.operation_id}")
    if result.recovery_action is not None:
        lines.append(f"Recovery action: {result.recovery_action.value}")
    if result.confirmation_token is not None and result.recovery_action is not None:
        lines.append(f"Confirmation token: {result.confirmation_token}")
        lines.append(
            f"To execute: pfsense-mcp-security recover --execute {result.recovery_action.value} "
            f"--confirm {result.confirmation_token}"
        )
    if result.evidence is not None:
        lines.append(f"Object kind: {result.evidence.object_kind}")
        lines.append(f"Objects before/after: {result.evidence.objects_before}/{result.evidence.objects_after}")
        lines.append(f"Verified absent: {result.evidence.verified_absent}")
    lines.append("")
    lines.append("Default (no --execute) is read-only inspection only -- makes no pfSense mutation.")
    lines.append(
        _wrap(
            "Execution requires both --execute <ACTION> and the exact confirmation token this inspection "
            "just printed; a missing, wrong, stale, or cross-target/object/action/incident token is refused "
            "before any mutating HTTP call."
        )
    )
    lines.append("Never prints or logs an API key, password, or any other secret value.")
    return "\n".join(lines)


def _wrap(text: str, *, indent: str = "", initial_indent: str | None = None) -> str:
    """Wrap free-form prose in command *output* (not --help text, see
    _ParagraphHelpFormatter) to the terminal width. Found via v1.0.0
    Product/UX closure arc C3's narrow-terminal dogfood: discover/plan/
    doctor's own explanatory prose (evidence bullets, notes, diagnostic
    footers) was being emitted as single unwrapped lines up to 400+
    characters at 60 columns. break_long_words/break_on_hyphens are off
    -- a long unbreakable token (a plan digest, confirmation token, or
    URL) must overflow its own line rather than be silently split across
    two, which would corrupt it for copy/paste. `initial_indent`, if
    given, prefixes only the first line (e.g. a "  - " bullet marker)
    while `indent` aligns every continuation line beneath it."""
    width = max(shutil.get_terminal_size(fallback=(80, 24)).columns, 20)
    return textwrap.fill(
        text,
        width,
        initial_indent=indent if initial_indent is None else initial_indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


class _ParagraphHelpFormatter(argparse.HelpFormatter):
    """Wraps `description`/`epilog` text to the terminal width, like
    argparse's own default formatter, but preserves blank-line paragraph
    breaks -- unlike `RawDescriptionHelpFormatter` (never wraps, at any
    width; found via v1.0.0 Product/UX closure arc C3's narrow-terminal
    dogfood to produce a 449-character unwrapped line at 60 columns) or
    the plain default formatter (collapses paragraph breaks, losing the
    author's own exit-code/paragraph structure)."""

    def _fill_text(self, text: str, width: int, indent: str) -> str:
        paragraphs = text.split("\n\n")
        return "\n\n".join(
            textwrap.fill(paragraph, width, initial_indent=indent, subsequent_indent=indent) for paragraph in paragraphs
        )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pfsense-mcp-security",
        description=(
            "Guided security-posture discovery and diagnostics for pfsense-mcp-server (ADR-021, "
            "Accepted). `discover`/`plan`/`doctor` are read-only diagnostics; `bootstrap`/`setup "
            "apply`/`recover` are the separate, explicitly-gated provisioning/recovery subcommands."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    discover_parser = subparsers.add_parser(
        "discover",
        help="Report the current capability-posture and anchor-assurance axis state. Read-only.",
        description="Report the current capability-posture and anchor-assurance axis state. Read-only.",
        epilog=(
            "Exit codes: 0 on any clean discovery result, including an entirely unconfigured or "
            "unreachable-witness state -- neither is treated as a failure. 2 only if the anchor-assurance "
            "evidence state is provisioned_mismatch (the live witness value disagrees with the persisted "
            "high-water mark) -- a security-relevant anomaly, reported only, never auto-resolved."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    discover_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    plan_parser = subparsers.add_parser(
        "plan",
        help=(
            "Compare current posture against an explicit target and generate an ordered, "
            "never-executed plan. Analysis only -- performs no provisioning, activation, or mutation."
        ),
        description=(
            "DISCOVER -> SELECT TARGET -> EVALUATE VALIDITY -> ASSESS PREREQUISITES -> GENERATE PLAN, "
            "then stop. Never provisions, activates, deactivates, repairs, mutates, or reconfigures "
            "anything -- see the plan's own 'notes' field: a generated plan is NEVER authorization to "
            "execute it."
        ),
        epilog=(
            "Exit codes: 0 whenever a plan was generated, including 'already satisfied' and "
            "'valid target but its backend is not implemented' -- neither is a usage error. 2 if the "
            "requested target combination itself is invalid per ADR-021 (e.g. write_protected + none), if "
            "the current state shows a store/witness mismatch (a security-relevant anomaly), or if the "
            "current anchor-assurance state is indeterminate (e.g. a malformed/foreign file already at "
            "the configured store path) -- unavailable evidence is never treated as a clean slate. The "
            "same meaning `discover`'s own exit code 2 already has, reused here rather than "
            "reinvented.\n\n"
            "This command selects nothing and authorizes nothing: selecting a target here is intent, "
            "not execution authorization, and no subsequent 'apply this plan' command exists in this "
            "build.\n\n"
            "'Safe to proceed' means only that the target is architecturally valid and current evidence "
            "shows no detected anomaly -- it is never authorization, approval, execution-readiness, or a "
            "claim that every step is unblocked or implemented.\n\n"
            "'Plan digest' is a deterministic identity value (ADR-022 Phase B) binding a future "
            "authorization to this exact plan -- it is plan identity only, never authorization, a "
            "secret, a bearer token, or proof of operator consent. No command in this build creates, "
            "accepts, or verifies an authorization artifact."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    plan_parser.add_argument(
        "--capability-posture",
        required=True,
        choices=_CAPABILITY_POSTURE_CHOICES,
        help="Target capability-posture axis value.",
    )
    plan_parser.add_argument(
        "--anchor-assurance",
        required=True,
        choices=_ANCHOR_ASSURANCE_CHOICES,
        help="Target anchor-assurance axis value. 'unknown' is not accepted -- it is evidence-only.",
    )
    plan_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    doctor_parser = subparsers.add_parser(
        "doctor",
        help=(
            "Read-only Tier 1 ceremony preflight: artifact-exchange path cleanliness plus witness "
            "readiness. Diagnostic only -- never repairs, cleans, or mutates anything."
        ),
        description=(
            "Checks the four fixed Tier 1 artifact-exchange paths (authorization inbox, "
            "confirmation-pending outbox, confirmation-signed inbox, authorization-preview outbox) are "
            "absent, and that the anti-rollback witness is currently verified -- exactly the two classes "
            "of real incident this command exists to catch before an operator starts a ceremony. Never "
            "deletes/moves/repairs an artifact and never mutates witness or store state."
        ),
        epilog=(
            "Exit codes: 0 if every check passed (READY). 1 if one or more checks failed or are not "
            "configured (NOT READY) -- unlike `discover`/`plan`, an entirely unconfigured host is reported "
            "as NOT READY here, since a ceremony genuinely cannot begin without configuration; each "
            "check's own status distinguishes 'not configured' from 'configured but broken' so the "
            "reason is still actionable. 2 on a usage error (argparse's own existing convention, "
            "unchanged).\n\n"
            "This command never deletes, moves, archives, or overwrites an artifact, and never changes "
            "witness or store state -- it only reads filesystem metadata and delegates witness readiness "
            "to the same read-only discovery `discover` itself already uses."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help=(
            "ADR-033 least-privilege service-account bootstrap orchestration. Verified offline and, "
            "once, live (LAB, 2026-08-26, ceremony-scoped)."
        ),
        description=(
            "Journal-aware, locking, deterministic orchestration of the already-implemented ADR-033 "
            "security-bootstrap stack: creates or additively syncs the one fixed, least-privilege "
            "pfsense-mcp service account against the target configured entirely through environment "
            "variables (the same PFSENSE_*/PFSENSE_ADMIN_* variables build_admin_context() already "
            "validates -- no separate flags exist for target/credentials). May provision real security "
            "prerequisites when run against a real appliance -- verified offline (synthetic/fake HTTP "
            "fixtures) and, once, live against a disposable LAB appliance under an explicit, "
            "ceremony-specific owner authorization (2026-08-26) that does not stand for any future "
            "run; every live invocation still requires its own fresh authorization. "
            "`pfsense-mcp-security setup` is the separate, already-implemented interactive wizard; "
            "`bootstrap` is the deterministic, non-interactive command underneath it (composed by "
            "`setup apply --capability-posture write_protected`). Supply secrets (admin API key, admin "
            "password, journal integrity key) through the configured file paths, never inline -- shell "
            "history would otherwise capture them."
        ),
        epilog=(
            "Exit codes: 0 success (provisioning completed or was already correctly satisfied, or a "
            "prior operation was already recorded and independently confirmed complete). "
            "1 the engine ran but did not reach a verified successful state (covers authentication/"
            "authorization failure, a duplicate/ambiguous existing account, a post-mutation "
            "verification mismatch, and any unexpected error escaping the engine) -- see 'detail' and "
            "'provisioning_detail' for the specific reason; the local lock is held pending manual "
            "investigation. 2 the engine refused before any HTTP call (e.g. unsupported installed "
            "pfSense REST API package version) -- proven zero network activity, but this alone does not "
            "unblock a subsequent offline attempt against the same target (see notes). 3 another "
            "process currently holds the local operation lock. 4 a prior operation's journal/lock state "
            "requires human recovery attention before a new bootstrap may start -- see "
            "'restart_decision'. 5 local journal/lock/custody-artifact state is corrupt or internally "
            "inconsistent. 6 the environment/configuration itself was rejected before any lock or "
            "journal was touched (missing/invalid variable, insecure file permissions, a schema that is "
            "not fully source-cross-checked, etc.).\n\n"
            "When a prior journal exists for the same target/account/profile, this command "
            "automatically attempts one fresh, read-only live observation (GET-only; never a mutation) "
            "of the account's actual current state before classifying the restart. Only an exact match "
            "against every expected binding field resolves to a clean, already-complete restart; a "
            "failed, inconclusive, or mismatched observation is still conservatively treated as "
            "requiring recovery attention -- the journal alone is never sufficient evidence of "
            "completion. See `security_bootstrap_orchestration.build_authoritative_restart_observation()` "
            "for the exact fail-closed construction.\n\n"
            "Never prints, logs, or serializes an API key, password, or any other secret value. A "
            "freshly generated service-account key is written only to the owner-only "
            "PFSENSE_SERVICE_API_KEY_FILE custody path."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    bootstrap_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    recover_parser = subparsers.add_parser(
        "recover",
        help=(
            "ADR-033 recovery-execution orchestration: inspect, and only with an explicit --execute "
            "plus the exact confirmation token, execute one of the two closed recovery actions. "
            "Standalone -- inspection path verified offline and live (LAB, 2026-08-26); --execute "
            "verified offline only."
        ),
        description=(
            "Default (no flags): read-only inspection only. Classifies the existing bootstrap "
            "incident, and if recovery is required, reports the exact action needed, the affected "
            "object, and prints a confirmation token bound to this exact target/action/object/incident. "
            "Makes no pfSense mutation. Execution requires BOTH --execute <ACTION> and --confirm "
            "<TOKEN> (or --confirm - to read the token from stdin) -- a token from a stale, "
            "cross-target, cross-object, cross-action, or different-incident inspection is refused "
            "before any mutating HTTP call. Reuses the already-implemented, already-reviewed "
            "revoke_failed_bootstrap_api_key()/delete_dedicated_recovery_user() primitives verbatim -- "
            "this command sequences them, never reimplements their HTTP/verification logic. "
            "Standalone -- not folded into `bootstrap` or a future `setup` wizard. Configured entirely "
            "through the same PFSENSE_*/PFSENSE_ADMIN_* environment variables `bootstrap` already uses."
        ),
        epilog=(
            "Exit codes: 0 no recovery needed, already recorded complete, or execution succeeded and "
            "verified. 1 recovery is needed and was reported (inspection only, not yet executed) -- "
            "not an error, distinguished from 0 so a monitoring script can alert on it. 2 --execute "
            "does not match the action this incident actually requires -- refused before any HTTP "
            "call. 3 another operation holds the recovery-typed lock. 4 the environment/configuration "
            "itself was rejected before any lock or journal was touched. 5 execution was attempted "
            "(all gates passed) and the underlying recovery primitive failed -- no mutation was "
            "performed, per that primitive's own fail-closed contract; the lock is held pending manual "
            "review. 6 the confirmation token is missing, malformed, or does not match the current "
            "target/action/object/incident -- refused before any HTTP call. 7 the read-only "
            "candidate-identification read found zero or more than one matching object. 8 a prior "
            "recovery attempt for this incident is itself in a non-terminal state (crashed, ambiguous, "
            "or otherwise incomplete) -- no automatic retry is ever attempted; manual review is "
            "required. 9 local recovery journal/lock state is corrupt or unauthenticated.\n\n"
            "Never executes merely because recovery is required: execution always requires the "
            "explicit --execute and a fresh, currently-valid --confirm token together. Never prints, "
            "logs, or serializes an API key, password, or any other secret value -- the confirmation "
            "token is a derived confirmation artifact, not a credential."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    recover_parser.add_argument(
        "--execute",
        choices=[action.value for action in RecoveryAction],
        default=None,
        metavar="ACTION",
        help=(
            "Execute the named recovery action. Requires --confirm. Refused before any HTTP call if it "
            "does not match the action this incident currently requires."
        ),
    )
    recover_parser.add_argument(
        "--confirm",
        default=None,
        metavar="TOKEN",
        help=(
            "The exact confirmation token a prior inspection printed for this action. Pass '-' to read "
            "it from stdin instead of the command line. Required together with --execute."
        ),
    )
    recover_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    setup_parser = subparsers.add_parser(
        "setup",
        help=(
            "Guided, non-mutating discovery + plan-only setup wizard. Bare `setup` never mutates "
            "pfSense state, never provisions anything, never executes -- produces a reviewable "
            "SetupPlan only. `setup apply` (a wholly separate, explicit command; supports both "
            "read_only and write_protected postures) is never reachable from this flow -- see "
            "`setup apply --help`."
        ),
        description=(
            "DISCOVER -> (interactively, or via flags) SELECT TARGET/POSTURE/ANCHOR -> GENERATE SETUP "
            "PLAN, then stop. Composes the already-implemented `discover`/`plan` machinery plus ADR-033 "
            "account/privilege content -- never a second, independent implementation of either. "
            "Interactive by default (prompts for anything not supplied via flags, and every prompt may "
            "be left blank to skip it); pass --non-interactive for deterministic, prompt-free "
            "automation (requires --capability-posture and --anchor-assurance)."
        ),
        epilog=(
            "Exit codes: 0 a plan was generated, including 'already satisfied' and 'valid target but "
            "not yet implemented' -- neither is a usage error, the same convention `plan` already uses. "
            "2 the requested target combination is invalid, or the current state shows a detected "
            "anomaly or indeterminate evidence -- the same meaning `plan`'s own exit code 2 already "
            "has. 3 interactive prompting was abandoned (EOF, or the operator gave no value for a "
            "required prompt) before a plan could be generated -- nothing was planned, nothing was "
            "mutated.\n\n"
            "This command NEVER mutates pfSense state and NEVER provisions, activates, deactivates, "
            "generates a secret, or writes MCP client configuration, in every mode, always -- selecting "
            "a target here is intent for a human to review, not execution authorization. There is no "
            "'continue and apply' path from this command: applying a plan (a future, separately "
            "authorized slice) will always be a wholly separate, explicit invocation, never a "
            "continuation of this one.\n\n"
            "Never performs a live network call of any kind -- --schema-file, if given, is read from "
            "local disk only, never fetched. If a previous `pfsense-mcp-security bootstrap` attempt may "
            "have failed and left RECOVERY_REQUIRED state, this command does not detect it -- run "
            "`pfsense-mcp-security recover` directly to inspect."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    setup_parser.add_argument(
        "--non-interactive",
        action="store_true",
        help="Never prompt; every required value must be supplied via flags.",
    )
    setup_parser.add_argument(
        "--capability-posture",
        choices=_CAPABILITY_POSTURE_CHOICES,
        default=None,
        help="Target capability-posture axis value. Prompted for if omitted and interactive.",
    )
    setup_parser.add_argument(
        "--anchor-assurance",
        choices=_ANCHOR_ASSURANCE_CHOICES,
        default=None,
        help="Target anchor-assurance axis value. Prompted for if omitted and interactive.",
    )
    setup_parser.add_argument(
        "--target-origin",
        default=None,
        help="pfSense target origin (e.g. a base URL), recorded exactly as entered -- never verified by this slice.",
    )
    setup_parser.add_argument(
        "--target-identity",
        default=None,
        help="A human-meaningful label for the target, recorded exactly as entered.",
    )
    setup_parser.add_argument(
        "--tls-mode",
        choices=["verify", "verify_private_ca", "insecure"],
        default=None,
        help="Declared TLS intent, recorded exactly as entered -- never verified by this slice.",
    )
    setup_parser.add_argument(
        "--tls-ca-file",
        default=None,
        metavar="PATH",
        help=(
            "Optional, purely-informational path to your private CA's certificate -- only used to "
            "personalize the generated MCP client configuration preview when --tls-mode is "
            "verify_private_ca; never read, validated, or sent anywhere by this slice."
        ),
    )
    setup_parser.add_argument(
        "--api-key-file",
        default=None,
        metavar="PATH",
        help=(
            "Optional, purely-informational path to your pfSense API key file -- only used to "
            "personalize the generated MCP client configuration preview instead of showing an "
            "illustrative placeholder; never read, validated, or sent anywhere by this slice."
        ),
    )
    setup_parser.add_argument(
        "--command",
        dest="command_override",
        default=None,
        metavar="PATH",
        help=(
            "Override the auto-detected pfsense-mcp-server executable path shown in the generated "
            "MCP client configuration -- only needed if you are generating this configuration for a "
            "different machine than the one running this command."
        ),
    )
    setup_parser.add_argument(
        "--schema-file",
        default=None,
        metavar="PATH",
        help=(
            "Optional local path to a previously-saved pfSense OpenAPI schema JSON file. Read from "
            "local disk only -- never fetched over the network by this slice."
        ),
    )
    setup_parser.add_argument(
        "--declared-package-version",
        default=None,
        metavar="X.Y.Z",
        help="Optional, manually-declared pfSense-restapi package version. Never probed live by this slice.",
    )
    setup_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    setup_subparsers = setup_parser.add_subparsers(dest="setup_action")

    init_confirm_key_parser = setup_subparsers.add_parser(
        "init-confirm-key",
        help=(
            "Guided, one-time local provisioning of PFSENSE_SETUP_CONFIRM_KEY_FILE -- the local "
            "secret both `setup apply` and `setup write-client-config` require. Never touches pfSense."
        ),
        description=(
            "Generates a fresh, cryptographically random local key and writes it to a safe default "
            "path (override with --path), owner-only permissions, refusing to follow a symlink or "
            "overwrite an existing key. This key is never sent to pfSense and is not a pfSense "
            "credential -- it is used only to bind a `setup apply`/`setup write-client-config` "
            "confirmation token to the exact plan/target/posture you were shown, so a stale or "
            "copy-pasted command cannot reach a live pfSense call or local file write by accident. "
            "Safe to run again later: an existing key is always left untouched, never rotated or "
            "overwritten -- doing so would invalidate any --confirm token you have not yet redeemed."
        ),
        epilog=(
            "Exit codes: 0 a key now exists at the printed path (freshly created, or one already "
            "there from a prior run -- both are the safe, expected outcome). 1 the target path is a "
            "symbolic link -- refused before touching it. 2 the key could not be created safely (e.g. "
            "the parent directory could not be created, or this platform lacks O_NOFOLLOW support).\n\n"
            "Never prints, logs, or serializes the key's own value -- only its file path."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    init_confirm_key_parser.add_argument(
        "--path",
        default=None,
        metavar="PATH",
        help=f"Override the default key path ({DEFAULT_CONFIRM_KEY_FILE}).",
    )
    init_confirm_key_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    apply_parser = setup_subparsers.add_parser(
        "apply",
        help=(
            "Apply a read_only or write_protected plan. read_only verifies live connectivity using "
            "the operator's existing runtime credentials -- never a mutation. write_protected "
            "composes the existing `bootstrap` command to provision the one fixed ADR-033 service "
            "account -- never a new, independent mutating primitive."
        ),
        description=(
            "Recomputes the plan fresh from current state, refuses if it does not match --plan-digest "
            "(the state you reviewed has changed), refuses if --confirm does not match the exact "
            "plan/target/posture, and only then acts. For read_only: one read-only connectivity check "
            "against the pfSense target configured via the normal runtime PFSENSE_API_URL/"
            "PFSENSE_IDENTITY/PFSENSE_API_KEY_FILE/PFSENSE_TLS_* environment variables -- the exact "
            "same configuration the MCP server itself would use to start. For write_protected: composes "
            "`pfsense-mcp-security bootstrap`'s own orchestration to provision (or verify/repair) the "
            "dedicated least-privilege service account, using the same ADR-033 administrative "
            "environment variables standalone `bootstrap` already requires; for anchor_assurance="
            "hardware_witness, `doctor` must report ready before this call is ever made. A prior "
            "incomplete/failed bootstrap for this target/account/profile is refused (exit 9) and points "
            "at `pfsense-mcp-security recover` -- never bypassed, retried, or resolved automatically. "
            "Omitting --confirm (or --plan-digest) performs inspection only: it shows the current plan "
            "and the exact token a real apply would need, without touching pfSense at all."
        ),
        epilog=(
            "Exit codes: 0 apply completed (read_only: connectivity verified, nothing changed; "
            "write_protected: the ADR-033 service account is now provisioned or was already so). "
            "1 inspection only -- the plan is current and a confirmation token was shown, but --confirm "
            "was not supplied, so nothing was applied. 2 the recomputed plan digest does not match "
            "--plan-digest -- current state has changed since the plan was reviewed; refused before the "
            "confirmation token is even considered. 3 --confirm does not match this exact "
            "plan/target/posture -- refused before any pfSense contact. 5 the environment/configuration "
            "itself was rejected before any pfSense contact (missing/invalid PFSENSE_* variable, "
            "missing/invalid PFSENSE_SETUP_CONFIRM_KEY_FILE, insecure file permissions). 6 the one "
            "read-only connectivity check failed (read_only only). 7 `doctor` reports the requested "
            "hardware-witness anchor is not ready -- checked after connectivity for read_only, checked "
            "before any bootstrap call for write_protected. 8 another process holds the local ADR-033 "
            "operation lock (write_protected only). 9 a prior bootstrap attempt for this target/account/"
            "profile requires recovery before a new one may start (write_protected only) -- "
            "RECOVERY_REQUIRED, surfaced faithfully, never bypassed: a read-only recovery inspection "
            "(the exact same one bare `pfsense-mcp-security recover` performs) is run inline and its "
            "own recovery_action/confirmation_token are shown, but only the operator's own separate "
            "`pfsense-mcp-security recover --execute <ACTION> --confirm <TOKEN>` invocation can ever "
            "resolve it -- this command never supplies that token itself. 10 local ADR-033 journal/"
            "lock/custody state is corrupt or untrusted (write_protected only). 11 the engine refused "
            "before any HTTP call -- unsupported package version, or privilege derivation not fully "
            "source-cross-checked (write_protected only; proven zero network activity, but still "
            "requires human review before retrying). 12 the engine ran and did not reach a verified "
            "successful state (write_protected only); local state is held for human review.\n\n"
            "Never introduces a second mutating primitive: the only pfSense contact for read_only is "
            "one read-only GET; the only things write_protected ever composes are the exact same "
            "`run_bootstrap_from_environment()` standalone `bootstrap` already calls and (inspection "
            "only, exit 9) the exact same `run_recovery_from_environment()` standalone `recover` "
            "already calls, made only after the confirmation token has already been verified.\n\n"
            "Never prints, logs, or serializes an API key, password, journal-integrity key, or any "
            "other secret value -- the confirmation token and the recovery confirmation token are both "
            "derived confirmation artifacts, not credentials."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    apply_parser.add_argument(
        "--capability-posture",
        choices=_CAPABILITY_POSTURE_CHOICES,
        required=True,
        help="The exact target capability-posture axis value the plan being applied was generated for.",
    )
    apply_parser.add_argument(
        "--anchor-assurance",
        choices=_ANCHOR_ASSURANCE_CHOICES,
        required=True,
        help="The exact target anchor-assurance axis value the plan being applied was generated for.",
    )
    apply_parser.add_argument("--target-origin", default=None, help="Must match the value `setup` recorded.")
    apply_parser.add_argument("--target-identity", default=None, help="Must match the value `setup` recorded.")
    apply_parser.add_argument(
        "--tls-mode",
        choices=["verify", "verify_private_ca", "insecure"],
        default=None,
        help="Must match the value `setup` recorded.",
    )
    apply_parser.add_argument(
        "--plan-digest",
        default=None,
        metavar="DIGEST",
        help="The plan digest printed by a prior `setup`/`setup --non-interactive` run. Omit for inspection only.",
    )
    apply_parser.add_argument(
        "--confirm",
        default=None,
        metavar="TOKEN",
        help=(
            "The exact confirmation token a prior inspection printed for this plan. Pass '-' to read it "
            "from stdin instead of the command line. Omit for inspection only, unless "
            f"{_SETUP_APPLY_CONFIRM_TOKEN_ENV_VAR} is set (checked only when this flag is omitted "
            "entirely; an explicit --confirm always wins) -- the CI-friendly way to supply it without "
            "shell history/process-list exposure when piping to stdin is impractical."
        ),
    )
    apply_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    write_client_config_parser = setup_subparsers.add_parser(
        "write-client-config",
        help=(
            "Phase C: write the MCP client configuration snippet Slice 6 already prints to a real "
            "client config file, merge-only. Off by default -- requires its own explicit --confirm, "
            "separate from any pfSense-side confirmation. Never a whole-file replacement."
        ),
        description=(
            "Computes the exact same command/env values `setup`'s own print-only summary already "
            "shows, merges only the `pfsense` server entry into the target client's config file "
            "(creating it if absent), and refuses to touch a malformed existing file. Requires a "
            "fresh --confirm token bound to the client, the exact config path, the current plan, and "
            "the exact current on-disk content -- a file that changed since inspection, or a wrong "
            "client/path, is refused by the binding itself, the same way a stale pfSense plan is "
            "refused by `setup apply`. Backs up an existing file to <path>.bak (exclusive create -- "
            "refuses if a backup from a prior interrupted attempt already exists) before an atomic "
            "write, then reads the result back and restores the backup if it does not match exactly."
        ),
        epilog=(
            "Exit codes: 0 the file was written (or created). 1 inspection only -- the proposed diff "
            "and a confirmation token were shown, but --confirm was not supplied. 2 the recomputed "
            "plan digest does not match --plan-digest -- current pfSense-side plan state has changed "
            "since the plan was reviewed. 3 --confirm does not match this exact client/path/plan/"
            "current-file-state -- refused before any file was touched (this also catches the file "
            "having changed on disk since inspection). 4 the environment/configuration itself was "
            "rejected (missing/invalid PFSENSE_* variable, missing/invalid "
            "PFSENSE_SETUP_CONFIRM_KEY_FILE, claude-desktop's --config-path omitted -- it has no "
            "documented default). 5 the existing file at the target path is not valid "
            "JSON/TOML for its client -- refused before any write, never partially repaired. 6 the "
            "target path is unsafe (a symbolic link, not a regular file, or not owned by the current "
            "user). 7 the file was written but did not read back exactly as intended -- the original "
            "was restored (or the new file removed, if none existed before); no lasting change was "
            "made.\n\n"
            "Never a whole-file replacement, ever: only the `mcp_servers.pfsense`/`mcpServers.pfsense` "
            "entry is added or updated; every other server, table, and setting in the file is "
            "preserved. Never makes a pfSense network call -- this command only ever touches a local "
            "application-configuration file on this machine.\n\n"
            "Never prints, logs, or serializes an API key, password, journal-integrity key, or any "
            "other secret value -- the confirmation token is a derived confirmation artifact, not a "
            "credential, and the generated snippet itself never contains a live secret value, only a "
            "key-file *path* placeholder."
        ),
        formatter_class=_ParagraphHelpFormatter,
    )
    write_client_config_parser.add_argument(
        "--client",
        choices=["claude-desktop", "codex"],
        required=True,
        help="Which client's config format/location to write. 'codex' also covers the ChatGPT desktop "
        "app, which shares Codex CLI's own config file.",
    )
    write_client_config_parser.add_argument(
        "--config-path",
        default=None,
        metavar="PATH",
        help="Absolute override path. Required for claude-desktop (no documented default in this "
        "project's own examples). Optional for codex (defaults to ~/.codex/config.toml).",
    )
    write_client_config_parser.add_argument(
        "--capability-posture",
        choices=_CAPABILITY_POSTURE_CHOICES,
        required=True,
        help="The exact target capability-posture axis value the plan being applied was generated for.",
    )
    write_client_config_parser.add_argument(
        "--anchor-assurance",
        choices=_ANCHOR_ASSURANCE_CHOICES,
        required=True,
        help="The exact target anchor-assurance axis value the plan being applied was generated for.",
    )
    write_client_config_parser.add_argument(
        "--target-origin", default=None, help="Must match the value `setup` recorded."
    )
    write_client_config_parser.add_argument(
        "--target-identity", default=None, help="Must match the value `setup` recorded."
    )
    write_client_config_parser.add_argument(
        "--tls-mode",
        choices=["verify", "verify_private_ca", "insecure"],
        default=None,
        help="Must match the value `setup` recorded.",
    )
    write_client_config_parser.add_argument(
        "--tls-ca-file",
        default=None,
        metavar="PATH",
        help=(
            "Path to your private CA's certificate, written verbatim into the generated "
            "PFSENSE_TLS_CA_FILE value when --tls-mode is verify_private_ca. Never read or validated "
            "by this command -- only the path string is used."
        ),
    )
    write_client_config_parser.add_argument(
        "--api-key-file",
        default=None,
        metavar="PATH",
        help=(
            "Path to your pfSense API key file, written verbatim into the generated "
            "PFSENSE_API_KEY_FILE value instead of an illustrative placeholder. Never read or "
            "validated by this command -- only the path string is used."
        ),
    )
    write_client_config_parser.add_argument(
        "--command",
        dest="command_override",
        default=None,
        metavar="PATH",
        help=(
            "Override the auto-detected pfsense-mcp-server executable path written into the client "
            "config file -- only needed if this file is being generated for a different machine than "
            "the one running this command."
        ),
    )
    write_client_config_parser.add_argument(
        "--plan-digest",
        default=None,
        metavar="DIGEST",
        help="The plan digest printed by a prior `setup`/`setup --non-interactive` run. Omit for inspection only.",
    )
    write_client_config_parser.add_argument(
        "--confirm",
        default=None,
        metavar="TOKEN",
        help=(
            "The exact confirmation token a prior inspection printed for this client/path/plan/"
            "file-state. Pass '-' to read it from stdin instead of the command line. Omit for "
            "inspection only."
        ),
    )
    write_client_config_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    return parser


def _run_discover(*, as_json: bool, env: dict[str, str] | None, out: TextIO) -> int:
    discovery = discover_security_posture(env)
    if as_json:
        print(json.dumps(_discovery_to_dict(discovery), indent=2, sort_keys=True), file=out)
    else:
        print(_format_human(discovery), file=out)
    if discovery.anchor_assurance.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH:
        return _MISMATCH_EXIT_CODE
    return 0


def _run_plan(
    *, capability_posture: str, anchor_assurance: str, as_json: bool, env: dict[str, str] | None, out: TextIO
) -> int:
    plan = generate_security_posture_plan(
        CapabilityPosture(capability_posture),
        AnchorAssurance(anchor_assurance),
        env,
    )
    if as_json:
        print(json.dumps(_plan_to_dict(plan), indent=2, sort_keys=True), file=out)
    else:
        print(_format_plan_human(plan), file=out)
    if plan.overall_status in (
        PlanOverallStatus.BLOCKED_INVALID_TARGET,
        PlanOverallStatus.BLOCKED_ANOMALY_DETECTED,
        PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE,
    ):
        return _BLOCKED_TARGET_EXIT_CODE
    return 0


def _run_doctor(*, as_json: bool, env: dict[str, str] | None, out: TextIO) -> int:
    result = run_doctor_checks(env)
    posture = discover_capability_posture(env)
    if as_json:
        print(json.dumps(_doctor_result_to_dict(result, posture), indent=2, sort_keys=True), file=out)
    else:
        print(_format_doctor_human(result, posture), file=out)
    return 0 if result.ready else _DOCTOR_NOT_READY_EXIT_CODE


def _run_bootstrap(*, as_json: bool, env: dict[str, str] | None, out: TextIO) -> int:
    result = run_bootstrap_from_environment(env)
    if as_json:
        print(json.dumps(_bootstrap_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_bootstrap_human(result), file=out)
    return _BOOTSTRAP_EXIT_CODES[result.outcome]


def _run_recover(
    *,
    execute: str | None,
    confirm: str | None,
    as_json: bool,
    env: dict[str, str] | None,
    out: TextIO,
    in_: TextIO,
) -> int:
    execute_action = RecoveryAction(execute) if execute is not None else None
    # '-' reads the token from stdin rather than the command line/process
    # argv (visible in shell history and to other local processes via
    # /proc) -- the token is not a secret credential, but this keeps
    # controlled-automation use consistent with how this codebase already
    # prefers file/stdin-sourced input over inline secrets elsewhere.
    confirm_token = in_.readline().rstrip("\n") if confirm == "-" else confirm
    result = run_recovery_from_environment(env, execute_action=execute_action, confirm_token=confirm_token)
    if as_json:
        print(json.dumps(_recover_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_recover_human(result), file=out)
    return _RECOVERY_EXIT_CODES[result.outcome]


def _target_to_dict(target: TargetDescriptor) -> dict[str, Any]:
    return {
        "origin": target.origin,
        "identity": target.identity,
        "tls_mode": target.tls_mode,
        "reachability_verified": target.reachability_verified,
    }


def _privilege_plan_to_dict(privilege_plan: PrivilegePlan) -> dict[str, Any]:
    return {
        "intended_capability_posture": privilege_plan.intended_capability_posture.value,
        "intended_account_identity": privilege_plan.intended_account_identity,
        "dedicated_account_provisioning_implemented": privilege_plan.dedicated_account_provisioning_implemented,
        "provisioning_note": privilege_plan.provisioning_note,
        "schema_provided": privilege_plan.schema_provided,
        "required_privileges": (
            list(privilege_plan.required_privileges) if privilege_plan.required_privileges is not None else None
        ),
        "unresolved_requirement_tool_names": list(privilege_plan.unresolved_requirement_tool_names),
    }


def _version_evidence_to_dict(version_evidence: VersionEvidence) -> dict[str, Any]:
    return {
        "schema_provided": version_evidence.schema_provided,
        "declared_package_version": version_evidence.declared_package_version,
        "package_version_supported": version_evidence.package_version_supported,
        "version_note": version_evidence.version_note,
    }


#: Slice 6 (`reports-ai/SETUP_WIZARD_DESIGN_2026-08-23.md` §14):
#: print-only MCP client configuration generation.
#:
#: v1.0.0 clean-room finding (2026-08-28): a real pipx install/setup
#: journey found that a hardcoded `.venv/bin/...` command placeholder
#: is actively wrong once pipx (this project's own recommended install
#: method) is used -- pipx installs into a per-package venv whose path
#: has nothing to do with any project checkout. `_resolve_mcp_client_command()`
#: below now resolves the real, currently-installed sibling executable
#: at generation time instead of assuming a fixed illustrative path;
#: this placeholder remains only as the last-resort fallback when that
#: resolution genuinely cannot find one (e.g. running from an unpacked
#: source checkout that was never actually installed).
_MCP_CLIENT_COMMAND_PLACEHOLDER = "/absolute/path/to/pfsense-mcp-server/.venv/bin/pfsense-mcp-server"
_MCP_CLIENT_ORIGIN_PLACEHOLDER = "https://pfsense.example.invalid"
_MCP_CLIENT_IDENTITY_PLACEHOLDER = "api-mcp-admin"
_MCP_CLIENT_KEY_FILE_PLACEHOLDER = "/absolute/private/path/pfsense-api.key"
_MCP_CLIENT_CA_FILE_PLACEHOLDER = "/absolute/path/to/your-private-ca.crt"


@dataclass(frozen=True)
class _MCPClientHints:
    """Operator-declared, purely-informational values used only to
    personalize the generated MCP client configuration preview/write.
    Never validated (no file is ever opened by this dataclass or its
    callers), never part of `SetupPlan` or its digest -- the same
    "declared intent, never verified" discipline `generate_setup_plan()`
    already applies to `target.origin`/`target.identity`. `ca_file` is
    only ever rendered when the plan's own `tls_mode` is
    `verify_private_ca`; `command_override` always wins over
    auto-detection when given (see `_resolve_mcp_client_command()`).
    `api_key_file`: v1.0.0 clean-room finding (2026-08-29) -- a real
    `setup apply` -> `setup write-client-config` walkthrough found the
    generated config always wrote the illustrative placeholder path
    even when the operator's own already-working `PFSENSE_API_KEY_FILE`
    was sitting right there in their environment; mirrors `ca_file`'s
    own flag-only, never-validated personalization exactly."""

    ca_file: str | None = None
    command_override: str | None = None
    api_key_file: str | None = None


_EMPTY_MCP_CLIENT_HINTS = _MCPClientHints()


def _resolve_mcp_client_command(override: str | None = None) -> tuple[str, bool]:
    """Returns `(command_path, is_a_real_usable_path)`. An explicit
    `override` (from `--command`) always wins and is always trusted --
    it is never re-detected or second-guessed.

    Otherwise, resolves the real, currently-installed `pfsense-mcp-server`
    executable colocated with the currently-running `pfsense-mcp-security`
    -- both are declared as `[project.scripts]` in the same package, so
    they are always installed into the very same environment's `bin/`
    directory together, regardless of install method (`pipx`, a plain
    `venv` + `pip`, or `uv tool install`): this is a structural packaging
    guarantee, not a runtime coincidence, and it is exactly the directory
    `sys.executable` (the interpreter running *this* process) lives in.
    Falls back to `shutil.which()` for the unusual case of a
    non-colocated PATH-based install, and only falls back to the
    illustrative placeholder if neither resolves to a real file -- e.g.
    running directly from an unpacked source checkout that was never
    actually installed."""

    if override:
        return override, True
    candidate = Path(sys.executable).with_name("pfsense-mcp-server")
    if candidate.is_file():
        return str(candidate), True
    found = shutil.which("pfsense-mcp-server")
    if found:
        return found, True
    return _MCP_CLIENT_COMMAND_PLACEHOLDER, False


def _mcp_client_tls_mode(plan: SetupPlan) -> str:
    """Translates `setup`'s own wizard-facing `--tls-mode` vocabulary
    (`verify`/`verify_private_ca`/`insecure`) into the real runtime
    `PfSenseConfig`/`TLSMode` vocabulary (`strict`/`auto`/`insecure`)
    the generated snippet must actually be valid for -- these are
    deliberately different vocabularies, so this is a real translation,
    not a pass-through."""

    if plan.target.tls_mode == "insecure":
        return "insecure"
    if plan.target.tls_mode == "verify_private_ca":
        return "auto"
    return "strict"


def _mcp_client_env_vars(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> dict[str, str]:
    """The `PFSENSE_*` values shared verbatim by every documented
    client format (`examples/claude-desktop.md`'s JSON, and
    `examples/codex-cli.md`/`examples/chatgpt.md`'s shared TOML) --
    computed once so the JSON and TOML snippet builders never drift
    against each other. For `write_protected`, the identity is the
    fixed ADR-033 service account (`INTENDED_SERVICE_ACCOUNT_IDENTITY`)
    -- once `setup apply`/`bootstrap` actually provisions it, that is
    the correct least-privilege identity for the MCP server's own
    runtime credential; suggesting the *administrator* identity used to
    provision it would be exactly the privilege-escalation mistake
    ADR-033 exists to prevent. For `read_only` (bring-your-own-key),
    the operator's own entered identity is used instead, since no
    dedicated account is ever provisioned for that posture."""

    posture = plan.privilege_plan.intended_capability_posture
    identity = (
        INTENDED_SERVICE_ACCOUNT_IDENTITY
        if posture is CapabilityPosture.WRITE_PROTECTED
        else (plan.target.identity or _MCP_CLIENT_IDENTITY_PLACEHOLDER)
    )
    env: dict[str, str] = {
        "PFSENSE_API_URL": plan.target.origin or _MCP_CLIENT_ORIGIN_PLACEHOLDER,
        "PFSENSE_IDENTITY": identity,
        "PFSENSE_API_KEY_FILE": hints.api_key_file or _MCP_CLIENT_KEY_FILE_PLACEHOLDER,
        "PFSENSE_TLS_MODE": _mcp_client_tls_mode(plan),
    }
    # v1.0.0 clean-room finding (2026-08-28): a real private-CA pfSense
    # LAB target found this env var was never generated at all --
    # `setup`'s own TLS choice had no way to express "verify against a
    # private CA" in the first place. Only ever added when that's the
    # declared intent; `hints.ca_file`, if given, is purely
    # operator-declared and never read/validated by this function.
    if plan.target.tls_mode == "verify_private_ca":
        env["PFSENSE_TLS_CA_FILE"] = hints.ca_file or _MCP_CLIENT_CA_FILE_PLACEHOLDER
    return env


def _mcp_client_config_snippet(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> dict[str, Any]:
    """The exact `mcpServers` block `examples/claude-desktop.md`
    already documents. Print-only, forever the default (owner decision
    8) -- `setup` never writes this to any file."""

    command, _ = _resolve_mcp_client_command(hints.command_override)
    return {
        "mcpServers": {
            "pfsense": {
                "command": command,
                "env": _mcp_client_env_vars(plan, hints),
            }
        }
    }


def _toml_escape_string(value: str) -> str:
    """Minimal, correct TOML basic-string escaping -- backslash,
    double-quote, and the standard short control-character escapes;
    every other control character falls back to `\\u00XX`. Operator-
    entered `target.identity`/`target.origin` values are untrusted
    input to this function, not just the fixed placeholders."""

    escapes = {"\\": "\\\\", '"': '\\"', "\b": "\\b", "\t": "\\t", "\n": "\\n", "\f": "\\f", "\r": "\\r"}
    result = []
    for character in value:
        if character in escapes:
            result.append(escapes[character])
        elif ord(character) < 0x20 or ord(character) == 0x7F:
            result.append(f"\\u{ord(character):04x}")
        else:
            result.append(character)
    return "".join(result)


def _mcp_client_config_toml(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> str:
    """The exact `[mcp_servers.pfsense]` TOML table
    `examples/codex-cli.md` already documents, shared verbatim by the
    ChatGPT desktop app per `examples/chatgpt.md` ("the desktop app,
    Codex CLI, and Codex IDE extension share that configuration on the
    same host"). Deliberately a *different* format from
    `_mcp_client_config_snippet()`'s own JSON `mcpServers` block, not a
    reformatting of it -- Claude Desktop's config is JSON, Codex/
    ChatGPT's is TOML, and printing JSON for the latter two would be
    unusable as-is. Same env values either way, via
    `_mcp_client_env_vars()`. Print-only, forever the default (owner
    decision 8) -- `setup` never writes this to any file."""

    command, _ = _resolve_mcp_client_command(hints.command_override)
    env_vars = _mcp_client_env_vars(plan, hints)
    lines = [
        "[mcp_servers.pfsense]",
        f'command = "{_toml_escape_string(command)}"',
        "required = true",
        "",
        "[mcp_servers.pfsense.env]",
    ]
    lines.extend(f'{key} = "{_toml_escape_string(value)}"' for key, value in env_vars.items())
    return "\n".join(lines)


def _setup_plan_to_dict(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> dict[str, Any]:
    _, command_resolved = _resolve_mcp_client_command(hints.command_override)
    return {
        "schema_version": plan.schema_version,
        "target": _target_to_dict(plan.target),
        "posture_plan": _plan_to_dict(plan.posture_plan),
        "privilege_plan": _privilege_plan_to_dict(plan.privilege_plan),
        "version_evidence": _version_evidence_to_dict(plan.version_evidence),
        "planned_local_artifacts": list(plan.planned_local_artifacts),
        "planned_pfsense_actions": list(plan.planned_pfsense_actions),
        "planned_postconditions": list(plan.planned_postconditions),
        "unsupported_steps": list(plan.unsupported_steps),
        "notes": list(plan.notes),
        # Mirrors `plan`'s own "plan_digest" field exactly: plan identity
        # only -- never authorization. See security_setup_plan_digest.py's
        # own module docstring.
        "setup_plan_digest": compute_setup_plan_digest(plan),
        "setup_plan_digest_schema_version": SETUP_PLAN_DIGEST_SCHEMA_VERSION,
        # Slice 6: always present, always print-only -- never written to
        # any file by this codebase. See _mcp_client_config_snippet()'s
        # own docstring for exactly what is (and is not) populated.
        # JSON form for Claude Desktop; the TOML form (Codex CLI/ChatGPT
        # desktop, a genuinely different config format, not a
        # reformatting of the JSON one) is a plain string since JSON
        # cannot represent TOML syntax natively.
        "mcp_client_config": _mcp_client_config_snippet(plan, hints),
        "mcp_client_config_toml": _mcp_client_config_toml(plan, hints),
        # v1.0.0 clean-room finding: whether "command" above was
        # actually auto-detected/explicitly overridden (True) or is the
        # illustrative placeholder because neither resolved to a real
        # file (False) -- lets an automation consumer of --json decide
        # whether to trust it verbatim.
        "mcp_client_command_resolved": command_resolved,
    }


_STATUS_WORD_READY = "Ready"
_STATUS_WORD_NEEDS_ATTENTION = "Needs attention"
_STATUS_WORD_NOT_AVAILABLE_YET = "Not available yet"

_STATUS_MARKERS = {
    _STATUS_WORD_READY: "✓ Ready",
    _STATUS_WORD_NEEDS_ATTENTION: "! Needs attention",
    _STATUS_WORD_NOT_AVAILABLE_YET: "○ Not available yet",
}


def _human_status_word(plan: SetupPlan) -> str:
    status = plan.posture_plan.overall_status
    if status in (PlanOverallStatus.ALREADY_SATISFIED, PlanOverallStatus.PLAN_GENERATED):
        return _STATUS_WORD_READY
    if status is PlanOverallStatus.BLOCKED_NOT_IMPLEMENTED:
        return _STATUS_WORD_NOT_AVAILABLE_YET
    return _STATUS_WORD_NEEDS_ATTENTION


def _human_mode_label(plan: SetupPlan) -> str:
    if plan.privilege_plan.intended_capability_posture is CapabilityPosture.READ_ONLY:
        return "Read-only"
    return "Protected write"


def _human_connection_label(plan: SetupPlan) -> str:
    if plan.target.tls_mode == "insecure":
        return "Skip TLS verification (not recommended)"
    if plan.target.tls_mode == "verify":
        return "Verify TLS certificate"
    if plan.target.tls_mode == "verify_private_ca":
        return "Verify TLS certificate (private/internal certificate authority)"
    return "Not specified"


#: How many leading hex characters of the full plan digest to show in
#: human-mode output -- a short, glanceable Plan ID, never the
#: authoritative identity value itself. The full, authoritative digest
#: (`compute_setup_plan_digest(plan)`, unabridged) remains available
#: via `--json` and is never computed differently or weakened by this
#: truncation -- this constant only controls how many of its own
#: leading characters this file's human-mode formatter chooses to
#: print.
_HUMAN_PLAN_ID_LENGTH = 12


#: v1.0.0 clean-room finding (2026-08-28): a real read-only pfSense LAB
#: journey found that nothing in this command's own output ever
#: explained that `setup apply`'s one connectivity check reads its
#: pfSense connection details from the operator's real shell
#: environment -- the *exact same* `PFSENSE_*` variables the MCP server
#: itself reads at startup -- not from anything `setup` collected
#: interactively. An operator who only ever answered the wizard's
#: questions had no way to know they still needed to `export` these
#: themselves before the printed `setup apply` command could succeed.
def _credential_guidance_lines() -> tuple[str, ...]:
    """How to obtain and safely store the pfSense API key
    `PFSENSE_API_KEY_FILE` must point at. Mirrors
    docs/INSTALLATION.md's own "Obtain and configure a credential
    safely" section verbatim in substance (same recipe, same
    permissions requirement) so this project never gives two different
    answers to the same question. Never prints, requests, or implies
    typing the key value itself anywhere -- only the file *path* is
    ever part of this guidance."""

    return (
        "Need an API key? In pfSense, under the REST API package's own",
        "user/key management, generate one for the identity above (or",
        "reuse an existing key for that identity if you already have",
        "one). Save ONLY the key itself to a private file, e.g.:",
        "",
        "  install -m 600 /dev/null /absolute/private/path/pfsense-api.key",
        "  # paste the key as the file's first (and only) line",
        "",
        "The file must be owned by you with no group/other permissions",
        "(600 above already sets that) -- the server refuses to start",
        "otherwise. Never paste the key value itself anywhere else.",
    )


def _private_ca_guidance_lines() -> tuple[str, ...]:
    """What "verify against a private/internal certificate authority"
    means and how to obtain the one file it requires. Only ever shown
    when `plan.target.tls_mode == "verify_private_ca"`."""

    return (
        "Your pfSense target uses a certificate signed by a private or",
        "internal certificate authority (common for a self-hosted or",
        "LAB pfSense) rather than a publicly trusted one -- this needs",
        "one file: that CA's own public certificate (never a private",
        "key). Export it from pfSense's own Certificate Manager, or ask",
        "whoever manages this pfSense's certificates for it, then point",
        "PFSENSE_TLS_CA_FILE at wherever you saved it.",
    )


def _confirm_key_guidance_lines() -> tuple[str, ...]:
    """`setup apply` (both postures) and `setup write-client-config`
    both also require PFSENSE_SETUP_CONFIRM_KEY_FILE -- a purely local
    secret, never sent to pfSense and not a pfSense credential, used
    only to bind a confirmation token to the exact plan you were shown
    (see `security_setup_confirm_key.py`'s own module docstring for the
    full rationale). v1.0.0 clean-room finding (2026-08-29): this was
    previously never mentioned here at all, so `setup apply` failed
    with an unexplained `blocked_configuration_error` for an operator
    who had done everything else this screen told them to."""

    return (
        "Also required, the first time only (persists across future",
        "setup apply / write-client-config runs): PFSENSE_SETUP_CONFIRM_KEY_FILE",
        "-- a local secret this tool uses only to confirm you've",
        "reviewed a plan before applying it (never sent to pfSense,",
        "never a pfSense credential). Don't have one yet? Create it:",
        "",
        "  pfsense-mcp-security setup init-confirm-key",
        "",
        "It prints the exact 'export PFSENSE_SETUP_CONFIRM_KEY_FILE=...'",
        "line to use below. Already have one from a prior run? Export",
        "that same path instead.",
    )


def _next_step_lines(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> tuple[str, ...]:
    """The "Next step" guidance for the human-mode completion screen.
    `setup apply` now exists for both postures (Slice 2 read_only,
    Slice 3 write_protected) -- shows the exact command, built from
    this plan's own recorded values, an operator can copy verbatim to
    inspect (and then apply) it. Wording differs only in what the
    command actually *does*: read_only verifies connectivity;
    write_protected provisions the ADR-033 service account via the
    existing `bootstrap` machinery."""

    posture = plan.privilege_plan.intended_capability_posture
    command_tokens = ["--capability-posture", posture.value]
    command_tokens += ["--anchor-assurance", plan.posture_plan.target_anchor_assurance.value]
    if plan.target.origin:
        command_tokens += ["--target-origin", plan.target.origin]
    if plan.target.identity:
        command_tokens += ["--target-identity", plan.target.identity]
    if plan.target.tls_mode:
        command_tokens += ["--tls-mode", plan.target.tls_mode]
    command_tokens += ["--plan-digest", compute_setup_plan_digest(plan)]

    command_lines = ["  pfsense-mcp-security setup apply \\"]
    for index in range(0, len(command_tokens), 2):
        flag, value = command_tokens[index], command_tokens[index + 1]
        is_last = index + 2 >= len(command_tokens)
        suffix = "" if is_last else " \\"
        command_lines.append(f"    {flag} {shlex.quote(value)}{suffix}")

    action_lines: tuple[str, ...]
    confirm_lines: tuple[str, ...]
    env_lines: tuple[str, ...] = ()
    if posture is CapabilityPosture.READ_ONLY:
        env_vars = _mcp_client_env_vars(plan, hints)
        env_export_lines = tuple(f'  export {key}="{value}"' for key, value in env_vars.items())
        env_lines = (
            "Before running the command below, set these in your shell",
            "-- `setup apply` reads them fresh from your real environment,",
            "the exact same way the MCP server itself does at startup;",
            "`setup` never reads or writes them itself:",
            "",
            *env_export_lines,
            "",
            *_credential_guidance_lines(),
        )
        if plan.target.tls_mode == "verify_private_ca":
            env_lines += ("", *_private_ca_guidance_lines())
        env_lines += ("", *_confirm_key_guidance_lines(), "")
        action_lines = (
            "To verify live connectivity (no pfSense changes are made),",
            "run:",
        )
        confirm_lines = (
            "That command alone only inspects and prints a confirmation",
            "token; add --confirm <TOKEN> to it to actually verify.",
        )
    else:
        env_lines = ("", *_confirm_key_guidance_lines(), "")
        action_lines = (
            "To provision the dedicated least-privilege ADR-033 service",
            "account (requires the same PFSENSE_ADMIN_* environment",
            "`pfsense-mcp-security bootstrap` already needs), run:",
        )
        confirm_lines = (
            "That command alone only inspects and prints a confirmation",
            "token; add --confirm <TOKEN> to it to actually provision.",
        )

    return (
        "This setup has only been planned. Nothing has been changed yet.",
        "",
        *env_lines,
        *action_lines,
        "",
        *command_lines,
        "",
        *confirm_lines,
    )


def _format_setup_human(plan: SetupPlan, hints: _MCPClientHints = _EMPTY_MCP_CLIENT_HINTS) -> str:
    """The default human-readable rendering for every human-mode setup
    output -- both the interactive wizard's completion screen and
    `--non-interactive` without `--json`. Deliberately does not surface
    internal identifiers (`capability_posture`, `anchor_assurance`,
    `schema_provided`, the full plan-digest value, ...) -- those remain
    fully available, unabridged, via `--json` (`_setup_plan_to_dict()`,
    never changed by this function). This function only changes
    *presentation* of an already-complete `SetupPlan`; it adds no new
    fields and drops no data from the plan model itself, and never
    recomputes the digest differently than `--json` does."""

    status_word = _human_status_word(plan)
    lines = [
        f"{_STATUS_MARKERS[status_word]}: setup plan created",
        "",
        f"Mode:        {_human_mode_label(plan)}",
    ]
    if plan.target.identity:
        lines.append(f"Firewall:    {plan.target.identity}")
    if plan.target.origin:
        lines.append(f"Address:     {plan.target.origin}")
    lines.append(f"Connection:  {_human_connection_label(plan)}")
    lines.append("")
    lines.append("No changes were made to pfSense.")
    lines.append("")
    lines.append("Next step")
    lines.extend(_next_step_lines(plan, hints))
    if not plan.posture_plan.safe_to_proceed:
        if plan.posture_plan.blocking_findings:
            reason = plan.posture_plan.blocking_findings[0]
        elif plan.posture_plan.validity_evidence:
            reason = plan.posture_plan.validity_evidence[0]
        else:
            reason = "see --json for detail"
        lines.append("")
        lines.append(f"! This selection cannot be completed yet: {reason}")
    if plan.posture_plan.safe_to_proceed:
        command, command_resolved = _resolve_mcp_client_command(hints.command_override)
        lines.append("")
        lines.append("MCP client configuration (print-only -- copy into your client's config,")
        lines.append("nothing is written to any file by this command):")
        lines.append("")
        if command_resolved:
            lines.append(_wrap(f"Detected your installed pfsense-mcp-server executable: {command}"))
        else:
            lines.append(
                _wrap(
                    "Could not automatically detect your installed pfsense-mcp-server executable -- "
                    "replace the illustrative 'command' value below with the output of "
                    "`which pfsense-mcp-server`."
                )
            )
        lines.append("")
        lines.append("Claude Desktop (JSON):")
        lines.append(json.dumps(_mcp_client_config_snippet(plan, hints), indent=2, sort_keys=True))
        lines.append("")
        lines.append("Codex CLI / ChatGPT desktop (shared TOML config):")
        lines.append(_mcp_client_config_toml(plan, hints))
        lines.append("")
        lines.append(
            _wrap(
                "Replace PFSENSE_API_KEY_FILE above with wherever you saved your key (see the "
                "credential guidance under Next step)."
            )
        )
        if plan.target.tls_mode == "verify_private_ca":
            lines.append(
                _wrap(
                    "Replace PFSENSE_TLS_CA_FILE above with wherever you saved your CA certificate "
                    "(see the private-CA guidance under Next step)."
                )
            )
    lines.append("")
    short_plan_id = compute_setup_plan_digest(plan)[:_HUMAN_PLAN_ID_LENGTH]
    lines.append(f"Plan ID: {short_plan_id}  (full plan digest and technical detail available via --json)")
    return "\n".join(lines)


def _load_local_schema_file(path: str, *, out: TextIO) -> dict[str, Any] | None:
    """Local disk read only -- never a network fetch. A missing,
    unreadable, malformed, or non-object schema file is never a fatal
    error: it is optional supplementary evidence for the privilege
    plan, so this function reports a clear warning and returns `None`
    rather than raising, letting the rest of setup's plan generation
    proceed without it."""

    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        print(f"warning: could not read --schema-file {path!r}: {exc}; continuing without schema evidence", file=out)
        return None
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError as exc:
        print(f"warning: --schema-file {path!r} is not valid JSON: {exc}; continuing without schema evidence", file=out)
        return None
    if not isinstance(parsed, dict):
        print(f"warning: --schema-file {path!r} is not a JSON object; continuing without schema evidence", file=out)
        return None
    return parsed


class _WizardSignal(str, Enum):
    """What a wizard step function did. `NEXT` advances to whatever step
    follows; `BACK` returns to the immediately preceding *shown* step
    (a step skipped because a flag pre-filled it is never a `BACK`
    target -- see `_run_wizard()`'s history handling); `QUIT` cancels the
    whole wizard (explicit Quit, or EOF, which always means Quit,
    regardless of whether Quit was offered as a shortcut at that
    particular prompt)."""

    NEXT = "next"
    BACK = "back"
    QUIT = "quit"


@dataclass(frozen=True)
class _MenuOption:
    label: str
    description: tuple[str, ...] = ()
    tag: str | None = None
    available: bool = True


@dataclass
class _WizardState:
    """Mutable wizard-in-progress selections, in plain human terms --
    never `CapabilityPosture`/`AnchorAssurance` enum members. Translated
    to the real plan-generation vocabulary only once, at the very end of
    `_run_wizard()` (`_derive_anchor_assurance()`), so every intermediate
    step function only ever deals with the human-facing choices this
    file's own UI copy describes."""

    mode: str | None = None  # "read_only" | "write_protected"
    protection: str | None = None  # "hardware_witness" | "software" | None
    address: str | None = None
    name: str | None = None
    tls_choice: str | None = None  # "verify" | "verify_private_ca" | "insecure"
    ca_file_hint: str | None = None
    declared_package_version: str | None = None
    schema_file: str | None = None


@dataclass(frozen=True)
class _WizardPrefill:
    """Values already supplied via CLI flags in interactive mode -- each
    non-`None` field here means the corresponding wizard step is never
    shown at all (its value is applied directly), matching the
    established `plan`/original Slice-1 precedent that an explicit flag
    always wins over a prompt, never the other way around."""

    capability_posture: str | None
    anchor_assurance: str | None
    target_origin: str | None
    target_identity: str | None
    tls_mode: str | None
    tls_ca_file: str | None
    schema_file: str | None
    declared_package_version: str | None


@dataclass(frozen=True)
class _WizardResult:
    capability_posture: str
    anchor_assurance: str
    target_origin: str | None
    target_identity: str | None
    tls_mode: str | None
    tls_ca_file: str | None
    schema_file: str | None
    declared_package_version: str | None


_STEP_USAGE = "usage"
_STEP_PROTECTION = "protection"
_STEP_FIREWALL = "firewall"
_STEP_CONNECTION = "connection"
_STEP_REVIEW = "review"

_STEP_LABELS = {
    _STEP_USAGE: "Usage",
    _STEP_PROTECTION: "Protection",
    _STEP_FIREWALL: "Firewall",
    _STEP_CONNECTION: "Connection",
    _STEP_REVIEW: "Review",
}


def _step_sequence(mode: str | None) -> tuple[str, ...]:
    """The numbered core wizard steps for the given mode -- `Protection`
    only appears for `write_protected` (progressive disclosure: a
    read-only operator is never shown it, and it never counts toward
    "of N" for that path). Advanced discovery-input configuration is
    deliberately never part of this sequence: it is not a mandatory
    normal-flow step, only an explicit, optional action offered from
    the Review step (see `_step_review()`)."""

    if mode == "write_protected":
        return (_STEP_USAGE, _STEP_PROTECTION, _STEP_FIREWALL, _STEP_CONNECTION, _STEP_REVIEW)
    return (_STEP_USAGE, _STEP_FIREWALL, _STEP_CONNECTION, _STEP_REVIEW)


def _print_step_heading(out: TextIO, state: _WizardState, step: str) -> None:
    """Prints the shared "Step N of M -- Label" heading every numbered
    step uses, computed from `_step_sequence()` so the total is always
    consistent with whatever is actually about to be asked -- 4 for the
    read-only path (Usage/Firewall/Connection/Review), 5 for
    write_protected (with Protection inserted). Before `state.mode` is
    known (the very first time `Step 1 -- Usage` is shown), `mode` is
    `None`, which `_step_sequence()` treats the same as read-only (4) --
    the correct, honest default, since read-only is this wizard's own
    recommended/default choice."""

    sequence = _step_sequence(state.mode)
    total = len(sequence)
    index = sequence.index(step) + 1
    print(file=out)
    print("pfSense MCP Security Setup", file=out)
    print(f"Step {index} of {total} -- {_STEP_LABELS[step]}", file=out)


def _prompt_menu(
    out: TextIO,
    in_: TextIO,
    heading: str,
    subheading: str,
    options: list[_MenuOption],
    *,
    default: int = 1,
    allow_back: bool = True,
) -> int | _WizardSignal:
    """One numbered-choice menu prompt. Never crashes, never lets an
    invalid or unavailable selection escape as a return value, never
    silently substitutes a different choice for an invalid one -- always
    re-prompts with a short explanation instead. EOF always returns
    `QUIT` regardless of `allow_back`/whether 'q' was offered at this
    particular menu -- Ctrl+C/EOF must terminate cleanly from every
    step (`_run_setup()`'s own top-level `except KeyboardInterrupt`
    handles the terminal-SIGINT case; this function handles the
    `readline() == ""` EOF case)."""

    while True:
        print(file=out)
        if heading:
            print(heading, file=out)
        if subheading:
            print(subheading, file=out)
        print(file=out)
        for index, option in enumerate(options, start=1):
            tag = f"  [{option.tag}]" if option.tag else ""
            print(f"  {index}) {option.label}{tag}", file=out)
            for line in option.description:
                print(f"     {line}", file=out)
        print(file=out)
        nav = [f"1-{len(options)}", f"Enter={default}"]
        if allow_back:
            nav.append("b=Back")
        nav.append("q=Quit")
        print(f"Select [{', '.join(nav)}]: ", file=out, end="")
        out.flush()
        line = in_.readline()
        if line == "":
            return _WizardSignal.QUIT
        raw = line.strip()
        if raw == "":
            selected_index = default
        elif raw.lower() == "q":
            return _WizardSignal.QUIT
        elif allow_back and raw.lower() == "b":
            return _WizardSignal.BACK
        elif raw.isdigit() and 1 <= int(raw) <= len(options):
            selected_index = int(raw)
        else:
            print(f"  Please enter a number from 1 to {len(options)}.", file=out)
            continue
        selected = options[selected_index - 1]
        if not selected.available:
            print(f"  '{selected.label}' is not available yet in this build. Please choose another option.", file=out)
            continue
        return selected_index


def _prompt_text(
    out: TextIO,
    in_: TextIO,
    heading: str,
    help_lines: tuple[str, ...],
    *,
    example: str | None = None,
    required: bool = True,
    allow_back: bool = True,
) -> str | _WizardSignal:
    """One free-text prompt. EOF always returns `QUIT` (see
    `_prompt_menu()`'s docstring for why)."""

    print(file=out)
    print(heading, file=out)
    print(file=out)
    for line in help_lines:
        print(line, file=out)
    if example:
        print(f"Example: {example}", file=out)
    print(file=out)
    while True:
        nav = ["b=Back", "q=Quit"] if allow_back else ["q=Quit"]
        print(f"{heading} ({', '.join(nav)}): ", file=out, end="")
        out.flush()
        line = in_.readline()
        if line == "":
            return _WizardSignal.QUIT
        raw = line.strip()
        if raw.lower() == "q":
            return _WizardSignal.QUIT
        if allow_back and raw.lower() == "b":
            return _WizardSignal.BACK
        if raw == "" and required:
            print("  This field is required.", file=out)
            continue
        return raw


def _normalize_address(raw: str) -> tuple[str, bool]:
    """Pure, local syntax normalization only -- never claims the result
    is reachable or that a server exists at it. A bare host/IP is
    assumed to mean HTTPS (the recommended, normal-flow default); an
    already-schemed address is returned unchanged."""

    if "://" in raw:
        return raw, True
    return f"https://{raw}", False


def _looks_like_a_valid_address(url: str) -> bool:
    """Pure local structural check (scheme + host present, no embedded
    whitespace) -- never a reachability check, never a network call."""

    if " " in url or "\t" in url:
        return False
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    return bool(parts.scheme) and bool(parts.netloc)


def _prompt_address(out: TextIO, in_: TextIO) -> str | _WizardSignal:
    while True:
        result = _prompt_text(
            out,
            in_,
            "pfSense address",
            ("Enter the HTTPS address of your pfSense firewall.",),
            example="https://192.0.2.1",
        )
        if result is _WizardSignal.QUIT or result is _WizardSignal.BACK:
            return result
        normalized, had_scheme = _normalize_address(result)
        if not _looks_like_a_valid_address(normalized):
            print("  That doesn't look like a valid address. Please try again.", file=out)
            print("  Example: https://192.0.2.1", file=out)
            continue
        if had_scheme:
            return normalized
        choice = _prompt_menu(
            out,
            in_,
            "",
            "Use HTTPS?",
            [
                _MenuOption(f"Use {normalized}", tag="Recommended"),
                _MenuOption("Enter another address"),
            ],
            default=1,
            allow_back=False,
        )
        if choice is _WizardSignal.QUIT:
            return _WizardSignal.QUIT
        if choice == 1:
            return normalized
        # choice == 2: re-prompt for the address from scratch.


def _step_usage(out: TextIO, in_: TextIO, state: _WizardState) -> _WizardSignal:
    _print_step_heading(out, state, _STEP_USAGE)
    choice = _prompt_menu(
        out,
        in_,
        "",
        "How do you want to use pfSense MCP?",
        [
            _MenuOption(
                "Read-only",
                description=("View status and configuration without allowing pfSense changes.",),
                tag="Recommended",
            ),
            _MenuOption(
                "Protected write",
                description=("Allows explicitly approved changes through the protected security path.",),
            ),
        ],
        default=1,
        allow_back=False,
    )
    if choice is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    state.mode = "read_only" if choice == 1 else "write_protected"
    if state.mode == "read_only":
        state.protection = None
    return _WizardSignal.NEXT


def _step_protection(out: TextIO, in_: TextIO, state: _WizardState) -> _WizardSignal:
    _print_step_heading(out, state, _STEP_PROTECTION)
    choice = _prompt_menu(
        out,
        in_,
        "",
        "How should approved changes be protected?",
        [
            _MenuOption(
                "Hardware TPM witness",
                description=(
                    "Adds independent hardware-backed verification for",
                    "approved changes. Requires separate witness hardware.",
                ),
                tag="Advanced",
            ),
            _MenuOption(
                "Software protection",
                description=("Protects approved changes using local security controls.",),
                tag="Not available yet",
                available=False,
            ),
        ],
        default=1,
    )
    if choice is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    if choice is _WizardSignal.BACK:
        return _WizardSignal.BACK
    state.protection = "hardware_witness" if choice == 1 else "software"
    return _WizardSignal.NEXT


def _step_firewall(out: TextIO, in_: TextIO, state: _WizardState, prefill: _WizardPrefill) -> _WizardSignal:
    _print_step_heading(out, state, _STEP_FIREWALL)

    if prefill.target_origin is not None:
        state.address = prefill.target_origin
    elif state.address is None:
        result = _prompt_address(out, in_)
        if result is _WizardSignal.QUIT:
            return _WizardSignal.QUIT
        if result is _WizardSignal.BACK:
            return _WizardSignal.BACK
        state.address = result

    if prefill.target_identity is not None:
        state.name = prefill.target_identity
        return _WizardSignal.NEXT

    result = _prompt_text(
        out,
        in_,
        "Firewall name",
        (
            "Choose a friendly name used to identify this firewall",
            "in plans and reports.",
        ),
        example="Home pfSense",
    )
    if result is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    if result is _WizardSignal.BACK:
        if prefill.target_origin is not None:
            return _WizardSignal.BACK
        state.address = None
        return _step_firewall(out, in_, state, prefill)
    state.name = result
    return _WizardSignal.NEXT


def _step_connection(out: TextIO, in_: TextIO, state: _WizardState) -> _WizardSignal:
    """v1.0.0 clean-room finding (2026-08-28): a real private-CA pfSense
    LAB target found this step previously had no way to express "verify
    against a private/internal CA" at all -- only "verify against the
    system trust store" or "skip verification entirely". A private CA
    is common for a self-hosted/LAB pfSense, so it is now a first-class,
    directly-chosen option here (not buried in an "Advanced" submenu),
    distinguished in plain language from both the publicly-trusted-
    certificate case (still the overall recommended default) and the
    discouraged skip-verification case."""

    _print_step_heading(out, state, _STEP_CONNECTION)
    choice = _prompt_menu(
        out,
        in_,
        "",
        "Connection security",
        [
            _MenuOption(
                "Verify TLS certificate",
                description=("For pfSense with a certificate from a public,", "trusted certificate authority."),
                tag="Recommended",
            ),
            _MenuOption(
                "Verify against a private/internal certificate authority",
                description=(
                    "For self-hosted or LAB pfSense using its own or your",
                    "organization's internal CA.",
                ),
            ),
            _MenuOption(
                "Skip TLS verification",
                description=(
                    "Skips verifying the pfSense server's identity. Only",
                    "use this for trusted local/lab networks.",
                ),
                tag="Advanced · Not recommended",
            ),
        ],
        default=1,
    )
    if choice is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    if choice is _WizardSignal.BACK:
        return _WizardSignal.BACK
    if choice == 1:
        state.tls_choice = "verify"
        return _WizardSignal.NEXT
    if choice == 3:
        state.tls_choice = "insecure"
        return _WizardSignal.NEXT

    state.tls_choice = "verify_private_ca"
    ca_result = _prompt_text(
        out,
        in_,
        "Path to your private CA certificate file",
        (
            "Only the CA's own public certificate -- never a private key.",
            "Optional here -- leave blank if you don't have the file yet;",
            "you'll be reminded how to get it before applying this plan.",
        ),
        example="/path/to/lab-ca.crt",
        required=False,
        allow_back=False,
    )
    if ca_result is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    state.ca_file_hint = ca_result or None
    return _WizardSignal.NEXT


def _step_advanced(out: TextIO, in_: TextIO, state: _WizardState) -> _WizardSignal:
    print(file=out)
    print("Advanced options", file=out)
    choice = _prompt_menu(
        out,
        in_,
        "",
        "",
        [
            _MenuOption(
                "Continue with recommended defaults",
                description=("Suitable for normal installations.",),
                tag="Recommended",
            ),
            _MenuOption(
                "Configure advanced discovery inputs",
                description=(
                    "Manually provide saved schema/version evidence for",
                    "development or troubleshooting.",
                ),
            ),
        ],
        default=1,
    )
    if choice is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    if choice is _WizardSignal.BACK:
        return _WizardSignal.BACK
    if choice == 1:
        return _WizardSignal.NEXT

    version_result = _prompt_text(
        out,
        in_,
        "pfSense REST API package version",
        ("Optional -- leave blank to skip.",),
        example="2.10.0",
        required=False,
        allow_back=False,
    )
    if version_result is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    state.declared_package_version = version_result or None

    schema_result = _prompt_text(
        out,
        in_,
        "Saved OpenAPI schema file path",
        ("Optional -- leave blank to skip.",),
        example="/path/to/schema.json",
        required=False,
        allow_back=False,
    )
    if schema_result is _WizardSignal.QUIT:
        return _WizardSignal.QUIT
    state.schema_file = schema_result or None
    return _WizardSignal.NEXT


def _derive_anchor_assurance(state: _WizardState) -> str:
    if state.mode == "read_only":
        return AnchorAssurance.NONE.value
    return state.protection or AnchorAssurance.HARDWARE_WITNESS.value


def _effective_anchor_assurance(state: _WizardState, prefill: _WizardPrefill) -> str:
    return prefill.anchor_assurance or _derive_anchor_assurance(state)


def _print_review(out: TextIO, state: _WizardState, prefill: _WizardPrefill) -> None:
    print(file=out)
    print("Review setup plan", file=out)
    print(file=out)
    print("Mode", file=out)
    if state.mode == "read_only":
        print("  Read-only", file=out)
        print("  AI can inspect pfSense but cannot change it.", file=out)
    else:
        print("  Protected write", file=out)
        anchor = _effective_anchor_assurance(state, prefill)
        if anchor == AnchorAssurance.HARDWARE_WITNESS.value:
            print("  Approved changes are protected by hardware TPM witness", file=out)
            print("  verification.", file=out)
        else:
            print(f"  Approved changes are protected ({anchor}).", file=out)
    print(file=out)
    print("Firewall", file=out)
    print(f"  {state.name or '(not set)'}", file=out)
    print(f"  {state.address or '(not set)'}", file=out)
    print(file=out)
    print("Connection", file=out)
    if state.tls_choice == "insecure":
        print("  Skip TLS verification (not recommended)", file=out)
        print("  TLS verification will be skipped when setup connects to pfSense.", file=out)
    else:
        print("  Verify TLS certificate", file=out)
        print("  TLS verification will be required when setup connects to pfSense.", file=out)
    print(file=out)
    print("This is a planning step only.", file=out)
    print(file=out)
    print("No pfSense settings, accounts, credentials, or local", file=out)
    print("configuration files will be changed.", file=out)


def _step_review(out: TextIO, in_: TextIO, state: _WizardState, prefill: _WizardPrefill) -> _WizardSignal:
    """Review is the last numbered step. Advanced discovery-input
    configuration (`_step_advanced()`) is deliberately reached only from
    here, as an explicit, optional menu choice -- never a mandatory stop
    on the way to Review (see `_step_sequence()`'s own docstring). Both
    completing and backing out of that nested advanced sub-flow simply
    redisplay Review; only Generate/Go back/Exit can leave this
    function."""

    while True:
        _print_step_heading(out, state, _STEP_REVIEW)
        _print_review(out, state, prefill)
        choice = _prompt_menu(
            out,
            in_,
            "",
            "",
            [
                _MenuOption("Generate plan", tag="Recommended"),
                _MenuOption("Go back and change selections"),
                _MenuOption(
                    "Advanced options",
                    description=(
                        "Manually provide saved schema/version evidence for",
                        "development or troubleshooting.",
                    ),
                ),
                _MenuOption("Exit"),
            ],
            default=1,
            allow_back=False,
        )
        if choice is _WizardSignal.QUIT:
            return _WizardSignal.QUIT
        if choice == 1:
            return _WizardSignal.NEXT
        if choice == 2:
            return _WizardSignal.BACK
        if choice == 3:
            advanced_signal = _step_advanced(out, in_, state)
            if advanced_signal is _WizardSignal.QUIT:
                return _WizardSignal.QUIT
            # NEXT (configured, or chose "continue with defaults") and
            # BACK (backed out of the advanced sub-menu) both simply
            # redisplay Review -- neither ever leaves this function on
            # their own.
            continue
        return _WizardSignal.QUIT  # choice == 4, Exit


def _next_step(current: str, state: _WizardState) -> str:
    if current == _STEP_USAGE:
        return _STEP_PROTECTION if state.mode == "write_protected" else _STEP_FIREWALL
    if current == _STEP_PROTECTION:
        return _STEP_FIREWALL
    if current == _STEP_FIREWALL:
        return _STEP_CONNECTION
    if current == _STEP_CONNECTION:
        return _STEP_REVIEW
    raise AssertionError(current)


def _run_wizard(out: TextIO, in_: TextIO, prefill: _WizardPrefill) -> _WizardResult | None:
    """Drives the guided, numbered-menu wizard end to end. Returns
    `None` if the operator cancelled (explicit Quit, EOF) at any step --
    `_run_setup()` treats that identically to the non-interactive
    "required value missing" case: no plan is generated, exit code
    `_SETUP_ABORTED_EXIT_CODE`. Never performs I/O beyond `in_`/`out`;
    never imports or calls anything that could mutate pfSense state --
    this function only ever populates a `_WizardResult`, the same plain
    strings `generate_setup_plan()` already accepted from flags."""

    state = _WizardState()
    history: list[str] = []
    current = _STEP_USAGE

    while True:
        if current == _STEP_USAGE and prefill.capability_posture is not None:
            state.mode = prefill.capability_posture
            if state.mode == "read_only":
                state.protection = None
            current = _next_step(current, state)
            continue
        if current == _STEP_PROTECTION and prefill.anchor_assurance is not None:
            current = _next_step(current, state)
            continue
        if current == _STEP_CONNECTION and prefill.tls_mode is not None:
            state.tls_choice = prefill.tls_mode
            state.ca_file_hint = prefill.tls_ca_file
            current = _next_step(current, state)
            continue

        if current == _STEP_USAGE:
            signal = _step_usage(out, in_, state)
        elif current == _STEP_PROTECTION:
            signal = _step_protection(out, in_, state)
        elif current == _STEP_FIREWALL:
            signal = _step_firewall(out, in_, state, prefill)
        elif current == _STEP_CONNECTION:
            signal = _step_connection(out, in_, state)
        elif current == _STEP_REVIEW:
            signal = _step_review(out, in_, state, prefill)
        else:
            raise AssertionError(current)

        if signal is _WizardSignal.QUIT:
            return None
        if signal is _WizardSignal.BACK:
            if not history:
                continue
            current = history.pop()
            continue

        history.append(current)
        if current == _STEP_REVIEW:
            break
        current = _next_step(current, state)

    advanced_locked = prefill.schema_file is not None or prefill.declared_package_version is not None
    return _WizardResult(
        capability_posture=prefill.capability_posture or state.mode or CapabilityPosture.READ_ONLY.value,
        anchor_assurance=_effective_anchor_assurance(state, prefill),
        target_origin=state.address if prefill.target_origin is None else prefill.target_origin,
        target_identity=state.name if prefill.target_identity is None else prefill.target_identity,
        tls_mode=prefill.tls_mode or state.tls_choice,
        tls_ca_file=prefill.tls_ca_file if prefill.tls_mode is not None else state.ca_file_hint,
        schema_file=prefill.schema_file if advanced_locked else state.schema_file,
        declared_package_version=(
            prefill.declared_package_version if advanced_locked else state.declared_package_version
        ),
    )


def _run_setup(
    *,
    non_interactive: bool,
    capability_posture: str | None,
    anchor_assurance: str | None,
    target_origin: str | None,
    target_identity: str | None,
    tls_mode: str | None,
    tls_ca_file: str | None = None,
    command: str | None = None,
    api_key_file: str | None = None,
    schema_file: str | None,
    declared_package_version: str | None,
    as_json: bool,
    env: dict[str, str] | None,
    out: TextIO,
    in_: TextIO,
) -> int:
    """Never mutates pfSense state, never provisions anything, never
    executes anything -- in every mode, always. Interactive prompting
    (when `non_interactive` is `False`) is a guided, numbered-menu
    wizard (`_run_wizard()`) that only ever reads lines from `in_` and
    writes prompts to `out`; it never performs a pfSense request of any
    kind. `--non-interactive` skips the wizard entirely but reaches the
    exact same, single `generate_setup_plan()` call -- there is no
    separate "automation" code path that could silently behave
    differently. A real terminal SIGINT (Ctrl+C) during interactive
    prompting raises `KeyboardInterrupt`, caught here and treated
    identically to an explicit Quit -- no traceback, no partial plan.

    `tls_ca_file`/`command` are purely-informational rendering hints
    (see `_MCPClientHints`) -- never part of `SetupPlan`, never
    validated, never sent anywhere. `tls_ca_file` also prefills the
    interactive wizard's own private-CA prompt when `tls_mode` is
    prefilled (matching every other `--target-*`/`--tls-mode` prefill's
    existing "an explicit flag always wins, the step is never shown"
    behavior)."""

    if not non_interactive:
        prefill = _WizardPrefill(
            capability_posture=capability_posture,
            anchor_assurance=anchor_assurance,
            target_origin=target_origin,
            target_identity=target_identity,
            tls_mode=tls_mode,
            tls_ca_file=tls_ca_file,
            schema_file=schema_file,
            declared_package_version=declared_package_version,
        )
        try:
            wizard_result = _run_wizard(out, in_, prefill)
        except KeyboardInterrupt:
            wizard_result = None
        if wizard_result is None:
            print(file=out)
            print("Setup cancelled.", file=out)
            print("No changes were made.", file=out)
            return _SETUP_ABORTED_EXIT_CODE
        capability_posture = wizard_result.capability_posture
        anchor_assurance = wizard_result.anchor_assurance
        target_origin = wizard_result.target_origin
        target_identity = wizard_result.target_identity
        tls_mode = wizard_result.tls_mode
        tls_ca_file = wizard_result.tls_ca_file
        schema_file = wizard_result.schema_file
        declared_package_version = wizard_result.declared_package_version

    if capability_posture is None or anchor_assurance is None:
        print(
            "setup: no plan generated -- capability posture and anchor assurance are both required "
            "(use --capability-posture/--anchor-assurance, or answer both prompts interactively).",
            file=out,
        )
        return _SETUP_ABORTED_EXIT_CODE

    schema = _load_local_schema_file(schema_file, out=out) if schema_file else None

    plan = generate_setup_plan(
        target_capability_posture=CapabilityPosture(capability_posture),
        target_anchor_assurance=AnchorAssurance(anchor_assurance),
        target_origin=target_origin,
        target_identity=target_identity,
        tls_mode=tls_mode,
        schema=schema,
        declared_package_version=declared_package_version,
        env=env,
    )
    hints = _MCPClientHints(ca_file=tls_ca_file, command_override=command, api_key_file=api_key_file)
    if as_json:
        print(json.dumps(_setup_plan_to_dict(plan, hints), indent=2, sort_keys=True), file=out)
    else:
        print(_format_setup_human(plan, hints), file=out)
    if plan.posture_plan.overall_status in (
        PlanOverallStatus.BLOCKED_INVALID_TARGET,
        PlanOverallStatus.BLOCKED_ANOMALY_DETECTED,
        PlanOverallStatus.BLOCKED_INDETERMINATE_CURRENT_STATE,
    ):
        return _BLOCKED_TARGET_EXIT_CODE
    return 0


def _apply_result_to_dict(result: ApplyResult) -> dict[str, Any]:
    return {
        "outcome": result.outcome.value,
        "detail": result.detail,
        "plan_digest": result.plan_digest,
        "confirmation_token": result.confirmation_token,
        "doctor_ready": result.doctor_ready,
        "recovery_outcome": result.recovery_outcome,
        "recovery_action": result.recovery_action,
        "recovery_confirmation_token": result.recovery_confirmation_token,
    }


def _format_apply_human(result: ApplyResult) -> str:
    lines = [f"pfsense-mcp-security setup apply: {result.outcome.value}", "", result.detail]
    if result.plan_digest is not None:
        lines.append("")
        lines.append(f"Plan digest: {result.plan_digest}")
    if result.confirmation_token is not None:
        lines.append(f"Confirmation token: {result.confirmation_token}")
    if result.doctor_ready is not None:
        lines.append(f"Doctor ready: {result.doctor_ready}")
    if result.recovery_outcome is not None:
        lines.append("")
        lines.append(f"Inline recovery inspection outcome: {result.recovery_outcome}")
        if result.recovery_action is not None:
            lines.append(f"Recovery action needed: {result.recovery_action}")
        if result.recovery_confirmation_token is not None:
            lines.append(f"Recovery confirmation token: {result.recovery_confirmation_token}")
            lines.append(
                "To resolve, run: pfsense-mcp-security recover "
                f"--execute {result.recovery_action} --confirm {result.recovery_confirmation_token}"
            )
    return "\n".join(lines)


#: Slice 7 (automation hardening): an additional, purely additive way
#: to supply `--confirm`'s value that keeps it out of argv/`ps`/shell
#: history entirely -- the standard CI-secret-injection convention
#: (GitHub Actions/GitLab CI variables, etc. all inject as environment
#: variables), complementing `--confirm -` (stdin) for pipelines where
#: piping between steps is awkward. Never required, never the only way
#: to supply a token, and never consulted when `--confirm` is
#: explicitly given on the command line (including `-`) -- an explicit
#: flag always wins over an ambient environment variable.
_SETUP_APPLY_CONFIRM_TOKEN_ENV_VAR = "PFSENSE_SETUP_APPLY_CONFIRM_TOKEN"  # nosec B105 -- an env var name, not a credential


def _resolve_setup_apply_confirm(confirm: str | None, *, env: dict[str, str] | None, in_: TextIO) -> str | None:
    """Resolves the effective `--confirm` value, in strict precedence
    order: an explicit `--confirm -` reads stdin; an explicit
    `--confirm <TOKEN>` is used verbatim; only when `--confirm` was
    *omitted entirely* does `PFSENSE_SETUP_APPLY_CONFIRM_TOKEN` get a
    chance to supply it (an empty/whitespace-only env var is treated as
    absent, matching this codebase's own `_required()`-style discipline
    elsewhere) -- an operator explicitly typing `--confirm` (even a
    wrong or empty value passed some other way) is never silently
    overridden by an ambient environment variable."""

    if confirm == "-":
        return in_.readline().rstrip("\n")
    if confirm is not None:
        return confirm
    source = env if env is not None else os.environ
    from_env = source.get(_SETUP_APPLY_CONFIRM_TOKEN_ENV_VAR)
    if from_env is not None and from_env.strip():
        return from_env
    return None


def _init_confirm_key_result_to_dict(result: InitConfirmKeyResult) -> dict[str, Any]:
    return {"outcome": result.outcome.value, "path": str(result.path), "detail": result.detail}


def _format_init_confirm_key_human(result: InitConfirmKeyResult) -> str:
    lines = [f"pfsense-mcp-security setup init-confirm-key: {result.outcome.value}", "", result.detail]
    if result.outcome in (InitConfirmKeyOutcome.CREATED, InitConfirmKeyOutcome.ALREADY_EXISTS):
        lines.append("")
        lines.append("Before running `setup apply` or `setup write-client-config`, export:")
        lines.append("")
        lines.append(f'  export PFSENSE_SETUP_CONFIRM_KEY_FILE="{result.path}"')
        lines.append("")
        lines.append(_wrap("This key never leaves this machine, is never sent to pfSense, and is not a"))
        lines.append(
            _wrap(
                "pfSense credential -- it only lets this tool tell a fresh, reviewed plan apart from a "
                "stale or copy-pasted one."
            )
        )
    return "\n".join(lines)


def _run_setup_init_confirm_key(*, path: str | None, as_json: bool, out: TextIO) -> int:
    result = create_confirm_key(Path(path).expanduser() if path else None)
    if as_json:
        print(json.dumps(_init_confirm_key_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_init_confirm_key_human(result), file=out)
    return _INIT_CONFIRM_KEY_EXIT_CODES[result.outcome]


def _run_setup_apply(
    *,
    capability_posture: str,
    anchor_assurance: str,
    target_origin: str | None,
    target_identity: str | None,
    tls_mode: str | None,
    plan_digest: str | None,
    confirm: str | None,
    as_json: bool,
    env: dict[str, str] | None,
    out: TextIO,
    in_: TextIO,
) -> int:
    confirm_token = _resolve_setup_apply_confirm(confirm, env=env, in_=in_)
    result = run_setup_apply_from_environment(
        env,
        target_capability_posture=capability_posture,
        target_anchor_assurance=anchor_assurance,
        target_origin=target_origin,
        target_identity=target_identity,
        tls_mode=tls_mode,
        plan_digest=plan_digest,
        confirm_token=confirm_token,
    )
    if as_json:
        print(json.dumps(_apply_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_apply_human(result), file=out)
    return _SETUP_APPLY_EXIT_CODES[result.outcome]


def _write_result_to_dict(result: WriteResult) -> dict[str, Any]:
    return {
        "outcome": result.outcome.value,
        "detail": result.detail,
        "client_type": result.client_type,
        "config_path": result.config_path,
        "confirmation_token": result.confirmation_token,
        "diff": result.diff,
        "backup_path": result.backup_path,
    }


def _format_write_human(result: WriteResult) -> str:
    lines = [f"pfsense-mcp-security setup write-client-config: {result.outcome.value}", "", result.detail]
    if result.client_type is not None:
        lines.append("")
        lines.append(f"Client: {result.client_type}")
    if result.config_path is not None:
        lines.append(f"Config path: {result.config_path}")
    if result.backup_path is not None:
        lines.append(f"Backup: {result.backup_path}")
    if result.diff:
        lines.append("")
        lines.append("Proposed diff:")
        lines.append(result.diff.rstrip("\n"))
    if result.confirmation_token is not None:
        lines.append("")
        lines.append(f"Confirmation token: {result.confirmation_token}")
    return "\n".join(lines)


def _resolve_client_config_confirm(confirm: str | None, *, in_: TextIO) -> str | None:
    """Deliberately narrower than `_resolve_setup_apply_confirm()`: no
    environment-variable fallback. Reusing `setup apply`'s own
    `PFSENSE_SETUP_APPLY_CONFIRM_TOKEN` here would let a token meant to
    confirm a pfSense-side mutation silently also confirm an unrelated
    local file write (or vice versa) -- exactly the cross-domain
    confusion `--confirm` being "separate from every pfSense-side
    confirmation" (the design's own requirement) exists to prevent.
    `--confirm -` (stdin) remains available for CI use."""

    if confirm == "-":
        return in_.readline().rstrip("\n")
    return confirm


def _print_write_result(result: WriteResult, *, as_json: bool, out: TextIO) -> None:
    if as_json:
        print(json.dumps(_write_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_write_human(result), file=out)


def _run_setup_write_client_config(
    *,
    client: str,
    config_path: str | None,
    capability_posture: str,
    anchor_assurance: str,
    target_origin: str | None,
    target_identity: str | None,
    tls_mode: str | None,
    tls_ca_file: str | None = None,
    command: str | None = None,
    api_key_file: str | None = None,
    plan_digest: str | None,
    confirm: str | None,
    as_json: bool,
    env: dict[str, str] | None,
    out: TextIO,
    in_: TextIO,
) -> int:
    """`tls_ca_file`/`command`/`api_key_file` are the same purely-informational
    rendering hints `_run_setup()` accepts (see `_MCPClientHints`) --
    here they personalize the file actually being written, not just a
    preview, so getting them right matters even more: an un-overridden
    `command` still auto-resolves to the real, currently-installed
    `pfsense-mcp-server` executable (see `_resolve_mcp_client_command()`)
    rather than writing a placeholder that was never right for a
    pipx/uv-tool-installed operator to begin with."""

    try:
        posture = CapabilityPosture(capability_posture)
        anchor = AnchorAssurance(anchor_assurance)
    except ValueError as exc:
        result = WriteResult(WriteOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))
        _print_write_result(result, as_json=as_json, out=out)
        return _CLIENT_CONFIG_WRITE_EXIT_CODES[result.outcome]

    plan = generate_setup_plan(
        target_capability_posture=posture,
        target_anchor_assurance=anchor,
        target_origin=target_origin,
        target_identity=target_identity,
        tls_mode=tls_mode,
        env=env,
    )
    fresh_digest = compute_setup_plan_digest(plan)

    if plan_digest is not None and fresh_digest != plan_digest:
        result = WriteResult(
            WriteOutcome.BLOCKED_CONFIGURATION_ERROR,
            "The recomputed plan digest does not match --plan-digest -- current pfSense-side plan "
            "state has changed since this plan was generated. Run `setup --non-interactive` again to "
            "get a current plan.",
        )
        _print_write_result(result, as_json=as_json, out=out)
        return _CLIENT_CONFIG_WRITE_PLAN_STALE_EXIT_CODE

    hints = _MCPClientHints(ca_file=tls_ca_file, command_override=command, api_key_file=api_key_file)
    resolved_command, _ = _resolve_mcp_client_command(hints.command_override)
    confirm_token = _resolve_client_config_confirm(confirm, in_=in_)
    result = run_client_config_write_from_environment(
        env,
        client=client,
        config_path_override=config_path,
        command=resolved_command,
        env_vars=_mcp_client_env_vars(plan, hints),
        plan_digest=fresh_digest,
        confirm_token=confirm_token,
    )
    _print_write_result(result, as_json=as_json, out=out)
    return _CLIENT_CONFIG_WRITE_EXIT_CODES[result.outcome]


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command == "discover":
        return _run_discover(as_json=args.json, env=None, out=sys.stdout)
    if args.command == "plan":
        return _run_plan(
            capability_posture=args.capability_posture,
            anchor_assurance=args.anchor_assurance,
            as_json=args.json,
            env=None,
            out=sys.stdout,
        )
    if args.command == "doctor":
        return _run_doctor(as_json=args.json, env=None, out=sys.stdout)
    if args.command == "bootstrap":
        return _run_bootstrap(as_json=args.json, env=None, out=sys.stdout)
    if args.command == "recover":
        if args.confirm is not None and args.execute is None:
            parser.error("--confirm requires --execute")
        return _run_recover(
            execute=args.execute, confirm=args.confirm, as_json=args.json, env=None, out=sys.stdout, in_=sys.stdin
        )
    if args.command == "setup":
        if getattr(args, "setup_action", None) == "init-confirm-key":
            return _run_setup_init_confirm_key(path=args.path, as_json=args.json, out=sys.stdout)
        if getattr(args, "setup_action", None) == "apply":
            return _run_setup_apply(
                capability_posture=args.capability_posture,
                anchor_assurance=args.anchor_assurance,
                target_origin=args.target_origin,
                target_identity=args.target_identity,
                tls_mode=args.tls_mode,
                plan_digest=args.plan_digest,
                confirm=args.confirm,
                as_json=args.json,
                env=None,
                out=sys.stdout,
                in_=sys.stdin,
            )
        if getattr(args, "setup_action", None) == "write-client-config":
            return _run_setup_write_client_config(
                client=args.client,
                config_path=args.config_path,
                capability_posture=args.capability_posture,
                anchor_assurance=args.anchor_assurance,
                target_origin=args.target_origin,
                target_identity=args.target_identity,
                tls_mode=args.tls_mode,
                tls_ca_file=args.tls_ca_file,
                command=args.command_override,
                api_key_file=args.api_key_file,
                plan_digest=args.plan_digest,
                confirm=args.confirm,
                as_json=args.json,
                env=None,
                out=sys.stdout,
                in_=sys.stdin,
            )
        if args.non_interactive and (args.capability_posture is None or args.anchor_assurance is None):
            parser.error("--non-interactive requires --capability-posture and --anchor-assurance")
        return _run_setup(
            non_interactive=args.non_interactive,
            capability_posture=args.capability_posture,
            anchor_assurance=args.anchor_assurance,
            target_origin=args.target_origin,
            target_identity=args.target_identity,
            tls_mode=args.tls_mode,
            tls_ca_file=args.tls_ca_file,
            command=args.command_override,
            api_key_file=args.api_key_file,
            schema_file=args.schema_file,
            declared_package_version=args.declared_package_version,
            as_json=args.json,
            env=None,
            out=sys.stdout,
            in_=sys.stdin,
        )

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
