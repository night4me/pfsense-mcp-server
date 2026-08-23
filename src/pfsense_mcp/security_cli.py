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
    provisioning orchestration. The only mutating subcommand in this
    file. Composes the already-implemented, already-reviewed
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
    **This subcommand has been verified offline only**
    (synthetic/fake HTTP fixtures) -- no live
    pfSense appliance has been contacted by this development task, and
    running it against a real target is a separate, future, explicitly
    authorized action. `pfsense-mcp-security setup` (a user-facing
    interactive wizard) is reserved for a future slice and does not
    exist yet; `bootstrap` is the deterministic, non-interactive,
    lower-level command underneath it.

`discover`, `plan`, and `doctor` perform no provisioning, repair, or
mutation. `bootstrap` is the first and only subcommand that can mutate
pfSense state (when later run against a real appliance) -- and even
then, only ever the one fixed, least-privilege `pfsense-mcp` service
account this codebase's ADR-033 architecture already scopes it to.

This file does not import `pfsense_mcp.tier1` directly, or at all --
every axis-discovery call goes through the one function
`security_discovery.discover_security_posture()` exposes (`plan` calls
it only indirectly, via `security_plan.generate_security_posture_plan()`;
`doctor` calls it only indirectly, via
`security_doctor.run_doctor_checks()`), keeping the tier1-package-
isolation exemption's surface to exactly `security_discovery.py`,
matching `tier1_anchor_check.py`'s own established discipline for
`application.py`.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any, TextIO

from .security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    BootstrapOrchestrationResult,
    run_bootstrap_from_environment,
)
from .security_discovery import (
    AnchorAssurance,
    AnchorAssuranceDiscovery,
    AnchorEvidenceState,
    CapabilityPosture,
    CapabilityPostureDiscovery,
    SecurityPostureDiscovery,
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
    lines.extend(f"  - {line}" for line in cap.evidence)
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
    lines.extend(f"  - {line}" for line in anchor.evidence)
    lines.append("")
    if anchor.evidence_state is AnchorEvidenceState.PROVISIONED_MISMATCH:
        lines.append(
            "WARNING: witness/store mismatch detected -- this is a security-relevant anomaly. "
            "Reported only; no reconciliation was attempted."
        )
    else:
        lines.append(
            "Note: read_only + hardware_witness is a valid, representable combination in the accepted "
            "ADR-021 two-axis model -- not one of the three curated setup presets, but fully supported."
        )
    lines.append(
        "This report is read-only discovery only (ADR-021 Phase B). No provisioning/setup subcommand exists yet."
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
        lines.append(f"  - {line}")
    for line in plan.blocking_findings:
        lines.append(f"BLOCKING: {line}")
    if plan.steps:
        lines.append("")
        lines.append("Steps (ordered; none executed):")
        for step in plan.steps:
            lines.append(f"  [{step.order}] ({step.axis}) {step.action}")
            lines.append(f"      id:                     {step.step_id}")
            lines.append(f"      description:            {step.description}")
            lines.append(f"      mutation_class:         {step.mutation_class.value}")
            lines.append(f"      authorization_required: {step.authorization_required.value}")
            lines.append(f"      implementation_available: {step.implementation_available}")
            lines.append(f"      reversible:             {step.reversible}")
            lines.append(f"      security_impact:        {step.security_impact.value}")
            lines.append(f"      prerequisite_satisfied: {step.prerequisite_satisfied}")
            lines.append(f"      blocked:                {step.blocked}")
            if step.blocked_reason:
                lines.append(f"      blocked_reason:         {step.blocked_reason}")
    lines.append("")
    for line in plan.notes:
        lines.append(line)
    return "\n".join(lines)


def _doctor_check_to_dict(check: DoctorCheck) -> dict[str, Any]:
    return {
        "check_id": check.check_id,
        "description": check.description,
        "status": check.status.value,
        "detail": check.detail,
    }


def _doctor_result_to_dict(result: DoctorResult) -> dict[str, Any]:
    return {
        "ready": result.ready,
        "checks": [_doctor_check_to_dict(check) for check in result.checks],
        "notes": [
            "Diagnostic only -- no artifact was deleted, moved, or repaired, and no witness/store state "
            "was changed. Checks only artifact-exchange path cleanliness and witness readiness, not the "
            "full build_production_runtime() prerequisite set (store/authority-key configuration, etc.).",
        ],
    }


_STATUS_SYMBOL = {
    CheckStatus.PASS: "OK",
    CheckStatus.FAIL: "FAIL",
    CheckStatus.NOT_CONFIGURED: "NOT CONFIGURED",
}


def _format_doctor_human(result: DoctorResult) -> str:
    lines = [
        "pfsense-mcp-security: Tier 1 ceremony readiness check (read-only, diagnostic only)",
        "",
        f"Overall: {'READY' if result.ready else 'NOT READY'}",
        "",
    ]
    for check in result.checks:
        lines.append(f"  [{_STATUS_SYMBOL[check.status]}] {check.description} ({check.check_id})")
        lines.append(f"        {check.detail}")
    lines.append("")
    lines.append(
        "Diagnostic only -- no artifact was deleted, moved, or repaired, and no witness/store state was "
        "changed. Checks artifact-exchange path cleanliness and witness readiness only, not the full "
        "build_production_runtime() prerequisite set."
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
            "This subcommand is the only mutating command in this CLI. It is verified offline only "
            "(synthetic/fake HTTP fixtures) -- no live pfSense appliance has been contacted by the "
            "development task that implemented it.",
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
        f"Detail:  {result.detail}",
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
        lines.append(f"Engine detail:  {result.provisioning_detail}")
    lines.append("")
    lines.append(
        "This subcommand is the only mutating command in this CLI. It is verified offline only "
        "(synthetic/fake HTTP fixtures) -- no live pfSense appliance has been contacted by the "
        "development task that implemented it."
    )
    lines.append(
        "Never prints or logs an API key, password, or any other secret value. A freshly generated "
        "service-account key is written only to the configured PFSENSE_SERVICE_API_KEY_FILE custody "
        "path (owner-only permissions), never to stdout/stderr/JSON output."
    )
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pfsense-mcp-security",
        description=(
            "Guided security-posture discovery and diagnostics for pfsense-mcp-server (ADR-021, "
            "Accepted). Read-only discovery/diagnostics only -- no provisioning/setup subcommand "
            "exists yet."
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
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
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    doctor_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit deterministic machine-readable JSON instead of human-readable text.",
    )

    bootstrap_parser = subparsers.add_parser(
        "bootstrap",
        help=(
            "ADR-033 least-privilege service-account bootstrap orchestration. The only mutating "
            "subcommand in this CLI -- verified offline only."
        ),
        description=(
            "Journal-aware, locking, deterministic orchestration of the already-implemented ADR-033 "
            "security-bootstrap stack: creates or additively syncs the one fixed, least-privilege "
            "pfsense-mcp service account against the target configured entirely through environment "
            "variables (the same PFSENSE_*/PFSENSE_ADMIN_* variables build_admin_context() already "
            "validates -- no separate flags exist for target/credentials). May provision real security "
            "prerequisites when later run against a real appliance -- THIS implemented slice has been "
            "verified offline only (synthetic/fake HTTP fixtures); no live execution is authorized by "
            "the development task that built it. `pfsense-mcp-security setup` (a future interactive "
            "wizard) is a separate, not-yet-implemented command; `bootstrap` is the deterministic, "
            "non-interactive command underneath it. Supply secrets (admin API key, admin password, "
            "journal integrity key) through the configured file paths, never inline -- shell history "
            "would otherwise capture them."
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
            "This offline-only build never supplies a live server observation to restart "
            "classification: any pre-existing journal for the same target/account/profile is always "
            "conservatively treated as requiring recovery attention on a later run, even one that ended "
            "as cleanly as possible -- a deliberate, fail-closed limitation of this slice, not a bug. "
            "Only a future, separately-authorized live-verification slice can safely distinguish "
            "'already done, all good' from 'needs review' without manual state inspection.\n\n"
            "Never prints, logs, or serializes an API key, password, or any other secret value. A "
            "freshly generated service-account key is written only to the owner-only "
            "PFSENSE_SERVICE_API_KEY_FILE custody path."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    bootstrap_parser.add_argument(
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
    if as_json:
        print(json.dumps(_doctor_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_doctor_human(result), file=out)
    return 0 if result.ready else _DOCTOR_NOT_READY_EXIT_CODE


def _run_bootstrap(*, as_json: bool, env: dict[str, str] | None, out: TextIO) -> int:
    result = run_bootstrap_from_environment(env)
    if as_json:
        print(json.dumps(_bootstrap_result_to_dict(result), indent=2, sort_keys=True), file=out)
    else:
        print(_format_bootstrap_human(result), file=out)
    return _BOOTSTRAP_EXIT_CODES[result.outcome]


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

    parser.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
