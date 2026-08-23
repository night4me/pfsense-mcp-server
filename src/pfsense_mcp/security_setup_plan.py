"""`pfsense-mcp-security setup` (Slice 1): non-mutating discovery +
plan-only composition -- ADR-021's two-axis capability-posture/anchor-
assurance model, plus ADR-033's dedicated-account privilege story, in
one operator-reviewable `SetupPlan`.

This module performs **zero I/O of any kind** -- no filesystem access,
no network access, no SQLite, no environment-variable reads. It is pure
composition over already-computed inputs:

  - `generate_security_posture_plan()` (`security_plan.py`, ADR-021/022)
    supplies the whole capability-posture/anchor-assurance axis analysis
    verbatim -- this module never re-derives or duplicates any of it,
    only adds the ADR-033 account/privilege content that module does not
    cover (see `generate_setup_plan()`'s own docstring for exactly what
    is added and why).
  - `security_privileges.py`'s pure privilege-derivation functions
    (`resolve_profile_privileges()`, `distinct_ok_privileges()`,
    `check_package_version_support()`) supply the privilege/version
    content, given an already-loaded schema `dict` -- this module never
    loads a schema file itself; the CLI layer (`security_cli.py`) is
    responsible for any local file read, entirely optional, and never a
    live network probe (`pfsense-mcp-security setup` OWNER DECISION 6:
    "manual/default deliberate behavior for version/schema detection --
    do not silently add extra live probes").

Deliberately does **not** import `security_admin_composition.py`,
`security_bootstrap_*.py`, or `security_recovery_*.py` -- those modules
require live transport factories to construct an `AdministrativeContext`
even for read-only journal inspection, which this module has no need
for and must not acquire (Slice 1's own HARD SLICE-1 INVARIANT: "Prefer
pure/local discovery where possible"). One direct consequence: this
slice does **not** detect ADR-033 `RECOVERY_REQUIRED` state -- see
`generate_setup_plan()`'s docstring and `unsupported_steps` for the
explicit, non-silent statement of this gap and the exact operator
guidance (`pfsense-mcp-security recover`) `SetupPlan` records instead.

Never imports `pfsense_mcp.tier1`, `pfsense_mcp.tier1.canonical`
included -- digest computation over a `SetupPlan` lives in the sibling
module `security_setup_plan_digest.py`, mirroring the existing
`security_plan.py`/`security_plan_digest.py` split exactly, so this
module's own isolation boundary never needs to include tier1 hashing
machinery it has no other reason to import."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .security_discovery import AnchorAssurance, CapabilityPosture
from .security_plan import SecurityPosturePlan, generate_security_posture_plan
from .security_privileges import (
    VERIFIED_PACKAGE_VERSION_MAX,
    VERIFIED_PACKAGE_VERSION_MIN,
    check_package_version_support,
    distinct_ok_privileges,
    read_profile_requirements,
    resolve_profile_privileges,
    write_protected_profile_requirements,
)

#: Bumped whenever a `SetupPlan` field is added, removed, or
#: reinterpreted. Not itself a digest-participating mechanism choice --
#: see `security_setup_plan_digest.py`'s own docstring for why the
#: digest is mechanism-agnostic.
SETUP_PLAN_SCHEMA_VERSION = 1

#: The fixed ADR-033 dedicated administrative/service-account identity
#: this codebase's bootstrap/recovery stack already uses. Duplicated
#: here as a local constant, deliberately not imported from
#: `security_bootstrap_recovery.py` or any other lower-level module --
#: the same "small local constant duplication" precedent that module
#: itself already establishes for `RECOVERY_USERNAME`, chosen
#: specifically to avoid a new cross-module coupling into this
#: intentionally isolated planning module.
INTENDED_SERVICE_ACCOUNT_IDENTITY = "pfsense-mcp"


@dataclass(frozen=True)
class TargetDescriptor:
    """What the operator entered about the pfSense target. Purely
    operator-declared intent -- Slice 1 never verifies reachability or
    TLS validity against it (no network call exists anywhere in this
    module or its CLI wiring for Slice 1); `reachability_verified` is
    always `False` for exactly that reason, recorded explicitly rather
    than merely omitted, so a future slice that *does* implement
    verification cannot be confused with this one ever having silently
    skipped it."""

    origin: str | None
    identity: str | None
    tls_mode: str | None
    reachability_verified: bool = False


@dataclass(frozen=True)
class PrivilegePlan:
    """The ADR-033 account/privilege content `security_plan.py`'s own
    `SecurityPosturePlan` does not cover (that module's steps describe
    only the older `WriteEndpoints`/`PFSENSE_PROFILE` mechanism, never
    the dedicated-account bootstrap mechanism) -- added here, not
    duplicated there."""

    intended_capability_posture: CapabilityPosture
    intended_account_identity: str
    dedicated_account_provisioning_implemented: bool
    provisioning_note: str
    schema_provided: bool
    required_privileges: tuple[str, ...] | None
    unresolved_requirement_tool_names: tuple[str, ...]


@dataclass(frozen=True)
class VersionEvidence:
    """Manual-only version evidence (OWNER DECISION 6). `None` in every
    field this module was not given -- never silently inferred, never
    live-probed."""

    schema_provided: bool
    declared_package_version: str | None
    package_version_supported: bool | None
    version_note: str


@dataclass(frozen=True)
class SetupPlan:
    """The complete, deterministic output of `generate_setup_plan()`.
    Never itself authorization -- see `notes` and every `unsupported_steps`
    entry, which restate that explicitly. No field anywhere in this
    dataclass (or anything it references) names HMAC, a signing key, a
    signature, or any other specific future authorization mechanism --
    `security_setup_plan_digest.py`'s own docstring explains why that
    separation matters."""

    schema_version: int
    target: TargetDescriptor
    posture_plan: SecurityPosturePlan
    privilege_plan: PrivilegePlan
    version_evidence: VersionEvidence
    planned_local_artifacts: tuple[str, ...]
    planned_pfsense_actions: tuple[str, ...]
    planned_postconditions: tuple[str, ...]
    unsupported_steps: tuple[str, ...]
    notes: tuple[str, ...] = field(default_factory=tuple)


def _parse_declared_version(value: str) -> tuple[int, int, int] | None:
    """Pure, total, never raises. Accepts an `X.Y.Z` decimal triple, an
    `X.Y` pair (patch implicitly `0` -- the natural, common way pfSense
    versions are actually written, e.g. "2.10"), and an optional leading
    `v`/`V` (e.g. "v2.10.0"). This is a parsing-ergonomics improvement
    only: it never widens the *verified* compatibility range itself
    (`check_package_version_support()` is unchanged) and never accepts
    anything ambiguous -- non-numeric components, the wrong arity, or a
    negative/malformed value are still reported as unparseable rather
    than guessed at."""

    text = value.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    parts = text.split(".")
    if len(parts) not in (2, 3):
        return None
    numbers: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        numbers.append(int(part))
    if len(numbers) == 2:
        numbers.append(0)
    return (numbers[0], numbers[1], numbers[2])


def _privilege_plan(
    *,
    target_capability_posture: CapabilityPosture,
    schema: dict[str, Any] | None,
) -> PrivilegePlan:
    if target_capability_posture is CapabilityPosture.WRITE_PROTECTED:
        dedicated_account_provisioning_implemented = True
        provisioning_note = (
            "A dedicated least-privilege administrative bootstrap account can be provisioned via the "
            "existing `pfsense-mcp-security bootstrap` command (ADR-033). This plan does not run it -- "
            "`setup` never executes anything in this slice."
        )
        requirements = write_protected_profile_requirements()
    else:
        dedicated_account_provisioning_implemented = False
        provisioning_note = (
            "Dedicated least-privilege READ-only service-account provisioning is architecturally "
            "intended (`TargetProfile.READ_ONLY` already exists in the bootstrap engine) but has no "
            "implemented provisioning path yet in this codebase. Using a pre-existing, separately "
            "provisioned READ-only credential is the only currently-working option for a read_only "
            "posture; see ADR-033 for status."
        )
        requirements = read_profile_requirements()

    if schema is None:
        return PrivilegePlan(
            intended_capability_posture=target_capability_posture,
            intended_account_identity=INTENDED_SERVICE_ACCOUNT_IDENTITY,
            dedicated_account_provisioning_implemented=dedicated_account_provisioning_implemented,
            provisioning_note=provisioning_note,
            schema_provided=False,
            required_privileges=None,
            unresolved_requirement_tool_names=(),
        )

    url_requirements = [r for r in requirements if r.url is not None and r.method is not None]
    resolved = resolve_profile_privileges(schema, requirements)
    ok_privileges = tuple(sorted(distinct_ok_privileges(resolved)))
    unresolved_tool_names = tuple(
        sorted(req.tool_name for req, result in zip(url_requirements, resolved, strict=True) if not result.ok)
    )
    return PrivilegePlan(
        intended_capability_posture=target_capability_posture,
        intended_account_identity=INTENDED_SERVICE_ACCOUNT_IDENTITY,
        dedicated_account_provisioning_implemented=dedicated_account_provisioning_implemented,
        provisioning_note=provisioning_note,
        schema_provided=True,
        required_privileges=ok_privileges,
        unresolved_requirement_tool_names=unresolved_tool_names,
    )


def _version_evidence(*, schema: dict[str, Any] | None, declared_package_version: str | None) -> VersionEvidence:
    if declared_package_version is None:
        return VersionEvidence(
            schema_provided=schema is not None,
            declared_package_version=None,
            package_version_supported=None,
            version_note=(
                "No pfSense-restapi package version was declared. This slice never probes the target "
                "live for it (OWNER DECISION 6); pass it explicitly if known."
            ),
        )
    parsed = _parse_declared_version(declared_package_version)
    if parsed is None:
        return VersionEvidence(
            schema_provided=schema is not None,
            declared_package_version=declared_package_version,
            package_version_supported=None,
            version_note=(
                "The declared package version could not be parsed. Expected a decimal version such "
                "as 2.10 or 2.10.0, with an optional leading 'v'."
            ),
        )
    canonical = ".".join(map(str, parsed))
    finding = check_package_version_support(parsed)
    supported = finding is None
    verified_range = (
        f"{'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MIN))}-{'.'.join(map(str, VERIFIED_PACKAGE_VERSION_MAX))}"
    )
    note = (
        f"Declared package version is within the verified range {verified_range}."
        if supported
        else f"Declared package version is outside the verified range {verified_range} (advisory only)."
    )
    return VersionEvidence(
        schema_provided=schema is not None,
        declared_package_version=canonical,
        package_version_supported=supported,
        version_note=note,
    )


def generate_setup_plan(
    *,
    target_capability_posture: CapabilityPosture,
    target_anchor_assurance: AnchorAssurance,
    target_origin: str | None = None,
    target_identity: str | None = None,
    tls_mode: str | None = None,
    schema: dict[str, Any] | None = None,
    declared_package_version: str | None = None,
    env: dict[str, str] | None = None,
) -> SetupPlan:
    """Pure composition, mutation-free. Calls
    `generate_security_posture_plan()` exactly once (which itself calls
    `discover_security_posture()` exactly once); performs no other I/O.

    Both enum targets are coerced through their own constructors before
    any other logic runs, mirroring `generate_security_posture_plan()`'s
    own defensive discipline exactly, for the same reason: a plain,
    value-equal string would satisfy `==` but silently fail `is`
    comparisons throughout `security_plan.py`."""

    target_capability_posture = CapabilityPosture(target_capability_posture)
    target_anchor_assurance = AnchorAssurance(target_anchor_assurance)

    posture_plan = generate_security_posture_plan(target_capability_posture, target_anchor_assurance, env)
    privilege_plan = _privilege_plan(target_capability_posture=target_capability_posture, schema=schema)
    version_evidence = _version_evidence(schema=schema, declared_package_version=declared_package_version)

    planned_local_artifacts: list[str] = [
        "No local secrets are generated by this slice (secret generation is planned for a later, "
        "separately-reviewed slice).",
        "No ADR-033 administrative operation journal is created by `setup` itself -- it is only ever "
        "created by `pfsense-mcp-security bootstrap`, a separate command.",
    ]

    planned_pfsense_actions: list[str] = [
        f"{step.action} (axis={step.axis}, mutation_class={step.mutation_class.value}, "
        f"implementation_available={step.implementation_available})"
        for step in posture_plan.steps
    ]
    if target_capability_posture is CapabilityPosture.WRITE_PROTECTED:
        planned_pfsense_actions.append(
            "Provision the ADR-033 dedicated least-privilege administrative account via "
            "`pfsense-mcp-security bootstrap` (axis=capability_posture, mutation_class=service_deployment, "
            "implementation_available=True). Not part of `security_plan.py`'s own step list -- that "
            "module describes only the older WriteEndpoints/profile mechanism."
        )

    planned_postconditions: tuple[str, ...] = (
        "`pfsense-mcp-security discover` reports the selected capability_posture and anchor_assurance.",
        "`pfsense-mcp-security doctor` reports READY where applicable to the selected anchor assurance.",
    )

    unsupported_steps: list[str] = [
        "TLS/reachability verification: not implemented in this slice -- no live network call is made "
        "by `setup` at all; the target origin/identity/TLS mode are recorded exactly as entered, "
        "unverified.",
        "Secret generation: not implemented in this slice (approved in principle for a later slice).",
        "MCP client configuration writing: not implemented -- print-only is the permanent default; "
        "`setup` never writes Claude/Codex/ChatGPT configuration files.",
        "ADR-033 RECOVERY_REQUIRED detection: not implemented in this slice (this module never "
        "constructs an administrative context). If a previous `bootstrap` attempt may have failed, run "
        "`pfsense-mcp-security recover` directly to inspect and, if needed, resolve it.",
        "`setup apply` (actual execution of this plan): does not exist in this slice -- `setup` only "
        "ever plans, never executes.",
    ]
    if target_capability_posture is CapabilityPosture.READ_ONLY:
        unsupported_steps.append(
            "Dedicated least-privilege READ-only account provisioning: not implemented -- see "
            "privilege_plan.provisioning_note."
        )

    notes: tuple[str, ...] = (
        "This is a plan, never authorization. Nothing in this build accepts, verifies, or acts on a "
        "generated plan -- see security_setup_plan_digest.py for the plan's deterministic identity value, "
        "which is itself also never authorization.",
        "`setup` never mutates pfSense state and never provisions anything, in every mode, always -- "
        "see the adversarial test suite for the specific proofs.",
    )

    return SetupPlan(
        schema_version=SETUP_PLAN_SCHEMA_VERSION,
        target=TargetDescriptor(
            origin=target_origin,
            identity=target_identity,
            tls_mode=tls_mode,
            reachability_verified=False,
        ),
        posture_plan=posture_plan,
        privilege_plan=privilege_plan,
        version_evidence=version_evidence,
        planned_local_artifacts=tuple(planned_local_artifacts),
        planned_pfsense_actions=tuple(planned_pfsense_actions),
        planned_postconditions=planned_postconditions,
        unsupported_steps=tuple(unsupported_steps),
        notes=notes,
    )
