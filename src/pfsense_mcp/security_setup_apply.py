"""`pfsense-mcp-security setup apply` -- Slice 2 (READ-only apply) +
Slice 3 (WRITE-protected apply, composing ADR-033 `bootstrap`) + Slice 4
(inline `RECOVERY_REQUIRED` delegation).

Composes, never reimplements: `generate_setup_plan()`/
`compute_setup_plan_digest()` (Slice 1, unchanged), `load_config()`/
`load_api_key()`/`build_pfsense_client()` (the exact same dependency-
construction path every real MCP server startup already uses via
`application.py`), `run_doctor_checks()` (unchanged), `security_bootstrap_orchestration.
run_bootstrap_from_environment()` (Slice 3), and -- new in Slice 4 --
`security_recovery_orchestration.run_recovery_from_environment()`, the
exact same sole gateways `security_cli.py`'s own `bootstrap`/`recover`
subcommands already use to reach the deeper, already-reviewed ADR-033
stack. This module reaches that stack only through those two
orchestration functions, never through any module either composes --
a dedicated structural test enforces that by name, treating this
module as a second legitimate entry point into both orchestration
bridges, alongside `security_cli.py` itself. Adds exactly one new
primitive of its own: `security_setup_apply_confirmation`'s plan-bound
HMAC token.

**Slice 4: inline `RECOVERY_REQUIRED` delegation**
(`reports-ai/SETUP_WIZARD_DESIGN_2026-08-23.md` §10(b), option (b)).
When `write_protected` bootstrap composition itself reports
`BLOCKED_PRIOR_OPERATION`, this module additionally calls
`run_recovery_from_environment(env)` with **no** `execute_action`/
`confirm_token` -- the exact same read-only inspection bare
`pfsense-mcp-security recover` performs by default -- and surfaces
whatever it returns (`recovery_outcome`/`recovery_action`/
`recovery_confirmation_token`) directly in `ApplyResult`, sparing the
operator a second command just to see the detail. This module never
supplies `execute_action`/`confirm_token` under any circumstance: doing
so would synthesize or auto-confirm recovery on the operator's behalf,
exactly what the design explicitly forbids. Executing recovery still
always requires the operator's own separate, explicit
`pfsense-mcp-security recover --execute <ACTION> --confirm <TOKEN>`
invocation -- "the exact same way they would outside the wizard."

**Posture scope, both now supported:**

- `read_only`: two account modes, security-bound into the plan/digest/
  confirmation-token itself via `read_only_account_mode` (POST-v1.0
  MANAGED READ-ONLY WIZARD INTEGRATION mission, 2026-08-29; see
  `security_setup_plan.ReadOnlyAccountMode`/`security_setup_apply_
  confirmation.py`'s own docstrings for why this must be digest-bound,
  not merely presentational):
    - `byo` (default, unchanged from Slice 2): one read-only `GET`
      (`PfSenseClient.get_system_status()`) against the operator's
      existing bring-your-own-key runtime configuration. Never mutates
      anything.
    - `managed`: composes `run_readonly_bootstrap_from_environment()`
      (the live-LAB-verified POST-v1.0 MANAGED READ-ONLY DEFENSE IN
      DEPTH mission's own function) to provision (or verify/repair) the
      dedicated `pfsense-mcp-readonly` least-privilege service account
      -- never a second, independent provisioning engine. Mirrors
      `write_protected`'s own `run_bootstrap_from_environment()`
      composition exactly, including the `anchor_assurance=
      hardware_witness` doctor-before-lock ordering.
- `write_protected` (Slice 3): composes `run_bootstrap_from_environment()`
  to provision (or verify/repair) the fixed ADR-033 least-privilege
  service account, using the operator's separately-configured ADR-033
  admin credentials (`PFSENSE_ADMIN_*`/`PFSENSE_SERVICE_API_KEY_FILE`/
  etc. -- the exact same env vars standalone `bootstrap` already
  requires). This composition does **not** by itself make any new WRITE
  tool reachable through the MCP server -- the public MCP contract (100
  READ + 2 guidance + 0 default-reachable WRITE) is unaffected by
  provisioning this account; Tier 1's own store/witness provisioning
  remains a separate, still-manual prerequisite for the resulting
  account's privileges to ever become operationally exercised writes
  (`reports-ai/SETUP_WIZARD_DESIGN_2026-08-23.md` Section 20 item 3).
  For `anchor_assurance=hardware_witness` specifically, `run_doctor_checks()`
  gates *before* `run_bootstrap_from_environment()` is ever called --
  blocking, not informational, since (unlike `read_only`'s harmless GET)
  a write_protected apply's one composed call can acquire a lock and
  write a journal. `none`/`software` anchor values proceed to bootstrap
  composition unconditionally, exactly mirroring `read_only`'s own
  anchor-agnostic doctor treatment from Slice 2.

**RECOVERY_REQUIRED is surfaced faithfully, never bypassed.** This
module never constructs its own `AdministrativeContext`, never
classifies restart state itself, never opens or reopens a recovery
journal, and never synthesizes or bypasses a recovery confirmation
token -- `run_bootstrap_from_environment()`'s own existing, already-
reviewed refusal (`BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION`)
is passed straight through as `ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED`,
pointing the operator at the separate, already-implemented
`pfsense-mcp-security recover` command. This module always calls
`run_bootstrap_from_environment()` with `authoritative=None` (the same
offline default `bootstrap` itself uses), so any pre-existing journal
for this target/account/profile is conservatively treated exactly as
that module's own docstring already documents -- no new leniency, no
new automatic recovery attempt, added here.

**Zero pfSense mutation for `read_only`+`byo`, in every outcome, always.**
For `write_protected` and `read_only`+`managed`, the one composed call
is `run_bootstrap_from_environment()` or `run_readonly_bootstrap_from_
environment()` respectively -- both themselves already fully reviewed,
journal-aware, and lock-guarded (`security_bootstrap_orchestration.py`'s
own module docstring); the `read_only`+`managed` composed call only
ever provisions/reconciles the dedicated `pfsense-mcp-readonly`
least-privilege account, itself live-verified to reject WRITE at the
pfSense layer (POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission,
2026-08-29). This module never imports `write_api_client`/
`WriteApiClient`/`build_write_client` -- there is no code path to the
generic MCP WRITE-tool machinery anywhere in it, for any posture or
account mode; the ADR-033 mutation pathway is a separate,
independently-reviewed subsystem.

A plan digest and a confirmation token are never treated as
interchangeable: the digest is recomputed fresh from current discovery
on every call (never trusted from the caller) and compared against the
caller-supplied `--plan-digest` *before* the token is even considered,
so a stale plan is refused before authorization is evaluated at all.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .config import load_api_key, load_config
from .errors import (
    ConfigurationError,
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseResponseShapeError,
)
from .factory import build_pfsense_client
from .secure_file import open_nofollow, validate_descriptor
from .security_bootstrap_orchestration import (
    BootstrapOrchestrationOutcome,
    BootstrapOrchestrationResult,
    run_bootstrap_from_environment,
    run_readonly_bootstrap_from_environment,
)
from .security_discovery import AnchorAssurance, CapabilityPosture
from .security_doctor import run_doctor_checks
from .security_recovery_orchestration import (
    RecoveryOrchestrationResult,
    run_recovery_from_environment,
)
from .security_setup_apply_confirmation import (
    ApplyConfirmationBinding,
    confirmation_token_matches,
    derive_confirmation_token,
)
from .security_setup_plan import ReadOnlyAccountMode, generate_setup_plan
from .security_setup_plan_digest import compute_setup_plan_digest

_MAX_CONFIRM_KEY_BYTES = 4096


class ApplyOutcome(str, Enum):
    """Every outcome `run_setup_apply_from_environment()` can return.
    Deliberately exhaustive and independently numbered at the CLI layer
    (`security_cli.py`'s own `_SETUP_APPLY_EXIT_CODES`) -- mirrors
    `RecoveryOrchestrationOutcome`'s own discipline: no outcome is ever
    collapsed into a generic "failed".

    There is deliberately no `NOT_SUPPORTED_FOR_POSTURE` value (Slice 2
    had one; Slice 3 removed it): `CapabilityPosture` has exactly two
    members and both are now fully supported by this function, so that
    branch became genuinely unreachable rather than merely unlikely --
    keeping a documented-but-dead exit code would have been actively
    misleading to a reader of `setup apply --help`."""

    INSPECT_PLAN_CURRENT = "inspect_plan_current"
    PLAN_STALE = "plan_stale"
    CONFIRM_TOKEN_INVALID = "confirm_token_invalid"  # nosec B105 -- an outcome enum value, not a credential
    BLOCKED_CONFIGURATION_ERROR = "blocked_configuration_error"
    CONNECTIVITY_FAILED = "connectivity_failed"
    DOCTOR_NOT_READY = "doctor_not_ready"
    APPLY_COMPLETED = "apply_completed"
    #: `write_protected`, via `run_bootstrap_from_environment()`'s own
    #: `BootstrapOrchestrationOutcome` -- see `_map_bootstrap_result()`.
    BOOTSTRAP_ALREADY_COMPLETE = "bootstrap_already_complete"
    BOOTSTRAP_COMPLETED = "bootstrap_completed"
    BOOTSTRAP_LOCK_CONTENTION = "bootstrap_lock_contention"
    #: The faithful, non-bypassed surfacing of ADR-033 RECOVERY_REQUIRED-
    #: shaped state -- see this module's own docstring.
    BOOTSTRAP_RECOVERY_REQUIRED = "bootstrap_recovery_required"
    BOOTSTRAP_CORRUPT_LOCAL_STATE = "bootstrap_corrupt_local_state"
    BOOTSTRAP_PREFLIGHT_DERIVATION_FAILED = "bootstrap_preflight_derivation_failed"
    BOOTSTRAP_PROVISIONING_FAILED = "bootstrap_provisioning_failed"


class ApplyError(Exception):
    """Raised only internally by this module's own confirmation-key
    loading; never escapes `run_setup_apply_from_environment()`."""


@dataclass(frozen=True)
class ApplyResult:
    outcome: ApplyOutcome
    detail: str
    plan_digest: str | None = None
    confirmation_token: str | None = None
    doctor_ready: bool | None = None
    #: Slice 4 inline RECOVERY_REQUIRED delegation (design report §10(b)):
    #: populated only when `outcome is BOOTSTRAP_RECOVERY_REQUIRED`, from
    #: a read-only `run_recovery_from_environment(env)` inspection call
    #: (never `execute_action`/`confirm_token` -- see this module's own
    #: docstring). `recovery_outcome` is always the exact
    #: `RecoveryOrchestrationOutcome` value that inspection returned,
    #: never collapsed or reinterpreted -- it may be anything inspection
    #: can return (`recovery_needed`, `recovery_already_complete`,
    #: `blocked_ambiguous_recovery_state`, `blocked_candidate_not_identifiable`,
    #: `blocked_configuration_error`, `blocked_corrupt_local_state`, or
    #: even `no_recovery_needed` if state changed between the two
    #: classify() calls). `recovery_confirmation_token` is present only
    #: for `recovery_needed` -- the exact token a subsequent, separate
    #: `pfsense-mcp-security recover --execute <ACTION> --confirm <TOKEN>`
    #: invocation would need; this module never supplies it on the
    #: operator's behalf.
    recovery_outcome: str | None = None
    recovery_action: str | None = None
    recovery_confirmation_token: str | None = None


def _read_confirm_key(path: Path) -> bytes:
    """Local disk read only, same O_NOFOLLOW + owner-only-permission +
    bounded-size discipline `config.py`'s own API-key loading and the
    ADR-033 admin stack's own journal-integrity-key loading already use
    -- reused via `secure_file.py`'s shared primitives, duplicated as a
    thin wrapper rather than importing either of those two modules
    directly (keeping this module's own dependency graph exactly as
    narrow as its actual job needs)."""

    descriptor = open_nofollow(path, on_error=ApplyError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_MAX_CONFIRM_KEY_BYTES, on_error=ApplyError)
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 65536):
            chunks.append(chunk)
        value = b"".join(chunks)
    except OSError:
        raise ApplyError(f"Setup-apply confirmation key could not be read securely: {path}") from None
    finally:
        os.close(descriptor)
    if not value.strip():
        raise ApplyError(f"Setup-apply confirmation key is empty: {path}")
    return value.strip()


def _load_confirm_key(env: dict[str, str] | None) -> bytes:
    source = env if env is not None else os.environ
    raw_path = source.get("PFSENSE_SETUP_CONFIRM_KEY_FILE")
    if not raw_path or not raw_path.strip():
        raise ApplyError("Missing required environment variable: PFSENSE_SETUP_CONFIRM_KEY_FILE")
    return _read_confirm_key(Path(raw_path).expanduser())


def run_setup_apply_from_environment(
    env: dict[str, str] | None = None,
    *,
    target_capability_posture: str,
    target_anchor_assurance: str,
    target_origin: str | None = None,
    target_identity: str | None = None,
    tls_mode: str | None = None,
    read_only_account_mode: str = ReadOnlyAccountMode.BRING_YOUR_OWN.value,
    plan_digest: str | None = None,
    confirm_token: str | None = None,
) -> ApplyResult:
    """Pure orchestration over already-reviewed primitives -- no logic
    here is a mutating primitive in its own right. Order of operations
    is deliberate and fail-closed: recompute the plan and check
    staleness *before* even loading the confirmation key; verify the
    confirmation token *before* branching on posture at all; only then
    does posture decide which already-reviewed primitive is composed --
    `read_only` loads pfSense config/credentials before its one live
    GET, with `doctor` checked after (connectivity is the more
    fundamental fact for a harmless read) and, like `write_protected`,
    only for `anchor=hardware_witness` -- `doctor`'s own checks are
    exclusively about that optional hardware-witness ceremony, so for
    `none`/`software` anchors it is never run and `doctor_ready` stays
    `None` (v1.0.0 clean-room finding, 2026-08-29: a plain read_only
    apply against `none`/`software` used to run and report `doctor`
    unconditionally, ending a successful read-only onboarding with an
    unexplained `Doctor ready: False` that had nothing to do with the
    posture actually selected); `write_protected` checks `doctor`
    *before* composing `run_bootstrap_from_environment()` for
    `anchor=hardware_witness` (a missing prerequisite must fail closed
    before a lock/journal-touching call, not after). No step after a
    failure is ever reached."""

    try:
        posture = CapabilityPosture(target_capability_posture)
        anchor = AnchorAssurance(target_anchor_assurance)
    except ValueError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))

    try:
        account_mode = ReadOnlyAccountMode(read_only_account_mode)
    except ValueError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))
    if posture is CapabilityPosture.WRITE_PROTECTED and account_mode is not ReadOnlyAccountMode.BRING_YOUR_OWN:
        return ApplyResult(
            ApplyOutcome.BLOCKED_CONFIGURATION_ERROR,
            "read_only_account_mode only applies to target_capability_posture=read_only -- "
            "write_protected always uses the one fixed ADR-033 dedicated account.",
        )

    plan = generate_setup_plan(
        target_capability_posture=posture,
        target_anchor_assurance=anchor,
        target_origin=target_origin,
        target_identity=target_identity,
        tls_mode=tls_mode,
        read_only_account_mode=account_mode.value,
        env=env,
    )
    fresh_digest = compute_setup_plan_digest(plan)

    if plan_digest is not None and fresh_digest != plan_digest:
        return ApplyResult(
            ApplyOutcome.PLAN_STALE,
            "The recomputed plan digest does not match --plan-digest -- current state has changed "
            "since this plan was generated. Run `setup --non-interactive` again to get a current plan.",
            plan_digest=fresh_digest,
        )

    try:
        integrity_key = _load_confirm_key(env)
    except ApplyError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc), plan_digest=fresh_digest)

    binding = ApplyConfirmationBinding(
        plan_digest=fresh_digest,
        target_origin=target_origin,
        target_identity=target_identity,
        capability_posture=posture.value,
        anchor_assurance=anchor.value,
        read_only_account_mode=(account_mode.value if posture is CapabilityPosture.READ_ONLY else None),
    )
    expected_token = derive_confirmation_token(binding, integrity_key=integrity_key)

    if confirm_token is None:
        return ApplyResult(
            ApplyOutcome.INSPECT_PLAN_CURRENT,
            "Plan is current. Re-run with --confirm <TOKEN> (shown below) to apply it.",
            plan_digest=fresh_digest,
            confirmation_token=expected_token,
        )

    if not confirmation_token_matches(confirm_token, binding, integrity_key=integrity_key):
        return ApplyResult(
            ApplyOutcome.CONFIRM_TOKEN_INVALID,
            "The supplied --confirm token does not match this exact plan/target/posture. Refused "
            "before any pfSense contact.",
            plan_digest=fresh_digest,
        )

    if posture is CapabilityPosture.WRITE_PROTECTED:
        return _run_write_protected_apply(env, anchor=anchor, fresh_digest=fresh_digest)

    if account_mode is ReadOnlyAccountMode.MANAGED:
        return _run_managed_readonly_apply(env, anchor=anchor, fresh_digest=fresh_digest)

    try:
        config = load_config(env)
    except ConfigurationError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc), plan_digest=fresh_digest)

    try:
        api_key = load_api_key(config)
    except ConfigurationError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc), plan_digest=fresh_digest)

    transport, client = build_pfsense_client(config, api_key)
    try:
        client.get_system_status(include_identifying_metadata=False)
    except (PfSenseConnectionError, PfSenseAuthError, PfSenseAPIError, PfSenseResponseShapeError) as exc:
        return ApplyResult(ApplyOutcome.CONNECTIVITY_FAILED, str(exc), plan_digest=fresh_digest)
    finally:
        transport.close()

    doctor_ready: bool | None = None
    if anchor is AnchorAssurance.HARDWARE_WITNESS:
        doctor_result = run_doctor_checks(env)
        if not doctor_result.ready:
            return ApplyResult(
                ApplyOutcome.DOCTOR_NOT_READY,
                "Connectivity verified, but the hardware witness anchor is not ready per `doctor`. Run "
                "`pfsense-mcp-security doctor` for detail.",
                plan_digest=fresh_digest,
                doctor_ready=False,
            )
        doctor_ready = doctor_result.ready

    return ApplyResult(
        ApplyOutcome.APPLY_COMPLETED,
        "Connectivity verified against the configured pfSense target. No pfSense state was changed "
        "(read_only posture performs no provisioning).",
        plan_digest=fresh_digest,
        doctor_ready=doctor_ready,
    )


def _run_write_protected_apply(
    env: dict[str, str] | None, *, anchor: AnchorAssurance, fresh_digest: str
) -> ApplyResult:
    """The `write_protected` branch -- reached only after plan
    freshness and the confirmation token have already been verified.

    For `anchor_assurance=hardware_witness`, `doctor` is checked
    *before* `run_bootstrap_from_environment()` is called at all --
    blocking, not informational (unlike Slice 2's read_only ordering,
    where the one live call is a harmless GET): a write_protected
    apply's composed call can acquire a lock and write a journal, so
    failing closed on a missing prerequisite happens before any of
    that, per this run's own requirement to fail closed on missing
    prerequisites ahead of a mutating call. `none`/`software` anchors
    proceed unconditionally, mirroring read_only's own anchor-agnostic
    treatment.

    `run_bootstrap_from_environment()` is called with no explicit
    `authoritative` override -- the exact same call standalone
    `bootstrap` itself makes. As of the restart-classification
    improvement, that function itself now builds a fresh, live
    `AuthoritativeRestartObservation` automatically whenever a local
    journal already exists for this target/account/profile, so a
    genuinely completed prior operation can resolve to
    `ALREADY_COMPLETE`; a prior incomplete/failed/ambiguous attempt, or
    any live mismatch, is still refused exactly as conservatively as
    it already was, never more leniently -- see
    `build_authoritative_restart_observation()`'s own docstring for the
    exact evidence this requires."""

    if anchor is AnchorAssurance.HARDWARE_WITNESS:
        doctor_result = run_doctor_checks(env)
        if not doctor_result.ready:
            return ApplyResult(
                ApplyOutcome.DOCTOR_NOT_READY,
                "The hardware witness anchor is not ready per `doctor` -- refusing to start bootstrap "
                "provisioning before any lock or journal is touched. Run `pfsense-mcp-security doctor` "
                "for detail.",
                plan_digest=fresh_digest,
                doctor_ready=False,
            )

    bootstrap_result = run_bootstrap_from_environment(env)
    return _map_bootstrap_result(bootstrap_result, env=env, fresh_digest=fresh_digest, target_profile="write_protected")


def _run_managed_readonly_apply(
    env: dict[str, str] | None, *, anchor: AnchorAssurance, fresh_digest: str
) -> ApplyResult:
    """The `read_only` + `read_only_account_mode=managed` branch -- reached only after plan
    freshness and the confirmation token (itself bound to `read_only_account_mode`, see
    `security_setup_apply_confirmation.py`) have already been verified. Mirrors
    `_run_write_protected_apply()` exactly, composing `run_readonly_bootstrap_from_environment()`
    (the live-LAB-verified POST-v1.0 MANAGED READ-ONLY DEFENSE IN DEPTH mission's own function)
    instead of `run_bootstrap_from_environment()` -- never a second, independent provisioning
    engine. Same `anchor_assurance=hardware_witness` doctor-before-lock ordering as write_protected,
    for the identical reason: this composed call can also acquire a lock and write a journal."""

    if anchor is AnchorAssurance.HARDWARE_WITNESS:
        doctor_result = run_doctor_checks(env)
        if not doctor_result.ready:
            return ApplyResult(
                ApplyOutcome.DOCTOR_NOT_READY,
                "The hardware witness anchor is not ready per `doctor` -- refusing to start managed "
                "read-only provisioning before any lock or journal is touched. Run "
                "`pfsense-mcp-security doctor` for detail.",
                plan_digest=fresh_digest,
                doctor_ready=False,
            )

    bootstrap_result = run_readonly_bootstrap_from_environment(env)
    return _map_bootstrap_result(bootstrap_result, env=env, fresh_digest=fresh_digest, target_profile="read_only")


def _map_bootstrap_result(
    result: BootstrapOrchestrationResult, *, env: dict[str, str] | None, fresh_digest: str, target_profile: str
) -> ApplyResult:
    """Translates `BootstrapOrchestrationResult` into `ApplyResult` 1:1,
    never collapsing distinct outcomes and never inventing new meaning
    for any of them -- `result.detail` (already sanitized by the
    orchestration/engine layers) is passed through verbatim or lightly
    extended, never replaced. `target_profile` ("write_protected" or
    "read_only") is threaded through only to reach the correct account's
    own journal if `_inline_recovery_inspection()` is needed -- it never
    changes how any other outcome is mapped."""

    detail = result.detail
    if result.outcome is BootstrapOrchestrationOutcome.ALREADY_COMPLETE:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_ALREADY_COMPLETE, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.COMPLETED:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_COMPLETED, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CONFIGURATION_ERROR:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.BLOCKED_LOCK_CONTENTION:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_LOCK_CONTENTION, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.BLOCKED_PRIOR_OPERATION:
        return _inline_recovery_inspection(
            env, bootstrap_detail=detail, fresh_digest=fresh_digest, target_profile=target_profile
        )
    if result.outcome is BootstrapOrchestrationOutcome.BLOCKED_CORRUPT_LOCAL_STATE:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_CORRUPT_LOCAL_STATE, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.PREFLIGHT_DERIVATION_FAILED:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_PREFLIGHT_DERIVATION_FAILED, detail, plan_digest=fresh_digest)
    if result.outcome is BootstrapOrchestrationOutcome.PROVISIONING_FAILED:
        return ApplyResult(ApplyOutcome.BOOTSTRAP_PROVISIONING_FAILED, detail, plan_digest=fresh_digest)
    raise AssertionError(f"unhandled BootstrapOrchestrationOutcome: {result.outcome}")  # pragma: no cover


def _inline_recovery_inspection(
    env: dict[str, str] | None, *, bootstrap_detail: str, fresh_digest: str, target_profile: str
) -> ApplyResult:
    """Slice 4: inline RECOVERY_REQUIRED delegation
    (`reports-ai/SETUP_WIZARD_DESIGN_2026-08-23.md` §10(b), option (b)
    "Delegate inline"). Reached only when bootstrap composition itself
    already reported `BLOCKED_PRIOR_OPERATION` -- this function never
    decides on its own that recovery is needed.

    Calls `run_recovery_from_environment(env, target_profile=target_profile)` with **no**
    `execute_action`/`confirm_token` -- the exact same read-only
    inspection bare `pfsense-mcp-security recover --target-profile <target_profile>` itself
    performs by default. `target_profile` (added for the POST-v1.0 MANAGED READ-ONLY WIZARD
    INTEGRATION mission, 2026-08-29) is never inferred or guessed here -- it is always the exact
    profile `_map_bootstrap_result()`'s own caller already used for the bootstrap composition that
    just reported `BLOCKED_PRIOR_OPERATION`, so this inspection reads that same account's own
    journal, never the other one's. No lock is acquired, no journal is written, by that
    function's own existing, unmodified contract. This function never
    passes an `execute_action` or a `confirm_token` under any
    circumstance -- doing so would be exactly the "synthesize, pre-fill,
    or auto-supply the confirmation token on the operator's behalf" the
    design explicitly forbids. Whatever `run_recovery_from_environment()`
    returns is surfaced verbatim (`recovery_outcome`/`recovery_action`/
    `recovery_confirmation_token`), never collapsed, reinterpreted, or
    filtered -- including the (rare, TOCTOU) case where state changed
    between bootstrap's own classify() and this one and inspection now
    reports `no_recovery_needed`."""

    recovery_result: RecoveryOrchestrationResult = run_recovery_from_environment(env, target_profile=target_profile)
    profile_flag = "" if target_profile == "write_protected" else f" --target-profile {target_profile}"
    return ApplyResult(
        ApplyOutcome.BOOTSTRAP_RECOVERY_REQUIRED,
        f"{bootstrap_detail} Inline recovery inspection: {recovery_result.detail} To resolve, run "
        f"`pfsense-mcp-security recover{profile_flag} --execute <ACTION> --confirm <TOKEN>` yourself -- "
        "this command never attempts or auto-confirms recovery.",
        plan_digest=fresh_digest,
        recovery_outcome=recovery_result.outcome.value,
        recovery_action=(recovery_result.recovery_action.value if recovery_result.recovery_action else None),
        recovery_confirmation_token=recovery_result.confirmation_token,
    )
