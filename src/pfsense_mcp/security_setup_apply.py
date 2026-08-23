"""`pfsense-mcp-security setup apply` -- Slice 2: READ-only apply.

Composes, never reimplements: `generate_setup_plan()`/
`compute_setup_plan_digest()` (Slice 1, unchanged), `load_config()`/
`load_api_key()`/`build_pfsense_client()` (the exact same dependency-
construction path every real MCP server startup already uses via
`application.py`), and `run_doctor_checks()` (unchanged). Adds exactly
one new primitive: `security_setup_apply_confirmation`'s plan-bound
HMAC token.

Scope, deliberately narrow (this run's own owner decisions + the
design report's own Slice 2 definition, `reports-ai/SETUP_WIZARD_DESIGN_2026-08-23.md`
Section 20 item 2): **read_only posture only**. `write_protected`
returns `NOT_SUPPORTED_FOR_POSTURE` before any pfSense contact --
WRITE-protected apply (composing `bootstrap`, and RECOVERY_REQUIRED
inline delegation for it) is a later slice, not this module's job.

**Zero pfSense mutation, in every outcome, always.** The only pfSense
call this module ever makes is one read-only `GET`
(`PfSenseClient.get_system_status()`), for the read_only posture only,
made only after the confirmation token has already been verified --
proving the operator's existing runtime configuration (the exact same
`PFSENSE_API_URL`/`PFSENSE_IDENTITY`/`PFSENSE_API_KEY_FILE`/TLS
settings the real MCP server would use) actually connects, nothing
more. This module never imports `write_api_client`/`WriteApiClient`/
`build_write_client` -- there is no write-capable code path anywhere
in it.

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
from .security_discovery import AnchorAssurance, CapabilityPosture
from .security_doctor import run_doctor_checks
from .security_setup_apply_confirmation import (
    ApplyConfirmationBinding,
    confirmation_token_matches,
    derive_confirmation_token,
)
from .security_setup_plan import generate_setup_plan
from .security_setup_plan_digest import compute_setup_plan_digest

_MAX_CONFIRM_KEY_BYTES = 4096


class ApplyOutcome(str, Enum):
    """Every outcome `run_setup_apply_from_environment()` can return.
    Deliberately exhaustive and independently numbered at the CLI layer
    (`security_cli.py`'s own `_SETUP_APPLY_EXIT_CODES`) -- mirrors
    `RecoveryOrchestrationOutcome`'s own discipline: no outcome is ever
    collapsed into a generic "failed"."""

    INSPECT_PLAN_CURRENT = "inspect_plan_current"
    PLAN_STALE = "plan_stale"
    CONFIRM_TOKEN_INVALID = "confirm_token_invalid"  # nosec B105 -- an outcome enum value, not a credential
    NOT_SUPPORTED_FOR_POSTURE = "not_supported_for_posture"
    BLOCKED_CONFIGURATION_ERROR = "blocked_configuration_error"
    CONNECTIVITY_FAILED = "connectivity_failed"
    DOCTOR_NOT_READY = "doctor_not_ready"
    APPLY_COMPLETED = "apply_completed"


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


def _read_confirm_key(path: Path) -> bytes:
    """Local disk read only, same O_NOFOLLOW + owner-only-permission +
    bounded-size discipline `config.py`'s own API-key loading and
    `security_admin_composition.py`'s own journal-integrity-key loading
    already use -- reused via `secure_file.py`'s shared primitives,
    duplicated as a thin wrapper rather than importing either of those
    two modules directly (keeping this module's own dependency graph
    exactly as narrow as its actual job needs)."""

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
    plan_digest: str | None = None,
    confirm_token: str | None = None,
) -> ApplyResult:
    """Pure orchestration over already-reviewed primitives -- no logic
    here is a mutating primitive in its own right. Order of operations
    is deliberate and fail-closed: recompute the plan and check
    staleness *before* even loading the confirmation key; verify the
    confirmation token *before* checking posture support; check posture
    support *before* touching pfSense config/credentials at all; load
    config/credentials *before* the one live GET; the live GET always
    happens *before* `doctor` (connectivity is the more fundamental
    fact). No step after a failure is ever reached."""

    try:
        posture = CapabilityPosture(target_capability_posture)
        anchor = AnchorAssurance(target_anchor_assurance)
    except ValueError as exc:
        return ApplyResult(ApplyOutcome.BLOCKED_CONFIGURATION_ERROR, str(exc))

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

    if posture is not CapabilityPosture.READ_ONLY:
        return ApplyResult(
            ApplyOutcome.NOT_SUPPORTED_FOR_POSTURE,
            "Protected-write apply is not implemented in this slice. Use `pfsense-mcp-security "
            "bootstrap` directly for ADR-033 account provisioning, or wait for a future setup slice.",
            plan_digest=fresh_digest,
        )

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

    doctor_result = run_doctor_checks(env)
    if anchor is AnchorAssurance.HARDWARE_WITNESS and not doctor_result.ready:
        return ApplyResult(
            ApplyOutcome.DOCTOR_NOT_READY,
            "Connectivity verified, but the hardware witness anchor is not ready per `doctor`. Run "
            "`pfsense-mcp-security doctor` for detail.",
            plan_digest=fresh_digest,
            doctor_ready=False,
        )

    return ApplyResult(
        ApplyOutcome.APPLY_COMPLETED,
        "Connectivity verified against the configured pfSense target. No pfSense state was changed "
        "(read_only posture performs no provisioning).",
        plan_digest=fresh_digest,
        doctor_ready=doctor_result.ready,
    )
