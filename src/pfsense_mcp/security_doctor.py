"""`pfsense-mcp-security doctor` -- read-only Tier 1 ceremony
preflight/readiness check (`docs/ROADMAP.md`'s "Operator setup and
security postures" section, doctor/preflight item). Combines two
already-established read-only checks into one deterministic READY/
NOT_READY verdict, rather than inventing a second security model:

- **Artifact-exchange path cleanliness.** The Tier 1 production
  runtime (`tier1/production_runtime.py`) uses four fixed,
  environment-derived artifact-exchange files -- the authorization
  inbox, the confirmation-pending outbox, the confirmation-signed
  inbox, and the authorization-preview outbox -- documented there as
  "all-or-nothing with every other required var." Because artifact
  writes use `write_secure_new()`'s exclusive-create discipline (never
  overwrites), a file left over at any of these fixed paths from a
  prior completed or abandoned ceremony silently blocks the next one.
  This module never imports `pfsense_mcp.tier1` -- the four env var
  *names* below are a deliberate, comment-linked duplication of
  `production_runtime.py`'s own constants, not an import, so this
  stays outside tier1's isolation boundary exactly like
  `security_discovery.py`/`security_plan_digest.py`/
  `tier1_anchor_check.py` already do (see
  `tests/tier1/test_isolation.py`). If those upstream names ever
  change, `tests/test_security_doctor.py::test_artifact_path_env_var_names_match_production_runtime`
  fails loudly rather than silently drifting.
- **Witness readiness.** Reuses
  `security_discovery.discover_anchor_assurance()` completely
  unchanged -- no second witness client, no new TPM/network code here
  at all. A ceremony is witness-ready only when the resulting
  `evidence_state` is exactly `PROVISIONED_VERIFIED`; every other
  state (including `PROVISIONED_MISMATCH`, the same anomaly `discover`
  itself already flags) is treated as not ready, fail-closed.

Two real incidents motivated this command (`docs/ROADMAP.md`'s
"Ceremony TTL/operator UX" section): a pre-positioned stale
`confirmation-signed.bin` from a prior completed ceremony, and a
signer whose local witness-store snapshot had gone stale, reporting
`provisioned_mismatch`. `doctor` catches both classes before an
operator spends a ceremony's own limited validity window finding out
the hard way.

**Diagnostic only, structurally.** This module contains no code path
that deletes, moves, archives, or overwrites an artifact; no code path
that mutates witness or store state (`discover_anchor_assurance()`
itself already never calls `advance()` or
`provision_anchor_baseline()`); and no import of
`write_api_client`/`tier1`/any Tier 1 execution primitive. It cannot
construct a `RecoveryContract`, sign anything, or contact pfSense.

**Known, deliberate limitation**: this checks exactly the two
categories above, not the full `build_production_runtime()`
prerequisite set (store configuration, encryption/authority key files,
the consumption store, etc.) -- checking those was out of scope for
this phase. A `doctor` result of READY means "the artifact-exchange
paths are clean and the witness is currently verified," not "every
precondition `build_production_runtime()` itself checks is satisfied."
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from .security_discovery import AnchorEvidenceState, discover_anchor_assurance

# Mirrors tier1/production_runtime.py's own _AUTHORIZATION_INBOX_FILE_VAR /
# _CONFIRMATION_PENDING_FILE_VAR / _CONFIRMATION_SIGNED_FILE_VAR /
# _AUTHORIZATION_PREVIEW_FILE_VAR exactly -- duplicated as plain strings
# (not imported) to keep this module outside tier1's isolation boundary.
# See this module's own docstring and
# tests/test_security_doctor.py::test_artifact_path_env_var_names_match_production_runtime.
_AUTHORIZATION_INBOX_FILE_VAR = "PFSENSE_TIER1_AUTHORIZATION_INBOX_FILE"
_CONFIRMATION_PENDING_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_PENDING_FILE"
_CONFIRMATION_SIGNED_FILE_VAR = "PFSENSE_TIER1_CONFIRMATION_SIGNED_FILE"
_AUTHORIZATION_PREVIEW_FILE_VAR = "PFSENSE_TIER1_AUTHORIZATION_PREVIEW_FILE"

# (check_id, human description, env var name) -- order is the order
# checks are reported in, matching the ceremony's own document order
# (inbox -> pending -> signed -> preview).
_ARTIFACT_PATH_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "artifact_exchange.authorization_inbox",
        "Signed PlanAuthorizationV2 inbox",
        _AUTHORIZATION_INBOX_FILE_VAR,
    ),
    (
        "artifact_exchange.confirmation_pending",
        "Unsigned PendingConfirmationRequest outbox",
        _CONFIRMATION_PENDING_FILE_VAR,
    ),
    (
        "artifact_exchange.confirmation_signed",
        "Signed ConfirmationEvidence inbox",
        _CONFIRMATION_SIGNED_FILE_VAR,
    ),
    (
        "artifact_exchange.authorization_preview",
        "Non-authorizing AuthorizationPreview outbox",
        _AUTHORIZATION_PREVIEW_FILE_VAR,
    ),
)

_WITNESS_CHECK_ID = "witness_readiness"


class CheckStatus(str, Enum):
    """Three-way, not a bool: `NOT_CONFIGURED` is deliberately distinct
    from `FAIL` so an operator (or automation) can tell "you haven't
    set this up yet" apart from "you set it up and it is currently
    broken" -- both make the overall result NOT_READY, but they call
    for different remediation."""

    PASS = "pass"  # nosec B105 -- a check-result enum value, not a credential
    FAIL = "fail"
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True)
class DoctorCheck:
    check_id: str
    description: str
    status: CheckStatus
    detail: str


@dataclass(frozen=True)
class DoctorResult:
    ready: bool
    checks: tuple[DoctorCheck, ...]


def _artifact_present(path: Path) -> bool:
    """Identical semantics to `production_runtime.py`'s own private
    `_artifact_present()`: `lexists`-equivalent, so a broken symlink
    (target missing) still counts as "something is here" rather than
    being silently treated as an empty handoff location."""

    return path.is_symlink() or path.exists()


def _check_artifact_path(
    check_id: str, description: str, env_var_name: str, source: dict[str, str] | os._Environ[str]
) -> DoctorCheck:
    raw = source.get(env_var_name)
    if raw is None or raw.strip() == "":
        return DoctorCheck(
            check_id=check_id,
            description=description,
            status=CheckStatus.NOT_CONFIGURED,
            detail=f"{env_var_name} is not set -- Tier 1 artifact exchange is not configured on this host.",
        )

    path = Path(raw).expanduser()
    if not path.is_absolute():
        return DoctorCheck(
            check_id=check_id,
            description=description,
            status=CheckStatus.FAIL,
            detail=f"{env_var_name} must be an absolute path (got {raw!r}).",
        )

    if not path.parent.is_dir():
        return DoctorCheck(
            check_id=check_id,
            description=description,
            status=CheckStatus.FAIL,
            detail=f"Expected exchange directory does not exist: {path.parent}",
        )

    if not os.access(path.parent, os.W_OK):
        return DoctorCheck(
            check_id=check_id,
            description=description,
            status=CheckStatus.FAIL,
            detail=f"Exchange directory exists but is not writable: {path.parent}",
        )

    if _artifact_present(path):
        return DoctorCheck(
            check_id=check_id,
            description=description,
            status=CheckStatus.FAIL,
            detail=(
                f"A file already exists at {path} -- likely left over from a previous ceremony. "
                "Archive or remove it by hand before starting a new one; doctor never does this "
                "automatically."
            ),
        )

    return DoctorCheck(
        check_id=check_id,
        description=description,
        status=CheckStatus.PASS,
        detail=f"{path} is absent, as expected before a new ceremony.",
    )


def _check_witness_readiness(env: dict[str, str] | None) -> DoctorCheck:
    discovery = discover_anchor_assurance(env)

    if discovery.evidence_state is AnchorEvidenceState.UNCONFIGURED:
        return DoctorCheck(
            check_id=_WITNESS_CHECK_ID,
            description="TPM anti-rollback witness readiness",
            status=CheckStatus.NOT_CONFIGURED,
            detail="Tier 1 store/witness is not configured on this host (evidence_state=unconfigured).",
        )

    if discovery.evidence_state is AnchorEvidenceState.PROVISIONED_VERIFIED:
        return DoctorCheck(
            check_id=_WITNESS_CHECK_ID,
            description="TPM anti-rollback witness readiness",
            status=CheckStatus.PASS,
            detail=(f"Witness verified and matches the persisted baseline (value={discovery.witness_value})."),
        )

    # Every other evidence_state -- configuration_invalid, store_error,
    # configured_unprovisioned, provisioned_unverified,
    # provisioned_unreachable, provisioned_mismatch -- means "cannot
    # currently prove the witness is in a good, current state," which
    # this check treats identically: fail closed, never guess.
    return DoctorCheck(
        check_id=_WITNESS_CHECK_ID,
        description="TPM anti-rollback witness readiness",
        status=CheckStatus.FAIL,
        detail=(
            f"Witness/store evidence_state={discovery.evidence_state.value!r}, not provisioned_verified -- "
            + (discovery.evidence[-1] if discovery.evidence else "see `pfsense-mcp-security discover` for detail.")
        ),
    )


def run_doctor_checks(env: dict[str, str] | None = None) -> DoctorResult:
    """Read-only. Runs the four artifact-exchange path checks plus the
    one witness-readiness check and returns a single deterministic
    result. Never mutates a file, a witness, or any store -- every
    check below only reads filesystem metadata (`Path.exists()`/
    `Path.is_dir()`/`os.access()`) or delegates to
    `discover_anchor_assurance()`, itself already proven read-only."""

    source = env if env is not None else os.environ
    checks = tuple(
        _check_artifact_path(check_id, description, env_var_name, source)
        for check_id, description, env_var_name in _ARTIFACT_PATH_CHECKS
    )
    checks = (*checks, _check_witness_readiness(env))
    ready = all(check.status is CheckStatus.PASS for check in checks)
    return DoctorResult(ready=ready, checks=checks)
