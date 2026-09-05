"""Off-host, operator-only signing commands for ADR-037 Shape-A batches --
the generalized counterpart to `alias_description_signing.py`, driven by
`pfsense_mcp.tier1.shape_a_registry.SHAPE_A_REGISTRATIONS`'s finite
capability set instead of hardcoding one operation.

## What this module signs, and how

`sign_pending_confirmation()` consumes exactly one
`ShapeAPendingConfirmationRequest` (already integrity-verified before this
module ever sees its fields) and produces one signed `ConfirmationEvidence`,
using the existing, unmodified `confirmation_providers.signing_payload()`
canonicalization and `Ed25519ConfirmationVerifier` self-check -- byte-for-
byte the same cryptographic operation `alias_description_signing.
sign_pending_confirmation()` performs, generalized only in which artifact
type it reads `contract_id`/`operation_id`/digest fields from.

`sign_authorization_preview()` consumes exactly one
`ShapeAAuthorizationPreview` and produces one signed `PlanAuthorizationV2`.
`requested_plan_digest`/`requested_step_id` are never read from the preview
and trusted directly: this function independently regenerates the current
security-posture plan via the existing, unmodified
`security_plan.generate_security_posture_plan()` -- the SAME shared,
capability-agnostic function and the SAME shared
`MILESTONE_9_WRITE_TARGET_*`/`MILESTONE_9_WRITE_STEP_ID` constants
`alias_description_signing.py` itself uses (this security-posture gate is
not alias-specific -- it represents "is write_protected + hardware witness
currently active," a single environment-wide fact every capability that
requires it shares) -- computes its own digest via
`security_plan_digest.compute_plan_digest()`, and only then cross-checks
the result against the preview's own copy, refusing (fail-closed) if they
disagree. `execution_intent_digest` is the one field taken directly from
the preview, never recomputed (recomputing it would require live pfSense
access, which this module is forbidden from having) -- identical
discipline to the alias tool.

## Capability binding (new relative to the alias tool)

Every command takes a required `--capability SYMBOL` argument, checked
against `shape_a_registry.is_registered_capability()` before anything else
runs -- an unsupported/unregistered/misspelled symbol is refused
immediately, with no artifact read and no key loaded. The loaded preview's/
pending request's own `capability_symbol` field is then cross-checked
against the same `--capability` value a second time (defense in depth
against an operator pointing the tool at the wrong capability's staged
artifact directory) -- a mismatch refuses fail-closed, never signs "the one
that was actually found."

## Trust boundary (identical to `alias_description_signing.py`)

Never queries pfSense. Never imports `production_runtime.py`,
`write_batch1_production_runtime.py`, or any other execution-shaped Tier 1
module to obtain live state. Never decrypts `RecoveryContract` data. Never
accepts a caller-supplied replacement for any digest/binding field --
every one is read from the already-integrity-verified artifact or
independently derived from shared canonical functions. Never signs without
an explicit, interactive operator approval -- the literal string `yes`,
same as the alias tool; there is no `--yes`/`--force`/unattended flag
anywhere in this module, and none may be added (would remove the one
human-approval gate the whole ceremony depends on). Never overwrites an
existing signed output file. Private Ed25519 signing keys live only in
files the operator supplies, read once, used once, never logged, never
re-serialized.

`--directory` mode processes every capability subdirectory with a pending
artifact of the relevant kind under one artifact base directory in a single
process invocation -- so one signer sitting can approve a whole Batch-1 (or
future, larger) batch without re-invoking the CLI once per capability --
but EACH artifact still receives its own explicit, separate `yes` prompt;
there is no batch-approve-all path.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor
from pfsense_mcp.security_authorization import (
    PlanAuthorizationStepBinding,
    PlanAuthorizationV2,
    SecurityAuthorizationError,
    build_plan_authorization_v2_payload,
    sign_plan_authorization_v2,
)
from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.security_discovery import discover_capability_posture
from pfsense_mcp.security_discovery_export import discover_anchor_assurance_from_export
from pfsense_mcp.security_plan import (
    MILESTONE_9_WRITE_STEP_ID,
    MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE,
    MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE,
    generate_security_posture_plan,
    generate_security_posture_plan_from_discovery,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.security_posture_types import SecurityPostureDiscovery
from pfsense_mcp.tier1.anchor_evidence_export import anchor_evidence_export_from_bytes
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import ArtifactExchangeError, KeyMaterialError, Tier1Error
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, load_key_material
from pfsense_mcp.tier1.shape_a_acceptance_orchestration import artifact_paths_for
from pfsense_mcp.tier1.shape_a_artifact_exchange import (
    ShapeAAuthorizationPreview,
    ShapeAPendingConfirmationRequest,
    confirmation_evidence_to_bytes,
    load_shape_a_authorization_preview,
    load_shape_a_pending_confirmation_request,
    plan_authorization_v2_to_bytes,
    write_secure_new,
)
from pfsense_mcp.tier1.shape_a_registry import SHAPE_A_REGISTRATIONS, is_registered_capability

__all__ = [
    "SigningError",
    "main",
    "render_authorization_review",
    "render_confirmation_review",
    "sign_authorization_command",
    "sign_authorization_preview",
    "sign_confirmation_command",
    "sign_pending_confirmation",
]

_AUTHORITY_FILE_MAX_BYTES = 4096
_PRIVATE_KEY_FILE_MAX_BYTES = 32
_NONCE_BYTES = 16
_AUTHORIZATION_ID_BYTES = 16
_AUTHORIZATION_VALIDITY = timedelta(minutes=5)


class SigningError(RuntimeError):
    """This tool's own, narrow error class -- never raised by, and never
    caught from, any production module."""


def _read_secure(path: Path, *, max_bytes: int) -> bytes:
    descriptor = open_nofollow(path, on_error=SigningError)
    try:
        validate_descriptor(path, descriptor, max_bytes=max_bytes, on_error=SigningError)
        return os.read(descriptor, max_bytes + 1)
    finally:
        os.close(descriptor)


def _load_pinned_authority_file(path: Path) -> PinnedAuthority:
    raw = _read_secure(path, max_bytes=_AUTHORITY_FILE_MAX_BYTES)
    if len(raw) > _AUTHORITY_FILE_MAX_BYTES:
        raise SigningError(f"pinned authority file is too large: {path}")
    try:
        value = json.loads(raw.decode("utf-8").strip())
        if not isinstance(value, dict) or set(value) != {"authority_id", "public_key_hex"}:
            raise ValueError("unexpected shape")
        authority_id, public_key_hex = value["authority_id"], value["public_key_hex"]
        if not isinstance(authority_id, str) or not isinstance(public_key_hex, str):
            raise ValueError("unexpected field types")
        return PinnedAuthority(authority_id=authority_id, public_key=bytes.fromhex(public_key_hex))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, Tier1Error) as exc:
        raise SigningError(f"pinned authority file is malformed: {path}") from exc


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    raw = _read_secure(path, max_bytes=_PRIVATE_KEY_FILE_MAX_BYTES)
    if len(raw) != _PRIVATE_KEY_FILE_MAX_BYTES:
        raise SigningError(f"private key file is not exactly 32 bytes: {path}")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise SigningError(f"private key file does not contain a valid Ed25519 key: {path}") from exc


def _require_capability(capability_symbol: str) -> str:
    if not is_registered_capability(capability_symbol):
        raise SigningError(
            f"{capability_symbol!r} is not a registered Shape-A capability (known: {sorted(SHAPE_A_REGISTRATIONS)})."
        )
    return capability_symbol


def render_confirmation_review(pending: ShapeAPendingConfirmationRequest) -> str:
    lines = [
        "=" * 72,
        f"CONFIRMATION REVIEW -- {pending.capability_symbol}",
        "=" * 72,
        f"contract reference:      {pending.contract_id}",
        f"operation reference:     {pending.operation_id}",
        "-" * 72,
    ]
    for label, value in pending.semantic_fields:
        lines.append(f"{label:24s}  {value!r}")
    lines += [
        "-" * 72,
        f"target_identity_digest:  {pending.target_identity_digest}",
        f"target_fingerprint:      {pending.target_fingerprint}",
        f"intent_digest:           {pending.intent_digest}",
        f"expected_authority_id:   {pending.expected_authority_id}",
        f"expected_algorithm:      {pending.expected_algorithm}",
        f"expires_at (UTC):        {pending.expires_at.isoformat()}",
        "=" * 72,
        "Signing authorizes execution of EXACTLY the already-prepared contract",
        "described above. This action cannot be undone once the signed artifact",
        "is delivered to production.",
    ]
    return "\n".join(lines)


def sign_pending_confirmation(
    *,
    capability_symbol: str,
    pending: ShapeAPendingConfirmationRequest,
    private_key: Ed25519PrivateKey,
    authority: PinnedAuthority,
    now: datetime,
) -> ConfirmationEvidence:
    if pending.capability_symbol != capability_symbol:
        raise SigningError(
            f"pending confirmation request names capability {pending.capability_symbol!r}, "
            f"expected {capability_symbol!r} -- refusing to sign a mismatched artifact"
        )
    expected_algorithm = ACCEPTED_ALGORITHM
    if pending.expected_authority_id != authority.authority_id:
        raise SigningError("pending confirmation request does not name this signer's own pinned authority")
    if pending.expected_algorithm != expected_algorithm:
        raise SigningError("pending confirmation request names an unsupported algorithm")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise SigningError("signing time must be a timezone-aware UTC datetime")
    if not now < pending.expires_at:
        raise SigningError("pending confirmation request has expired")

    unsigned = ConfirmationEvidence(
        authority_id=authority.authority_id,
        algorithm=expected_algorithm,
        nonce=secrets.token_hex(_NONCE_BYTES),
        contract_id=pending.contract_id,
        operation_id=pending.operation_id,
        target_identity_digest=pending.target_identity_digest,
        target_fingerprint=pending.target_fingerprint,
        intent_digest=pending.intent_digest,
        expires_at=pending.expires_at,
        issued_at=now,
        proof=b"\x00" * 64,
    )
    proof = private_key.sign(signing_payload(unsigned))
    evidence = ConfirmationEvidence(
        authority_id=unsigned.authority_id,
        algorithm=unsigned.algorithm,
        nonce=unsigned.nonce,
        contract_id=unsigned.contract_id,
        operation_id=unsigned.operation_id,
        target_identity_digest=unsigned.target_identity_digest,
        target_fingerprint=unsigned.target_fingerprint,
        intent_digest=unsigned.intent_digest,
        expires_at=unsigned.expires_at,
        issued_at=unsigned.issued_at,
        proof=proof,
    )
    if not Ed25519ConfirmationVerifier((authority,)).verify(evidence):
        raise SigningError(
            "signed confirmation evidence failed self-verification against the pinned authority "
            "-- the supplied private key does not match the supplied public authority file"
        )
    return evidence


def render_authorization_review(preview: ShapeAAuthorizationPreview) -> str:
    lines = [
        "=" * 72,
        f"AUTHORIZATION REVIEW -- {preview.capability_symbol}",
        "=" * 72,
    ]
    for label, value in preview.semantic_fields:
        lines.append(f"{label:24s}  {value!r}")
    lines += [
        "-" * 72,
        f"target capability posture: {preview.target_capability_posture.value}",
        f"target anchor assurance:   {preview.target_anchor_assurance.value}",
        f"requested_step_id:         {preview.requested_step_id}",
        f"requested_plan_digest:     {preview.requested_plan_digest}",
        f"execution_intent_digest:   {preview.execution_intent_digest}",
        f"preview generated_at (UTC):{preview.generated_at.isoformat()}",
        "=" * 72,
        f"Signing authorizes exactly the {preview.capability_symbol} mutation described above,",
        "bound to the CURRENT, independently-verified security posture (this tool",
        "re-derives the plan digest itself -- it does not trust the preview's copy",
        "of it). This action cannot be undone once the signed artifact is delivered",
        "to production.",
    ]
    return "\n".join(lines)


def sign_authorization_preview(
    *,
    capability_symbol: str,
    preview: ShapeAAuthorizationPreview,
    private_key: Ed25519PrivateKey,
    authority: PinnedAuthority,
    authorization_id: str,
    issued_at: datetime,
    expires_at: datetime,
    env: dict[str, str] | None = None,
    discovery: SecurityPostureDiscovery | None = None,
) -> PlanAuthorizationV2:
    """`discovery`, when supplied (2026-09-05, ADR-021/022 amendment),
    is an already-independently-derived `SecurityPostureDiscovery` --
    e.g. from `_build_discovery_from_export()`, itself from a signed
    `AnchorEvidenceExport` -- used in place of a fresh store-backed
    `discover_security_posture()` read. This is the isolated signer's
    own path: it never holds a copy of the runtime `RecoveryContract`
    store, so it cannot call `generate_security_posture_plan()`
    (`env=None`/`env=os.environ` path) at all. `generate_security_
    posture_plan_from_discovery()` runs the exact same pure plan-
    construction body either way, so `compute_plan_digest()` is
    unaffected by which path supplied the evidence -- see
    `tests/test_security_plan_from_discovery.py`. `env` is ignored
    when `discovery` is supplied."""

    if preview.capability_symbol != capability_symbol:
        raise SigningError(
            f"authorization preview names capability {preview.capability_symbol!r}, "
            f"expected {capability_symbol!r} -- refusing to sign a mismatched artifact"
        )
    if preview.target_capability_posture is not MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE:
        raise SigningError("authorization preview targets an unsupported capability posture")
    if preview.target_anchor_assurance is not MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE:
        raise SigningError("authorization preview targets an unsupported anchor assurance")
    if preview.requested_step_id != MILESTONE_9_WRITE_STEP_ID:
        raise SigningError("authorization preview names an unsupported step_id")

    if discovery is not None:
        plan = generate_security_posture_plan_from_discovery(
            discovery, MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE
        )
    else:
        plan = generate_security_posture_plan(
            MILESTONE_9_WRITE_TARGET_CAPABILITY_POSTURE, MILESTONE_9_WRITE_TARGET_ANCHOR_ASSURANCE, env
        )
    if not plan.safe_to_proceed:
        raise SigningError(
            "independently-derived security posture is not currently safe to proceed -- "
            "refusing to sign against an invalid target or a detected security anomaly"
        )
    fresh_plan_digest = compute_plan_digest(plan)
    if fresh_plan_digest != preview.requested_plan_digest:
        raise SigningError(
            "authorization preview is stale -- the independently, freshly re-derived security-plan "
            "digest no longer matches the preview's own copy; live security posture has changed "
            "since the preview was generated"
        )

    binding = PlanAuthorizationStepBinding(
        step_id=MILESTONE_9_WRITE_STEP_ID, execution_intent_digest=preview.execution_intent_digest
    )
    try:
        payload = build_plan_authorization_v2_payload(
            plan,
            [binding],
            authorization_id=authorization_id,
            authority_id=authority.authority_id,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except SecurityAuthorizationError as exc:
        raise SigningError(f"could not build the PlanAuthorizationV2 payload: {exc}") from exc
    authz = sign_plan_authorization_v2(payload, private_key)
    if not verify_plan_authorization_v2_signature(authz, PinnedAuthoritySet((authority,))):
        raise SigningError(
            "signed PlanAuthorizationV2 failed self-verification against the pinned authority "
            "-- the supplied private key does not match the supplied public authority file"
        )
    return authz


def _required_env_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SigningError(f"required signing environment variable is missing: {name}")
    return Path(value)


def _prompt_operator_approval(review: str) -> bool:
    print(review)
    response = input("Sign this artifact? Type exactly 'yes' to proceed, anything else refuses: ")
    return response.strip() == "yes"


@dataclass(frozen=True)
class _AuthorizationSigningConfig:
    """Exactly the env vars `sign-authorization` needs. Deliberately
    holds no confirmation-side field: an operator running only
    `sign-authorization` (the ordinary case -- see this module's own
    docstring on `--directory`-style batch sittings) must never be
    required to also export `PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_*`
    just to satisfy an unrelated subcommand's config loader (2026-09-05
    fix; previously both subcommands shared one `_load_config()`
    requiring all 7 vars regardless of which command actually ran)."""

    artifact_base_directory: Path
    authorization_authority_file: Path
    authorization_private_key_file: Path
    preview_integrity_key_file: Path


@dataclass(frozen=True)
class _ConfirmationSigningConfig:
    """Exactly the env vars `sign-confirmation` needs -- the mirror of
    `_AuthorizationSigningConfig` above, holding no authorization-side
    field."""

    artifact_base_directory: Path
    confirmation_authority_file: Path
    confirmation_private_key_file: Path
    pending_integrity_key_file: Path


def _load_authorization_config() -> _AuthorizationSigningConfig:
    return _AuthorizationSigningConfig(
        artifact_base_directory=_required_env_path("PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"),
        authorization_authority_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_AUTHORITY_FILE"),
        authorization_private_key_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_AUTHORIZATION_PRIVATE_KEY_FILE"),
        preview_integrity_key_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_PREVIEW_INTEGRITY_KEY_FILE"),
    )


def _load_confirmation_config() -> _ConfirmationSigningConfig:
    return _ConfirmationSigningConfig(
        artifact_base_directory=_required_env_path("PFSENSE_SIGNING_SHAPE_A_ARTIFACT_BASE_DIRECTORY"),
        confirmation_authority_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_AUTHORITY_FILE"),
        confirmation_private_key_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_CONFIRMATION_PRIVATE_KEY_FILE"),
        pending_integrity_key_file=_required_env_path("PFSENSE_SIGNING_SHAPE_A_PENDING_INTEGRITY_KEY_FILE"),
    )


_ANCHOR_EVIDENCE_EXPORT_FILE_VAR = "PFSENSE_SIGNING_ANCHOR_EVIDENCE_EXPORT_FILE"
_POSTURE_EVIDENCE_AUTHORITY_FILE_VAR = "PFSENSE_SIGNING_POSTURE_EVIDENCE_AUTHORITY_FILE"
_EXPECTED_STORE_ID_VAR = "PFSENSE_SIGNING_EXPECTED_STORE_ID"
_ANCHOR_EVIDENCE_EXPORT_MAX_BYTES = 8192


def _build_discovery_from_export(env: dict[str, str]) -> SecurityPostureDiscovery | None:
    """Opt-in, env-var-gated: builds a `SecurityPostureDiscovery` from a
    signed `AnchorEvidenceExport` instead of the runtime store, for the
    isolated signer (2026-09-05, ADR-021/022 amendment). Returns `None`
    (meaning: use the ordinary store-backed path) when none of the
    three vars are set -- existing alias-signer behavior is completely
    unaffected. Fails closed (raises `SigningError`) on a partial
    configuration -- never silently falls back to the store path when
    the operator's intent was clearly the export path."""

    export_file = env.get(_ANCHOR_EVIDENCE_EXPORT_FILE_VAR)
    authority_file = env.get(_POSTURE_EVIDENCE_AUTHORITY_FILE_VAR)
    expected_store_id = env.get(_EXPECTED_STORE_ID_VAR)
    if not export_file and not authority_file and not expected_store_id:
        return None
    if not export_file or not authority_file or not expected_store_id:
        raise SigningError(
            f"AnchorEvidenceExport signing configuration is partial -- {_ANCHOR_EVIDENCE_EXPORT_FILE_VAR}, "
            f"{_POSTURE_EVIDENCE_AUTHORITY_FILE_VAR}, and {_EXPECTED_STORE_ID_VAR} are required together."
        )

    raw_export = _read_secure(Path(export_file), max_bytes=_ANCHOR_EVIDENCE_EXPORT_MAX_BYTES)
    export = anchor_evidence_export_from_bytes(raw_export)
    posture_evidence_authority = _load_pinned_authority_file(Path(authority_file))
    authorities = PinnedAuthoritySet((posture_evidence_authority,))

    anchor_assurance = discover_anchor_assurance_from_export(
        export, authorities=authorities, expected_store_id=expected_store_id, now=datetime.now(timezone.utc), env=env
    )
    capability_posture = discover_capability_posture(env)
    return SecurityPostureDiscovery(capability_posture=capability_posture, anchor_assurance=anchor_assurance)


def _one_authorization(config: _AuthorizationSigningConfig, capability_symbol: str) -> int:
    paths = artifact_paths_for(config.artifact_base_directory, capability_symbol)
    if not paths.authorization_preview_file.exists():
        print(f"[{capability_symbol}] no authorization preview present -- skipping.")
        return 0
    if paths.authorization_inbox_file.exists():
        print(f"[{capability_symbol}] a signed authorization already exists -- skipping.")
        return 0

    integrity_key = load_key_material(config.preview_integrity_key_file, purpose=KeyPurpose.INTEGRITY).material
    preview = load_shape_a_authorization_preview(paths.authorization_preview_file, integrity_key=integrity_key)
    authority = _load_pinned_authority_file(config.authorization_authority_file)
    private_key = _load_private_key(config.authorization_private_key_file)
    discovery = _build_discovery_from_export(dict(os.environ))

    if not _prompt_operator_approval(render_authorization_review(preview)):
        print(f"[{capability_symbol}] refused -- no signature produced.")
        return 1

    now = datetime.now(timezone.utc)
    authz = sign_authorization_preview(
        capability_symbol=capability_symbol,
        preview=preview,
        private_key=private_key,
        authority=authority,
        authorization_id=f"authz-{secrets.token_hex(_AUTHORIZATION_ID_BYTES)}",
        issued_at=now,
        expires_at=now + _AUTHORIZATION_VALIDITY,
        discovery=discovery,
    )
    write_secure_new(paths.authorization_inbox_file, plan_authorization_v2_to_bytes(authz))
    print(f"[{capability_symbol}] signed PlanAuthorizationV2 written to {paths.authorization_inbox_file}")
    return 0


def _one_confirmation(config: _ConfirmationSigningConfig, capability_symbol: str) -> int:
    paths = artifact_paths_for(config.artifact_base_directory, capability_symbol)
    if not paths.confirmation_pending_file.exists():
        print(f"[{capability_symbol}] no pending confirmation present -- skipping.")
        return 0
    if paths.confirmation_signed_file.exists():
        print(f"[{capability_symbol}] a signed confirmation already exists -- skipping.")
        return 0

    integrity_key = load_key_material(config.pending_integrity_key_file, purpose=KeyPurpose.INTEGRITY).material
    pending = load_shape_a_pending_confirmation_request(paths.confirmation_pending_file, integrity_key=integrity_key)
    authority = _load_pinned_authority_file(config.confirmation_authority_file)
    private_key = _load_private_key(config.confirmation_private_key_file)

    if not _prompt_operator_approval(render_confirmation_review(pending)):
        print(f"[{capability_symbol}] refused -- no signature produced.")
        return 1

    evidence = sign_pending_confirmation(
        capability_symbol=capability_symbol,
        pending=pending,
        private_key=private_key,
        authority=authority,
        now=datetime.now(timezone.utc),
    )
    write_secure_new(paths.confirmation_signed_file, confirmation_evidence_to_bytes(evidence))
    print(f"[{capability_symbol}] signed confirmation evidence written to {paths.confirmation_signed_file}")
    return 0


def sign_authorization_command(capabilities: list[str]) -> int:
    config = _load_authorization_config()
    worst = 0
    for capability_symbol in capabilities:
        _require_capability(capability_symbol)
        worst = max(worst, _one_authorization(config, capability_symbol))
    return worst


def sign_confirmation_command(capabilities: list[str]) -> int:
    config = _load_confirmation_config()
    worst = 0
    for capability_symbol in capabilities:
        _require_capability(capability_symbol)
        worst = max(worst, _one_confirmation(config, capability_symbol))
    return worst


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="write-batch1-signing",
        description="Off-host, operator-only signing tool for ADR-037 Shape-A capability batches.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name, help_text in (
        ("sign-authorization", "Review and sign one or more AuthorizationPreviews."),
        ("sign-confirmation", "Review and sign one or more PendingConfirmationRequests."),
    ):
        sub = subparsers.add_parser(name, help=help_text)
        group = sub.add_mutually_exclusive_group(required=True)
        group.add_argument("--capability", action="append", help="A registered Shape-A capability symbol. May repeat.")
        group.add_argument(
            "--all-registered",
            action="store_true",
            help="Process every registered Shape-A capability (each still requires its own 'yes').",
        )
    args = parser.parse_args(argv)

    capabilities = sorted(SHAPE_A_REGISTRATIONS) if args.all_registered else list(args.capability or [])

    try:
        for capability_symbol in capabilities:
            _require_capability(capability_symbol)
        if args.command == "sign-authorization":
            return sign_authorization_command(capabilities)
        if args.command == "sign-confirmation":
            return sign_confirmation_command(capabilities)
        raise SigningError(f"unsupported command: {args.command}")  # unreachable -- argparse enforces choices
    except (SigningError, ArtifactExchangeError, KeyMaterialError, SecurityAuthorizationError, Tier1Error) as exc:
        print(f"Refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
