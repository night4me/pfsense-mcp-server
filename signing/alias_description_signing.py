"""Off-host, operator-only signing commands for the ADR-028 first-WRITE
product surface (`set_firewall_alias_description_v1`): `sign-confirmation`
and `sign-authorization`.

W3 Slice 5 shipped `sign-confirmation` only; `sign-authorization` was
deliberately not built because `security_plan.py`'s capability-posture
step generation dropped the `capability_posture.milestone_9_activation`
step from the plan the moment `PFSENSE_PROFILE=write_protected` was
active in the SAME process -- exactly the environment a signer would
need to reproduce to match what production's own freshness check
independently recomputes. W3 Slice 5B fixed that defect in
`security_plan.py` (see that module's `_milestone_9_activation_step()`
docstring for the full correction) and this module now implements
`sign-authorization` against the corrected, shared planning logic.

## What this module signs, and how

`sign_pending_confirmation()` consumes exactly one `PendingConfirmationRequest`
(schema v2, `pfsense_mcp.tier1.artifact_exchange`) -- integrity-verified
before this module ever sees its fields (`load_pending_confirmation_request()`
already refuses a malformed, wrong-schema, or MAC-tampered artifact,
reused unchanged) -- and produces one signed `ConfirmationEvidence`
using the existing, unmodified `confirmation_providers.signing_payload()`
canonicalization and `Ed25519ConfirmationVerifier` self-check.

`sign_authorization_preview()` consumes exactly one `AuthorizationPreview`
(`pfsense_mcp.tier1.artifact_exchange`) -- also integrity-verified before
this module ever sees its fields -- and produces one signed
`PlanAuthorizationV2`. `requested_plan_digest`/`requested_step_id` are
**never read from the preview and trusted directly**: this function
independently regenerates the current security-posture plan via the
existing, unmodified `security_plan.generate_security_posture_plan()`
(the same shared, canonical function `tier1_write_bridge.py` itself
calls in production, using the same shared
`security_plan.ALIAS_DESCRIPTION_WRITE_*` constants), computes its own
digest via `security_plan_digest.compute_plan_digest()`, and only then
cross-checks the result against the preview's own copy -- refusing
(fail-closed) if they disagree, exactly the ADR-024 anti-tautology
property this module must never weaken. `execution_intent_digest` is the
one field taken directly from the preview, never recomputed (recomputing
it would require live pfSense access, which this module is forbidden
from having).

Neither signing function contains any cryptography, canonicalization, or
signature-verification logic of its own: `sign_existing_pending()`
(`lab/reconciliation_owner.py`, the accepted LAB precedent) established
the exact "load pending -> sign the canonical payload -> self-verify
against the pinned public key before writing" shape both mirror.

## Trust boundary

- Never queries pfSense, never imports `WriteApiClient`/`PfSenseClient`/
  any pfSense-reaching transport (`tests/test_signing_tool_isolation.py`
  proves this by direct AST inspection).
- Never imports `production_runtime.py` or any other execution-shaped
  Tier 1 module to obtain live state -- `sign_authorization_preview()`
  derives the current security posture exclusively through the same
  public, shared `security_plan.generate_security_posture_plan()`
  function production itself calls, never through a second,
  independently-implemented path.
- Never decrypts `RecoveryContract` data and never accesses production
  store internals -- the only inputs are the files an operator is
  handed (the pending-confirmation/authorization-preview artifacts and
  their integrity key), both already reduced to plaintext-safe,
  non-authorizing review content by `production_runtime.py`/
  `artifact_exchange.py`.
- Never accepts a caller-supplied replacement for `contract_id`,
  `operation_id`, `plan_digest`, `step_id`, `execution_intent_digest`,
  `authority_id`, or any other digest/binding field -- every one of
  those is read directly from the already-integrity-verified artifact
  or independently derived from the shared canonical functions, never
  from a CLI argument, environment variable value chosen per-run, or
  operator free-text entry (`sign_pending_confirmation()`/
  `sign_authorization_preview()`'s own signatures have no such
  parameter).
- Never signs without an explicit, interactive operator approval --
  `main()`'s only path to either signing function is through
  `_prompt_operator_approval()` returning `True` from a real `input()`
  call; there is no `--yes`/`--force`/unattended flag anywhere in this
  module.
- Never overwrites an existing signed output file -- reuses
  `artifact_exchange.write_secure_new()`'s exclusive-creation-only
  discipline unchanged.
- Private Ed25519 signing keys live only in files the operator supplies
  (`PFSENSE_SIGNING_CONFIRMATION_PRIVATE_KEY_FILE`/
  `PFSENSE_SIGNING_AUTHORIZATION_PRIVATE_KEY_FILE`), read once, used
  once, never logged, never serialized, never written anywhere by this
  module. Production never imports this module and never has access to
  either file.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
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
from pfsense_mcp.security_plan import (
    ALIAS_DESCRIPTION_WRITE_STEP_ID,
    ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE,
    ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE,
    generate_security_posture_plan,
)
from pfsense_mcp.security_plan_digest import compute_plan_digest
from pfsense_mcp.tier1.alias_description import SEMANTIC_UNIT
from pfsense_mcp.tier1.artifact_exchange import (
    AuthorizationPreview,
    PendingConfirmationRequest,
    confirmation_evidence_to_bytes,
    load_authorization_preview,
    load_pending_confirmation_request,
    plan_authorization_v2_to_bytes,
    write_secure_new,
)
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import ArtifactExchangeError, KeyMaterialError, Tier1Error
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, load_key_material

__all__ = [
    "SigningError",
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

#: Fixed, non-operator-configurable validity window for a signed
#: PlanAuthorizationV2 -- matches `AliasDescriptionExecutionCoreV1`'s own
#: default `contract_validity`. Deliberately not a CLI flag or
#: environment variable: an unnecessary tunable this operation does not
#: need (mirrors the "do not add arbitrary parameters merely for
#: flexibility" instruction this tool was built under).
_AUTHORIZATION_VALIDITY = timedelta(minutes=5)


class SigningError(RuntimeError):
    """This tool's own, narrow error class. Never raised by, and never
    caught from, any production module -- production code paths remain
    entirely unaware this package exists."""


def _read_secure(path: Path, *, max_bytes: int) -> bytes:
    descriptor = open_nofollow(path, on_error=SigningError)
    try:
        validate_descriptor(path, descriptor, max_bytes=max_bytes, on_error=SigningError)
        return os.read(descriptor, max_bytes + 1)
    finally:
        os.close(descriptor)


def _load_pinned_authority_file(path: Path) -> PinnedAuthority:
    """Loads exactly one Ed25519 *public* key -- never a private one.

    Deliberately mirrors `production_runtime.py`'s own private
    `_load_pinned_authority()` file shape exactly
    (`{"authority_id": "...", "public_key_hex": "<64 lowercase hex>"}`),
    so the identical file a deployment provisions for production can be
    handed to the operator unmodified and used on both sides. Not
    imported from `production_runtime.py` (that function is private,
    and this package must never import anything from `src/pfsense_mcp.
    tier1.production_runtime` -- an execution-shaped module, not a
    shared owner). All domain validation (authority-id shape, exact
    32-byte key length) is delegated to `PinnedAuthority.__post_init__`,
    the existing, single owner of that validation -- never
    re-implemented here."""

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
    """Loads exactly one raw 32-byte Ed25519 private key -- the same
    convention `lab/reconciliation_owner.py`'s own accepted precedent
    uses (`Ed25519PrivateKey.from_private_bytes()` over a
    `secure_file.open_nofollow()`-validated read), not a second key
    format invented for this module. Never logged, never re-serialized,
    never written anywhere by this function."""

    raw = _read_secure(path, max_bytes=_PRIVATE_KEY_FILE_MAX_BYTES)
    if len(raw) != _PRIVATE_KEY_FILE_MAX_BYTES:
        raise SigningError(f"private key file is not exactly 32 bytes: {path}")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise SigningError(f"private key file does not contain a valid Ed25519 key: {path}") from exc


def render_confirmation_review(pending: PendingConfirmationRequest) -> str:
    """The required G5 human-readable review, shown to the operator
    before any signature is produced. Every field here comes directly
    from the already-integrity-verified `pending` object -- nothing is
    fabricated, inferred, or fetched from anywhere else. Digests are
    shown for audit correspondence only, never as a substitute for the
    semantic fields above them."""

    lines = [
        "=" * 72,
        "CONFIRMATION REVIEW -- set_firewall_alias_description_v1",
        "=" * 72,
        f"operation:               {pending.operation}",
        f"contract reference:      {pending.contract_id}",
        f"operation reference:     {pending.operation_id}",
        f"alias name:              {pending.alias_name}",
        f"previous description:    {pending.previous_description!r}",
        f"requested description:   {pending.requested_description!r}",
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
    pending: PendingConfirmationRequest,
    private_key: Ed25519PrivateKey,
    authority: PinnedAuthority,
    now: datetime,
) -> ConfirmationEvidence:
    """The sole confirmation-signing operation. The caller must have
    already obtained explicit operator approval -- this function
    performs no interaction of its own and is never invoked
    automatically anywhere in this module.

    Every security-critical value comes from `pending` (already
    integrity-verified by `load_pending_confirmation_request()` before
    this function is ever called) or from fixed, non-operator-controlled
    inputs (`authority`, `now`) -- `contract_id`/`operation_id`/every
    digest field is read directly from `pending`, never accepted as a
    separate parameter a caller could substitute."""

    if pending.operation != SEMANTIC_UNIT:
        raise SigningError("pending confirmation request operation is not the accepted first-WRITE operation")
    if pending.expected_authority_id != authority.authority_id:
        raise SigningError("pending confirmation request does not name this signer's own pinned authority")
    if pending.expected_algorithm != ACCEPTED_ALGORITHM:
        raise SigningError("pending confirmation request names an unsupported algorithm")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() != timezone.utc.utcoffset(now):
        raise SigningError("signing time must be a timezone-aware UTC datetime")
    if not now < pending.expires_at:
        raise SigningError("pending confirmation request has expired")

    unsigned = ConfirmationEvidence(
        authority_id=authority.authority_id,
        algorithm=ACCEPTED_ALGORITHM,
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


def render_authorization_review(preview: AuthorizationPreview) -> str:
    """The required G5 human-readable review, shown to the operator
    before any signature is produced. Every field here comes directly
    from the already-integrity-verified `preview` object -- nothing is
    fabricated, inferred, or fetched from anywhere else. Digests are
    shown for audit correspondence only, never as a substitute for the
    semantic fields above them."""

    lines = [
        "=" * 72,
        "AUTHORIZATION REVIEW -- set_firewall_alias_description_v1",
        "=" * 72,
        f"operation:                 {preview.operation}",
        f"alias name:                {preview.alias_name}",
        f"previous description:      {preview.previous_description!r}",
        f"requested description:     {preview.requested_description!r}",
        "-" * 72,
        f"target capability posture: {preview.target_capability_posture.value}",
        f"target anchor assurance:   {preview.target_anchor_assurance.value}",
        f"requested_step_id:         {preview.requested_step_id}",
        f"requested_plan_digest:     {preview.requested_plan_digest}",
        f"execution_intent_digest:   {preview.execution_intent_digest}",
        f"preview generated_at (UTC):{preview.generated_at.isoformat()}",
        "=" * 72,
        "Signing authorizes exactly the alias-description mutation described above,",
        "bound to the CURRENT, independently-verified security posture (this tool",
        "re-derives the plan digest itself -- it does not trust the preview's copy",
        "of it). This action cannot be undone once the signed artifact is delivered",
        "to production.",
    ]
    return "\n".join(lines)


def sign_authorization_preview(
    *,
    preview: AuthorizationPreview,
    private_key: Ed25519PrivateKey,
    authority: PinnedAuthority,
    authorization_id: str,
    issued_at: datetime,
    expires_at: datetime,
    env: dict[str, str] | None = None,
) -> PlanAuthorizationV2:
    """The sole authorization-signing operation. The caller must have
    already obtained explicit operator approval -- this function
    performs no interaction of its own and is never invoked
    automatically anywhere in this module.

    `plan_digest`/`step_id` are never accepted as parameters and never
    trusted from `preview` directly: this function always independently
    regenerates the current security-posture plan via the existing,
    unmodified `generate_security_posture_plan()` (called with the same
    shared `ALIAS_DESCRIPTION_WRITE_TARGET_*` constants production
    itself uses) and computes its own digest via the existing,
    unmodified `compute_plan_digest()` -- preserving ADR-024's
    anti-tautology property exactly. `preview.requested_plan_digest` is
    consulted only as a staleness cross-check (refusing, fail-closed, if
    it no longer matches what is independently, freshly derived) --
    never as the value that is actually signed. `execution_intent_digest`
    is the one field taken directly from `preview` -- never recomputed,
    since recomputing it would require live pfSense access this module
    is forbidden from having."""

    if preview.operation != SEMANTIC_UNIT:
        raise SigningError("authorization preview operation is not the accepted first-WRITE operation")
    if preview.target_capability_posture is not ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE:
        raise SigningError("authorization preview targets an unsupported capability posture")
    if preview.target_anchor_assurance is not ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE:
        raise SigningError("authorization preview targets an unsupported anchor assurance")
    if preview.requested_step_id != ALIAS_DESCRIPTION_WRITE_STEP_ID:
        raise SigningError("authorization preview names an unsupported step_id")

    plan = generate_security_posture_plan(
        ALIAS_DESCRIPTION_WRITE_TARGET_CAPABILITY_POSTURE, ALIAS_DESCRIPTION_WRITE_TARGET_ANCHOR_ASSURANCE, env
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
        step_id=ALIAS_DESCRIPTION_WRITE_STEP_ID, execution_intent_digest=preview.execution_intent_digest
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
    response = input("Sign this confirmation? Type exactly 'yes' to proceed, anything else refuses: ")
    return response.strip() == "yes"


def sign_confirmation_command() -> int:
    """The full `sign-confirmation` workflow: load, integrity-verify,
    render the G5 review, require explicit approval, sign, write.
    Returns `0` on a signed artifact written, `1` on operator refusal.
    Raises `SigningError`/`pfsense_mcp.tier1.errors.ArtifactExchangeError`/
    `pfsense_mcp.tier1.key_lifecycle.KeyMaterialError` for any fail-closed
    condition -- `main()` catches and reports these cleanly."""

    pending_file = _required_env_path("PFSENSE_SIGNING_CONFIRMATION_PENDING_FILE")
    integrity_key_file = _required_env_path("PFSENSE_SIGNING_CONFIRMATION_PENDING_INTEGRITY_KEY_FILE")
    authority_file = _required_env_path("PFSENSE_SIGNING_CONFIRMATION_AUTHORITY_FILE")
    private_key_file = _required_env_path("PFSENSE_SIGNING_CONFIRMATION_PRIVATE_KEY_FILE")
    output_file = _required_env_path("PFSENSE_SIGNING_CONFIRMATION_OUTPUT_FILE")

    integrity_key = load_key_material(integrity_key_file, purpose=KeyPurpose.INTEGRITY).material
    pending = load_pending_confirmation_request(pending_file, integrity_key=integrity_key)
    authority = _load_pinned_authority_file(authority_file)
    private_key = _load_private_key(private_key_file)

    if not _prompt_operator_approval(render_confirmation_review(pending)):
        print("Refused -- no signature produced.")
        return 1

    evidence = sign_pending_confirmation(
        pending=pending, private_key=private_key, authority=authority, now=datetime.now(timezone.utc)
    )
    write_secure_new(output_file, confirmation_evidence_to_bytes(evidence))
    print(f"Signed confirmation evidence written to {output_file}")
    return 0


def sign_authorization_command() -> int:
    """The full `sign-authorization` workflow: load, integrity-verify,
    render the G5 review, require explicit approval, independently
    re-derive the security-plan digest, sign, write. Returns `0` on a
    signed artifact written, `1` on operator refusal. Raises
    `SigningError`/`pfsense_mcp.tier1.errors.ArtifactExchangeError`/
    `pfsense_mcp.tier1.key_lifecycle.KeyMaterialError` for any fail-closed
    condition -- `main()` catches and reports these cleanly."""

    preview_file = _required_env_path("PFSENSE_SIGNING_AUTHORIZATION_PREVIEW_FILE")
    integrity_key_file = _required_env_path("PFSENSE_SIGNING_AUTHORIZATION_PREVIEW_INTEGRITY_KEY_FILE")
    authority_file = _required_env_path("PFSENSE_SIGNING_AUTHORIZATION_AUTHORITY_FILE")
    private_key_file = _required_env_path("PFSENSE_SIGNING_AUTHORIZATION_PRIVATE_KEY_FILE")
    output_file = _required_env_path("PFSENSE_SIGNING_AUTHORIZATION_OUTPUT_FILE")

    integrity_key = load_key_material(integrity_key_file, purpose=KeyPurpose.INTEGRITY).material
    preview = load_authorization_preview(preview_file, integrity_key=integrity_key)
    authority = _load_pinned_authority_file(authority_file)
    private_key = _load_private_key(private_key_file)

    if not _prompt_operator_approval(render_authorization_review(preview)):
        print("Refused -- no signature produced.")
        return 1

    now = datetime.now(timezone.utc)
    authz = sign_authorization_preview(
        preview=preview,
        private_key=private_key,
        authority=authority,
        authorization_id=f"authz-{secrets.token_hex(_AUTHORIZATION_ID_BYTES)}",
        issued_at=now,
        expires_at=now + _AUTHORIZATION_VALIDITY,
    )
    write_secure_new(output_file, plan_authorization_v2_to_bytes(authz))
    print(f"Signed PlanAuthorizationV2 written to {output_file}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="alias-description-signing",
        description=(
            "Off-host, operator-only signing tool for the ADR-028 first-WRITE "
            "product surface (set_firewall_alias_description_v1)."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "sign-authorization",
        help="Review and sign an AuthorizationPreview, producing a signed PlanAuthorizationV2.",
    )
    subparsers.add_parser(
        "sign-confirmation",
        help="Review and sign a PendingConfirmationRequest (schema v2), producing signed ConfirmationEvidence.",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "sign-authorization":
            return sign_authorization_command()
        if args.command == "sign-confirmation":
            return sign_confirmation_command()
        raise SigningError(f"unsupported command: {args.command}")  # unreachable -- argparse enforces choices
    except (SigningError, ArtifactExchangeError, KeyMaterialError, SecurityAuthorizationError, Tier1Error) as exc:
        print(f"Refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
