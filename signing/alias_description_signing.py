"""Off-host, operator-only signing command for the confirmation half of
the ADR-028 first-WRITE product surface (`set_firewall_alias_description_v1`).

W3 Slice 5 status: this module implements `sign-confirmation` only.
`sign-authorization` (consuming a production-generated
`AuthorizationPreview` to produce a signed `PlanAuthorizationV2`) is
deliberately NOT implemented -- see this package's own `__init__.py`
and the Slice 5 handoff report for the exact, reproducible reason
(`security_plan.py`'s capability-posture step generation drops the
`capability_posture.milestone_9_activation` step from the plan the
moment `PFSENSE_PROFILE=write_protected` is active in the SAME process
-- exactly the environment the signer would need to reproduce to match
what production's own freshness check independently recomputes,
making a correct signer for that step structurally impossible today).
Building it anyway would require either weakening the anti-tautology
property (trusting a caller-supplied plan_digest/step_id instead of an
independently reproduced plan) or a change to `security_plan.py` itself
-- both outside this narrow signing-tool authorization, so this module
does not attempt it.

## What this module signs, and how

`sign_pending_confirmation()` consumes exactly one `PendingConfirmationRequest`
(schema v2, `pfsense_mcp.tier1.artifact_exchange`) -- integrity-verified
before this module ever sees its fields (`load_pending_confirmation_request()`
already refuses a malformed, wrong-schema, or MAC-tampered artifact,
reused unchanged) -- and produces one signed `ConfirmationEvidence`
using the existing, unmodified `confirmation_providers.signing_payload()`
canonicalization and `Ed25519ConfirmationVerifier` self-check. This
module contains no cryptography, no canonicalization, and no signature-
verification logic of its own: `sign_existing_pending()`
(`lab/reconciliation_owner.py`, the accepted LAB precedent) established
the exact "load pending -> sign the canonical payload -> self-verify
against the pinned public key before writing" shape this function
mirrors.

## Trust boundary

- Never queries pfSense, never imports `WriteApiClient`/`PfSenseClient`/
  any pfSense-reaching transport (`tests/test_signing_tool_isolation.py`
  proves this by direct AST inspection).
- Never decrypts `RecoveryContract` data and never accesses production
  store internals -- the only inputs are the two files an operator is
  handed (the pending-confirmation artifact and its integrity key),
  both already reduced to plaintext-safe, non-authorizing review content
  by `production_runtime.py`/`artifact_exchange.py`.
- Never accepts a caller-supplied replacement for `contract_id`,
  `operation_id`, or any digest field -- every one of those is read
  directly from the already-integrity-verified `PendingConfirmationRequest`,
  never from a CLI argument, environment variable value chosen per-run,
  or operator free-text entry (`sign_pending_confirmation()`'s own
  signature has no such parameter).
- Never signs without an explicit, interactive operator approval --
  `main()`'s only path to `sign_pending_confirmation()` is through
  `_prompt_operator_approval()` returning `True` from a real `input()`
  call; there is no `--yes`/`--force` flag anywhere in this module.
- Never overwrites an existing signed-confirmation output file --
  reuses `artifact_exchange.write_secure_new()`'s exclusive-creation-only
  discipline unchanged.
- The private Ed25519 signing key lives only in a file the operator
  supplies via `PFSENSE_SIGNING_CONFIRMATION_PRIVATE_KEY_FILE`, read once,
  used once, never logged, never serialized, never written anywhere by
  this module. Production never imports this module and never has
  access to that file.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor
from pfsense_mcp.tier1.alias_description import SEMANTIC_UNIT
from pfsense_mcp.tier1.artifact_exchange import (
    PendingConfirmationRequest,
    confirmation_evidence_to_bytes,
    load_pending_confirmation_request,
    write_secure_new,
)
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, Ed25519ConfirmationVerifier, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority
from pfsense_mcp.tier1.errors import ArtifactExchangeError, KeyMaterialError, Tier1Error
from pfsense_mcp.tier1.key_lifecycle import KeyPurpose, load_key_material

__all__ = [
    "SigningError",
    "render_confirmation_review",
    "sign_confirmation_command",
    "sign_pending_confirmation",
]

_AUTHORITY_FILE_MAX_BYTES = 4096
_PRIVATE_KEY_FILE_MAX_BYTES = 32
_NONCE_BYTES = 16


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
        "sign-confirmation",
        help="Review and sign a PendingConfirmationRequest (schema v2), producing signed ConfirmationEvidence.",
    )
    args = parser.parse_args(argv)

    try:
        if args.command == "sign-confirmation":
            return sign_confirmation_command()
        raise SigningError(f"unsupported command: {args.command}")  # unreachable -- argparse enforces choices
    except (SigningError, ArtifactExchangeError, KeyMaterialError, Tier1Error) as exc:
        print(f"Refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
