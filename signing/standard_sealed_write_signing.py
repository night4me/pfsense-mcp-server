"""Local, on-host, operator-only signing command for producing a
`SealedWriteApproval` (`pfsense_mcp.tier1.sealed_write_approval`) -- the
single owner-approval artifact that replaces the full off-host
authorization+confirmation ceremony for `STANDARD_SEALED_WRITE`
capabilities (2026-09-06 owner-authorized two-tier WRITE security
model, Phase 1).

## What this module does, and does not, do

`sign_standard_sealed_write_approval()` is the sole signing operation:
it accepts the exact fields the mutation runtime rendered into an
unsigned approval request (`contract_id`, `state_version`,
`security_class`, `execution_intent_digest`, `target_identity_digest`)
plus a validity window, as explicit, caller-supplied values -- this
module never reads a `RecoveryContract` store, never contacts pfSense,
and never derives these values itself. It only ever signs
`STANDARD_SEALED_WRITE` (never `HIGH_ASSURANCE_TIER1`) -- a request
naming any other class is refused, fail-closed, before any signing is
attempted.

Every signed field is built via `build_sealed_write_approval_payload()`,
signed via `sign_sealed_write_approval()`, and self-verified via
`verify_sealed_write_approval_signature()` -- all three unmodified,
existing primitives from `pfsense_mcp.tier1.sealed_write_approval`.
This module contains no cryptography, canonicalization, or signature-
verification logic of its own, mirroring
`anchor_evidence_export_signing.py`'s own established discipline
exactly.

## Authority

This module signs for exactly one authority:
`STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID`
(`"standard-sealed-write-approval-authority-v1"`). The pinned public-key
file supplied via `PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE`
must name exactly this authority_id -- a file naming any other
authority is refused, fail-closed, before any signing is attempted.
This is a single-authority tool, not a generic "sign for any authority"
utility, and this authority is a **dedicated** Ed25519 keypair, distinct
from every HIGH_ASSURANCE authority (authorization, confirmation,
posture-evidence, reconciliation) and from every store's own HMAC
integrity key.

## Trust boundary -- what makes this a real owner-approval boundary

Per the accepted architecture, a STANDARD approval is only meaningful
if the mutation runtime cannot forge it on its own:

- **Separate local identity, not a runtime-reachable API.** This module
  is designed to run under a local OS identity distinct from the
  mutation runtime's own process identity, with the private key file
  readable only by that separate identity (owner-provisioned in a
  later, separate, explicitly-gated phase -- **not this one**; this
  phase authorizes implementation and testing only, never real
  identity/key provisioning). There is no function anywhere in this
  module, or in `pfsense_mcp.tier1.sealed_write_approval`, that accepts
  a payload and returns a signature without the explicit interactive
  approval step below -- no unconditional "sign this for me" call the
  runtime could invoke even if it somehow reached this process.
- **Never signs without an explicit, interactive operator approval** --
  `main()`'s only path to `sign_standard_sealed_write_approval()` is
  through `_prompt_operator_approval()` returning `True` from a real
  `input()` call; there is no `--yes`/`--force`/unattended flag
  anywhere in this module.
- Never queries pfSense, never imports `WriteApiClient`/`PfSenseClient`/
  any pfSense-reaching transport, never imports `production_runtime.py`,
  `write_batch1_production_runtime.py`, `executor.py`, or any other
  execution-shaped Tier 1 module
  (`signing/tests/test_signing_transport_isolation.py` proves this by
  direct import-graph inspection, extended to cover this module).
- Never contacts a TPM witness of any kind -- a STANDARD approval
  carries no witness/anchor evidence by design (see
  `write_security_class.StandardSealedExecutionPolicy`).
- Never accepts a caller-supplied replacement for `authority_id` --
  always read directly from the pinned authority file, never a CLI
  argument.
- Never overwrites an existing output file -- reuses
  `artifact_exchange.write_secure_new()`'s exclusive-creation-only
  discipline unchanged.
- The private Ed25519 signing key lives only in a file the operator
  supplies (`PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE`),
  read once via the same `secure_file.open_nofollow()`/
  `validate_descriptor()` discipline every other signing module in this
  package already uses (refuses symlinks, refuses non-owner-only
  permissions), used once, never logged, never re-serialized, never
  written anywhere by this module, never returned from any function
  this module exposes. Production (`src/pfsense_mcp`,
  `pfsense-mcp-server`) never imports this module and never has access
  to this file.

**Threat model (stated explicitly):** compromise of the mutation
runtime alone must not permit forging an approval -- the runtime never
holds this authority's private key, and no synchronous API exists for
it to request an unconditional signature. Full privileged compromise of
the physical host (root, or this separate signer identity's own
credentials) is explicitly outside this tier's protection.
HIGH_ASSURANCE_TIER1 retains its stronger property: its authorities are
never resident on this host at all.
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.secure_file import open_nofollow, validate_descriptor
from pfsense_mcp.tier1.artifact_exchange import write_secure_new
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthority, PinnedAuthoritySet
from pfsense_mcp.tier1.errors import ArtifactExchangeError, Tier1Error
from pfsense_mcp.tier1.sealed_write_approval import (
    STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID,
    SealedWriteApproval,
    SealedWriteApprovalError,
    build_sealed_write_approval_payload,
    sealed_write_approval_from_bytes,
    sealed_write_approval_to_bytes,
    sign_sealed_write_approval,
    verify_sealed_write_approval_signature,
)
from pfsense_mcp.tier1.write_security_class import WriteSecurityClass

__all__ = [
    "STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID",
    "SigningError",
    "render_approval_review",
    "sign_approval_command",
    "sign_standard_sealed_write_approval",
]

_AUTHORITY_FILE_MAX_BYTES = 4096
_PRIVATE_KEY_FILE_MAX_BYTES = 32


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
    Mirrors `anchor_evidence_export_signing.py`'s own
    `_load_pinned_authority_file()` file shape exactly
    (`{"authority_id": "...", "public_key_hex": "<64 lowercase hex>"}`).
    Refuses (fail-closed) a file naming any authority_id other than
    `STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID`."""

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
        authority = PinnedAuthority(authority_id=authority_id, public_key=bytes.fromhex(public_key_hex))
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, KeyError, Tier1Error) as exc:
        raise SigningError(f"pinned authority file is malformed: {path}") from exc
    if authority.authority_id != STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID:
        raise SigningError(
            f"pinned authority file names {authority.authority_id!r}, "
            f"expected exactly {STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID!r}"
        )
    return authority


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    """Loads exactly one raw 32-byte Ed25519 private key -- the same
    convention every other signing module in this package already uses.
    Never logged, never re-serialized, never written anywhere by this
    function, never returned to any caller outside this process."""

    raw = _read_secure(path, max_bytes=_PRIVATE_KEY_FILE_MAX_BYTES)
    if len(raw) != _PRIVATE_KEY_FILE_MAX_BYTES:
        raise SigningError(f"private key file is not exactly 32 bytes: {path}")
    try:
        return Ed25519PrivateKey.from_private_bytes(raw)
    except ValueError as exc:
        raise SigningError(f"private key file does not contain a valid Ed25519 key: {path}") from exc


def render_approval_review(
    *,
    contract_id: str,
    state_version: int,
    security_class: WriteSecurityClass,
    execution_intent_digest: str,
    target_identity_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    authority_id: str,
) -> str:
    """The required human-readable review, shown to the operator before
    any signature is produced. Every field here is exactly what will be
    signed -- nothing is fabricated, inferred, or fetched from anywhere
    else. The operator is expected to have independently confirmed this
    review matches the actual rendered semantic intent of the pending
    contract before typing 'yes'."""

    lines = [
        "=" * 72,
        "STANDARD SEALED WRITE APPROVAL REVIEW",
        "=" * 72,
        f"contract_id:              {contract_id}",
        f"state_version:            {state_version}",
        f"security_class:           {security_class.value}",
        f"execution_intent_digest:  {execution_intent_digest}",
        f"target_identity_digest:   {target_identity_digest}",
        f"issued_at (UTC):          {issued_at.isoformat()}",
        f"expires_at (UTC):         {expires_at.isoformat()}",
        f"authority_id:             {authority_id}",
        "=" * 72,
        "This approval, alone, authorizes exactly one narrowly-scoped,",
        "low-consequence mutation -- no off-host authorization, no",
        "confirmation ceremony, no TPM witness. Verify the contract_id/",
        "state_version/execution_intent_digest/target_identity_digest",
        "above exactly match the actual pending contract before proceeding.",
    ]
    return "\n".join(lines)


def sign_standard_sealed_write_approval(
    *,
    contract_id: str,
    state_version: int,
    execution_intent_digest: str,
    target_identity_digest: str,
    issued_at: datetime,
    expires_at: datetime,
    private_key: Ed25519PrivateKey,
    authority: PinnedAuthority,
) -> SealedWriteApproval:
    """The sole signing operation. The caller must have already obtained
    explicit operator approval -- this function performs no interaction
    of its own and is never invoked automatically anywhere in this
    module. `security_class` is never a parameter here: this function
    only ever signs `STANDARD_SEALED_WRITE`, the sole class this signer
    exists for.

    Builds the payload and signs it via the existing, unmodified
    `build_sealed_write_approval_payload()`/`sign_sealed_write_approval()`
    primitives -- no reimplemented canonicalization, serialization, or
    signing logic. Self-verifies the result against `authority` before
    returning, raising `SigningError` if the produced signature does not
    verify (the supplied private key does not match the supplied public
    authority)."""

    if authority.authority_id != STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID:
        raise SigningError(
            f"refusing to sign for authority {authority.authority_id!r}, "
            f"expected exactly {STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID!r}"
        )
    try:
        payload = build_sealed_write_approval_payload(
            contract_id=contract_id,
            state_version=state_version,
            security_class=WriteSecurityClass.STANDARD_SEALED_WRITE,
            execution_intent_digest=execution_intent_digest,
            target_identity_digest=target_identity_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )
    except SealedWriteApprovalError as exc:
        raise SigningError(f"could not build the SealedWriteApproval payload: {exc}") from exc
    approval = sign_sealed_write_approval(payload, authority_id=authority.authority_id, private_key=private_key)
    if not verify_sealed_write_approval_signature(approval, PinnedAuthoritySet((authority,))):
        raise SigningError(
            "signed SealedWriteApproval failed self-verification against the pinned authority "
            "-- the supplied private key does not match the supplied public authority file"
        )
    return approval


def _required_env_path(name: str) -> Path:
    value = os.environ.get(name)
    if not value:
        raise SigningError(f"required signing environment variable is missing: {name}")
    return Path(value)


def _prompt_operator_approval(review: str) -> bool:
    print(review)
    response = input("Sign this STANDARD sealed-write approval? Type exactly 'yes' to proceed, anything else refuses: ")
    return response.strip() == "yes"


def sign_approval_command(argv: list[str] | None = None) -> int:
    """The full `sign-approval` workflow: parse explicit finite inputs,
    load the pinned authority and private key, render the review,
    require explicit approval, sign, self-verify, round-trip through the
    production serializer/parser a second time, write. Returns `0` on a
    signed artifact written, `1` on operator refusal. Raises
    `SigningError`/`ArtifactExchangeError` for any fail-closed condition
    -- `main()` catches and reports these cleanly."""

    parser = argparse.ArgumentParser(
        prog="standard-sealed-write-signing sign-approval",
        description="Sign a fresh SealedWriteApproval from an explicit, rendered, operator-reviewed request.",
    )
    parser.add_argument("--contract-id", required=True, help="Exact contract_id this approval is bound to")
    parser.add_argument("--state-version", required=True, type=int, help="Exact contract state_version at request time")
    parser.add_argument(
        "--execution-intent-digest", required=True, help="Exact execution_intent_digest from the rendered request"
    )
    parser.add_argument(
        "--target-identity-digest", required=True, help="Exact target_identity_digest from the rendered request"
    )
    parser.add_argument(
        "--ttl-minutes",
        required=True,
        type=int,
        help="Validity window in minutes from now -- no default; this repository does not constrain a value",
    )
    parser.add_argument("--output", required=True, type=Path, help="Destination file for the signed approval")
    args = parser.parse_args(argv)

    if args.state_version < 0:
        raise SigningError("--state-version must be a non-negative integer")
    if args.ttl_minutes <= 0:
        raise SigningError("--ttl-minutes must be a positive integer")

    authority_file = _required_env_path("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_AUTHORITY_FILE")
    private_key_file = _required_env_path("PFSENSE_SIGNING_STANDARD_SEALED_WRITE_PRIVATE_KEY_FILE")

    authority = _load_pinned_authority_file(authority_file)
    private_key = _load_private_key(private_key_file)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=args.ttl_minutes)

    review = render_approval_review(
        contract_id=args.contract_id,
        state_version=args.state_version,
        security_class=WriteSecurityClass.STANDARD_SEALED_WRITE,
        execution_intent_digest=args.execution_intent_digest,
        target_identity_digest=args.target_identity_digest,
        issued_at=now,
        expires_at=expires_at,
        authority_id=authority.authority_id,
    )
    if not _prompt_operator_approval(review):
        print("Refused -- no signature produced.")
        return 1

    approval = sign_standard_sealed_write_approval(
        contract_id=args.contract_id,
        state_version=args.state_version,
        execution_intent_digest=args.execution_intent_digest,
        target_identity_digest=args.target_identity_digest,
        issued_at=now,
        expires_at=expires_at,
        private_key=private_key,
        authority=authority,
    )

    # Round-trip through the exact production serializer/parser before
    # writing -- proves the bytes this module is about to persist are
    # genuinely re-parseable and re-verifiable by the same functions the
    # runtime side will use, not merely internally self-consistent.
    serialized = sealed_write_approval_to_bytes(approval)
    reparsed = sealed_write_approval_from_bytes(serialized)
    if not verify_sealed_write_approval_signature(reparsed, PinnedAuthoritySet((authority,))):
        raise SigningError(
            "serialization round-trip failed self-verification -- refusing to write a possibly corrupted approval"
        )

    write_secure_new(args.output, serialized)
    print(f"Signed SealedWriteApproval written to {args.output}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="standard-sealed-write-signing",
        description=(
            "Local, operator-only signing tool for producing a fresh, signed SealedWriteApproval "
            f"for the {STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID!r} authority."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser(
        "sign-approval",
        help="Review and sign an explicit rendered request, producing a signed SealedWriteApproval.",
    )
    args, remaining = parser.parse_known_args(argv)

    try:
        if args.command == "sign-approval":
            return sign_approval_command(remaining)
        raise SigningError(f"unsupported command: {args.command}")  # unreachable -- argparse enforces choices
    except (SigningError, ArtifactExchangeError, SealedWriteApprovalError, Tier1Error) as exc:
        print(f"Refused: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
