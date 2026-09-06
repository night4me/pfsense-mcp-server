"""SealedWriteApproval -- the STANDARD_SEALED_WRITE owner-approval
artifact (2026-09-06 owner-authorized two-tier WRITE security model,
Phase 1).

## Why this exists

`HIGH_ASSURANCE_TIER1` capabilities are approved by a full off-host
ceremony: `PlanAuthorizationV2` (authorization) + `ConfirmationEvidence`
(confirmation), both signed by authorities that never reside on the
runtime host, plus an `AnchorEvidenceExport`/live TPM witness check.
`STANDARD_SEALED_WRITE` capabilities replace that entire ceremony with
exactly one signed artifact, `SealedWriteApproval` -- but the artifact
itself must still bind everything a forged or replayed approval could
otherwise exploit: the exact contract, its exact version, the class it
claims to approve, the exact semantic intent, and the exact target.

Signed with a **dedicated** Ed25519 keypair
(`standard-sealed-write-approval-authority-v1`), distinct from every
HIGH_ASSURANCE authority (authorization, confirmation, posture-evidence,
reconciliation) and from every store's own HMAC integrity key -- reusing
`tier1/ed25519_authority.py`'s `PinnedAuthority`/`PinnedAuthoritySet`
mechanics exactly like `anchor_evidence_export.py` already does, never
reinventing signature verification.

**No private key is provisioned by this module or anywhere in this
change**, and no local OS signer identity is provisioned either --
`sign_sealed_write_approval()` exists so the mechanism is implementable
and testable with synthetic, ephemeral keys, exactly like
`sign_anchor_evidence_export()`. Real key custody, the separated local
signer identity, and any live signing are a separate, explicit,
owner-gated provisioning phase (docs/tier1/specs/*, not this module).

**Threat model (stated explicitly, matching the accepted architecture):**
compromise of the mutation runtime alone must not permit forging an
approval, because the runtime never holds this authority's private key.
Full privileged compromise of the physical runtime host is explicitly
outside this tier's protection. HIGH_ASSURANCE_TIER1 retains its
stronger off-host-authority-separation property, which this tier does
not claim.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .canonical import CanonicalValue, canonical_json
from .ed25519_authority import PinnedAuthoritySet
from .errors import Tier1Error
from .write_security_class import WriteSecurityClass

#: Bumped whenever a field is added, removed, or reinterpreted -- an
#: approval signed under a prior schema can never silently verify under
#: a new one, because the version is itself part of the signed payload.
SEALED_WRITE_APPROVAL_SCHEMA_VERSION = 1

#: Domain-separation literal included in the signed payload -- so a
#: signature over this shape can never be replayed as, or confused
#: with, a signature over any other signed artifact this codebase
#: produces (PlanAuthorizationV2, ConfirmationEvidence,
#: AnchorEvidenceExport, ReconciliationEvidence all use their own
#: distinct literals for the identical reason).
_SIGNING_DOMAIN = "pfsense-mcp-standard-sealed-write-approval-v1"

#: The dedicated STANDARD approval authority identifier this module's
#: signing/verification functions require -- never any HIGH_ASSURANCE
#: authority_id.
STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID = "standard-sealed-write-approval-authority-v1"

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_ED25519_SIGNATURE_BYTES = 64


class SealedWriteApprovalError(Tier1Error):
    """Refused: malformed, unsigned, untrusted, expired, future-dated,
    or otherwise invalid `SealedWriteApproval`/payload. Never raised by
    a successful verification -- callers get `False` from
    `verify_sealed_write_approval()` for a bad/mismatched approval
    specifically; this exception is for structurally invalid data."""


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


@dataclass(frozen=True)
class SealedWriteApprovalPayload:
    """Every signed field except `proof`. Validated eagerly -- an
    invalid payload can never be constructed, let alone signed.

    Binds, at minimum, exactly what the accepted architecture requires:
    `contract_id`, `state_version`, `security_class`,
    `execution_intent_digest`, `target_identity_digest` -- plus an
    explicit validity window, so a stale or indefinitely-reusable
    approval is structurally impossible."""

    schema_version: int
    contract_id: str
    state_version: int
    security_class: WriteSecurityClass
    execution_intent_digest: str
    target_identity_digest: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SEALED_WRITE_APPROVAL_SCHEMA_VERSION:
            raise SealedWriteApprovalError("SealedWriteApproval payload schema_version is unsupported.")
        if not isinstance(self.contract_id, str) or not _SAFE_TOKEN.fullmatch(self.contract_id):
            raise SealedWriteApprovalError("SealedWriteApproval payload contract_id is invalid.")
        if type(self.state_version) is not int or isinstance(self.state_version, bool) or self.state_version < 0:
            raise SealedWriteApprovalError("SealedWriteApproval payload state_version must be a non-negative integer.")
        if not isinstance(self.security_class, WriteSecurityClass):
            raise SealedWriteApprovalError("SealedWriteApproval payload security_class is invalid.")
        if not isinstance(self.execution_intent_digest, str) or not _HEX_64.fullmatch(self.execution_intent_digest):
            raise SealedWriteApprovalError("SealedWriteApproval payload execution_intent_digest is invalid.")
        if not isinstance(self.target_identity_digest, str) or not _HEX_64.fullmatch(self.target_identity_digest):
            raise SealedWriteApprovalError("SealedWriteApproval payload target_identity_digest is invalid.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise SealedWriteApprovalError("SealedWriteApproval payload timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise SealedWriteApprovalError("SealedWriteApproval payload validity window is invalid.")


def build_sealed_write_approval_payload(
    *,
    contract_id: str,
    state_version: int,
    security_class: WriteSecurityClass,
    execution_intent_digest: str,
    target_identity_digest: str,
    issued_at: datetime,
    expires_at: datetime,
) -> SealedWriteApprovalPayload:
    """The one place a payload is built from an already-rendered,
    owner-reviewed unsigned approval request -- pure data assembly plus
    the validation `__post_init__` already enforces. Never reads a
    store, a contract, or anything else itself."""

    return SealedWriteApprovalPayload(
        schema_version=SEALED_WRITE_APPROVAL_SCHEMA_VERSION,
        contract_id=contract_id,
        state_version=state_version,
        security_class=security_class,
        execution_intent_digest=execution_intent_digest,
        target_identity_digest=target_identity_digest,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def sealed_write_approval_signing_payload(payload: SealedWriteApprovalPayload) -> bytes:
    """Canonical signing bytes -- key-sorted, whitespace-free, Unicode-
    normalized JSON via `tier1.canonical.canonical_json()`, the same
    primitive every other signed artifact in this codebase uses."""

    if not isinstance(payload, SealedWriteApprovalPayload):
        raise SealedWriteApprovalError("Expected SealedWriteApprovalPayload.")
    body: dict[str, CanonicalValue] = {
        "digest_purpose": _SIGNING_DOMAIN,
        "schema_version": payload.schema_version,
        "contract_id": payload.contract_id,
        "state_version": payload.state_version,
        "security_class": payload.security_class.value,
        "execution_intent_digest": payload.execution_intent_digest,
        "target_identity_digest": payload.target_identity_digest,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
    }
    return canonical_json(body)


@dataclass(frozen=True)
class SealedWriteApproval:
    """Signed approval -- the one artifact type
    `verify_sealed_write_approval()` ever loads. Carries its own
    `authority_id` so a verifier holding more than one pinned STANDARD
    authority (e.g. during key rotation) knows which public key to
    check against, exactly like `PlanAuthorizationV2.authority_id`."""

    schema_version: int
    contract_id: str
    state_version: int
    security_class: WriteSecurityClass
    execution_intent_digest: str
    target_identity_digest: str
    issued_at: datetime
    expires_at: datetime
    authority_id: str
    proof: bytes

    def __post_init__(self) -> None:
        # Re-validates via the same payload shape -- constructing a
        # SealedWriteApproval with an invalid field is impossible,
        # exactly like AnchorEvidenceExport's own discipline.
        SealedWriteApprovalPayload(
            schema_version=self.schema_version,
            contract_id=self.contract_id,
            state_version=self.state_version,
            security_class=self.security_class,
            execution_intent_digest=self.execution_intent_digest,
            target_identity_digest=self.target_identity_digest,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not isinstance(self.authority_id, str) or not _SAFE_TOKEN.fullmatch(self.authority_id):
            raise SealedWriteApprovalError("SealedWriteApproval authority_id is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise SealedWriteApprovalError("SealedWriteApproval proof must be a 64-byte Ed25519 signature.")


def sealed_write_approval_payload_of(approval: SealedWriteApproval) -> SealedWriteApprovalPayload:
    """Reconstruct the exact signed payload from the artifact itself --
    the same pattern `anchor_evidence_export_payload_of()` uses."""

    if not isinstance(approval, SealedWriteApproval):
        raise SealedWriteApprovalError("Expected SealedWriteApproval.")
    return SealedWriteApprovalPayload(
        schema_version=approval.schema_version,
        contract_id=approval.contract_id,
        state_version=approval.state_version,
        security_class=approval.security_class,
        execution_intent_digest=approval.execution_intent_digest,
        target_identity_digest=approval.target_identity_digest,
        issued_at=approval.issued_at,
        expires_at=approval.expires_at,
    )


def sign_sealed_write_approval(
    payload: SealedWriteApprovalPayload, *, authority_id: str, private_key: Ed25519PrivateKey
) -> SealedWriteApproval:
    """Signing-side only -- runs wherever the real STANDARD approval
    private key lives (a separate, local, owner-provisioned identity;
    see this module's own docstring). Never called with a real key by
    anything in this change; used only by tests, with synthetic,
    ephemeral keys."""

    if not isinstance(payload, SealedWriteApprovalPayload):
        raise SealedWriteApprovalError("Expected SealedWriteApprovalPayload.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise SealedWriteApprovalError("authority_id is invalid.")
    proof = private_key.sign(sealed_write_approval_signing_payload(payload))
    return SealedWriteApproval(
        schema_version=payload.schema_version,
        contract_id=payload.contract_id,
        state_version=payload.state_version,
        security_class=payload.security_class,
        execution_intent_digest=payload.execution_intent_digest,
        target_identity_digest=payload.target_identity_digest,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        authority_id=authority_id,
        proof=proof,
    )


def verify_sealed_write_approval_signature(approval: SealedWriteApproval, authorities: PinnedAuthoritySet) -> bool:
    """Signature-only verification -- the narrow primitive
    `verify_sealed_write_approval()` below composes with the actual
    contract-binding checks. Never raises for an ordinary bad signature;
    returns `False` exactly like `PinnedAuthoritySet.verify_signature()`
    itself does for an unknown/inactive authority or a malformed proof."""

    if not isinstance(approval, SealedWriteApproval):
        return False
    payload = sealed_write_approval_payload_of(approval)
    return authorities.verify_signature(
        authority_id=approval.authority_id,
        message=sealed_write_approval_signing_payload(payload),
        signature=approval.proof,
    )


def verify_sealed_write_approval(
    approval: object,
    *,
    authorities: PinnedAuthoritySet,
    now: datetime,
    contract_id: str,
    state_version: int,
    security_class: WriteSecurityClass,
    execution_intent_digest: str,
    target_identity_digest: str,
) -> bool:
    """The one function a STANDARD_SEALED_WRITE caller ever needs:
    fails closed (`False`, never an exception) on every adversarial
    condition the accepted architecture names -- wrong authority, wrong
    signing domain (folded into signature verification via
    `_SIGNING_DOMAIN`), wrong contract, wrong state_version, wrong
    security_class, wrong intent digest, wrong target identity,
    malformed artifact, expired approval, or signature failure. Every
    comparison uses `==` against already-validated, fixed-shape typed
    fields (never raw untrusted strings compared insecurely), and every
    check happens before the signature check is trusted as sufficient
    -- an attacker who can produce *some* validly-signed approval for a
    *different* contract/version/class/intent/target must still fail
    here."""

    if not isinstance(approval, SealedWriteApproval):
        return False
    if not isinstance(now, datetime) or not _is_utc(now):
        return False
    if (
        approval.contract_id != contract_id
        or approval.state_version != state_version
        or approval.security_class != security_class
        or approval.execution_intent_digest != execution_intent_digest
        or approval.target_identity_digest != target_identity_digest
    ):
        return False
    if not (approval.issued_at <= now < approval.expires_at):
        return False
    return verify_sealed_write_approval_signature(approval, authorities)


def sealed_write_approval_to_bytes(approval: SealedWriteApproval) -> bytes:
    """Self-authenticating serialization -- no additional HMAC/integrity
    wrapping is needed, because the Ed25519 signature already makes
    tampering detectable. Plain, explicit JSON; never `repr()`/`pickle`/
    anything ambiguous."""

    payload = sealed_write_approval_payload_of(approval)
    body: dict[str, CanonicalValue] = {
        "schema_version": payload.schema_version,
        "contract_id": payload.contract_id,
        "state_version": payload.state_version,
        "security_class": payload.security_class.value,
        "execution_intent_digest": payload.execution_intent_digest,
        "target_identity_digest": payload.target_identity_digest,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
        "authority_id": approval.authority_id,
        "proof_hex": approval.proof.hex(),
    }
    return canonical_json(body)


def sealed_write_approval_from_bytes(raw: bytes) -> SealedWriteApproval:
    """Parses untrusted bytes into a `SealedWriteApproval`. Never trusts
    the parsed content beyond what `SealedWriteApproval.__post_init__`
    already validates -- a malformed, truncated, or wrong-shaped file
    fails closed with `SealedWriteApprovalError`, never a partially-
    populated object. Signature/binding validity is NOT checked here --
    that is `verify_sealed_write_approval()`'s job, kept as an explicit,
    separate step so "parses" and "is trustworthy" can never be
    conflated."""

    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SealedWriteApprovalError("SealedWriteApproval file is not valid JSON.") from exc
    if not isinstance(body, dict):
        raise SealedWriteApprovalError("SealedWriteApproval file is not a JSON object.")
    required = {
        "schema_version",
        "contract_id",
        "state_version",
        "security_class",
        "execution_intent_digest",
        "target_identity_digest",
        "issued_at",
        "expires_at",
        "authority_id",
        "proof_hex",
    }
    if set(body) != required:
        raise SealedWriteApprovalError("SealedWriteApproval file has an unexpected field set.")
    try:
        issued_at = datetime.fromisoformat(body["issued_at"])
        expires_at = datetime.fromisoformat(body["expires_at"])
        proof = bytes.fromhex(body["proof_hex"])
        security_class = WriteSecurityClass(body["security_class"])
    except (TypeError, ValueError) as exc:
        raise SealedWriteApprovalError("SealedWriteApproval file has a malformed field.") from exc
    return SealedWriteApproval(
        schema_version=body["schema_version"],
        contract_id=body["contract_id"],
        state_version=body["state_version"],
        security_class=security_class,
        execution_intent_digest=body["execution_intent_digest"],
        target_identity_digest=body["target_identity_digest"],
        issued_at=issued_at,
        expires_at=expires_at,
        authority_id=body["authority_id"],
        proof=proof,
    )


__all__ = [
    "SEALED_WRITE_APPROVAL_SCHEMA_VERSION",
    "STANDARD_SEALED_WRITE_APPROVAL_AUTHORITY_ID",
    "SealedWriteApproval",
    "SealedWriteApprovalError",
    "SealedWriteApprovalPayload",
    "build_sealed_write_approval_payload",
    "sealed_write_approval_from_bytes",
    "sealed_write_approval_payload_of",
    "sealed_write_approval_signing_payload",
    "sealed_write_approval_to_bytes",
    "sign_sealed_write_approval",
    "verify_sealed_write_approval",
    "verify_sealed_write_approval_signature",
]
