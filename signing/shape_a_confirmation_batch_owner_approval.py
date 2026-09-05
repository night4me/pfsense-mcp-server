"""ShapeAConfirmationBatchOwnerApproval -- the confirmation-side
counterpart to `shape_a_batch_owner_approval.py`: one Ed25519-signed
artifact cryptographically binding one owner-reviewed
`ShapeAConfirmationBatchManifest` to the exact set of `ConfirmationEvidence`
this signer is about to produce for it.

## Binding mechanism (simpler than the authorization case)

Unlike `PlanAuthorizationV2.authorization_id`, `ConfirmationEvidence`
carries no signer-generated identifier that could be pre-committed
before signing -- its `contract_id`/`operation_id` are not chosen by
the signer at all; they already exist on the already-created
`RecoveryContract` the pending confirmation request names, read
unchanged from disk. This module binds directly to those pre-existing
values instead: the signed payload commits to the exact
`(capability_symbol, contract_id, operation_id, intent_digest)` tuple
for every capability in the batch, plus an independently recomputed
`manifest_digest`. A verifier holding this approval, an individual
signed `ConfirmationEvidence`, and the pinned authority that signed
both can prove the individual evidence belongs to exactly this approved
batch -- `verify_confirmation_evidence_batch_membership()` below is
that check, mirroring
`shape_a_batch_owner_approval.verify_plan_authorization_v2_batch_membership()`
exactly.

## What this module is not

Not consumed by `confirm_and_handoff()`/`write_execution_core.py` at
all -- purely an off-band audit/verification artifact, exactly like
`ShapeABatchOwnerApproval` and `AnchorEvidenceExport`.

## Why this lives in `signing/`, not `src/pfsense_mcp/tier1/`

Mirrors `shape_a_batch_owner_approval.py`'s own "Why this lives in
signing/" note exactly -- kept alongside its authorization-side sibling
for the same reason, even though this specific module's imports
(`confirmation`/`confirmation_providers`, not `security_authorization`)
would not themselves have tripped an isolation test.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.tier1.canonical import CanonicalValue, canonical_json
from pfsense_mcp.tier1.confirmation import ConfirmationEvidence
from pfsense_mcp.tier1.confirmation_providers import ACCEPTED_ALGORITHM, signing_payload
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthoritySet
from pfsense_mcp.tier1.errors import Tier1Error
from pfsense_mcp.tier1.shape_a_confirmation_batch_manifest import (
    ShapeAConfirmationBatchManifest,
    compute_shape_a_confirmation_batch_manifest_digest,
)

SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION = 1

_SIGNING_DOMAIN = "pfsense-mcp-shape-a-confirmation-batch-owner-approval-v1"

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_ED25519_SIGNATURE_BYTES = 64


class ShapeAConfirmationBatchOwnerApprovalError(Tier1Error):
    """Refused: malformed, unsigned, untrusted, expired, future-dated,
    or otherwise invalid `ShapeAConfirmationBatchOwnerApproval`/payload,
    or an attempt to build one from an entry set that does not exactly
    match the manifest it claims to approve."""


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


@dataclass(frozen=True)
class ShapeAConfirmationBatchOwnerApprovalEntry:
    capability_symbol: str
    contract_id: str
    operation_id: str
    intent_digest: str

    def __post_init__(self) -> None:
        if not isinstance(self.capability_symbol, str) or not _SAFE_TOKEN.fullmatch(self.capability_symbol):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entry capability_symbol is invalid.")
        if not isinstance(self.contract_id, str) or not _SAFE_TOKEN.fullmatch(self.contract_id):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entry contract_id is invalid.")
        if not isinstance(self.operation_id, str) or not _SAFE_TOKEN.fullmatch(self.operation_id):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entry operation_id is invalid.")
        if not isinstance(self.intent_digest, str) or not _HEX_64.fullmatch(self.intent_digest):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entry intent_digest is invalid.")


@dataclass(frozen=True)
class ShapeAConfirmationBatchOwnerApprovalPayload:
    schema_version: int
    batch_id: str
    manifest_digest: str
    expected_authority_id: str
    expected_algorithm: str
    entries: tuple[ShapeAConfirmationBatchOwnerApprovalEntry, ...]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if (
            type(self.schema_version) is not int
            or self.schema_version != SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION
        ):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval schema_version is unsupported.")
        if not isinstance(self.batch_id, str) or not _SAFE_TOKEN.fullmatch(self.batch_id):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval batch_id is invalid.")
        if not isinstance(self.manifest_digest, str) or not _HEX_64.fullmatch(self.manifest_digest):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval manifest_digest is invalid.")
        if not isinstance(self.expected_authority_id, str) or not _SAFE_TOKEN.fullmatch(self.expected_authority_id):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval expected_authority_id is invalid.")
        if not isinstance(self.expected_algorithm, str) or not _SAFE_TOKEN.fullmatch(self.expected_algorithm):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval expected_algorithm is invalid.")
        if not isinstance(self.entries, tuple) or not self.entries:
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entries are invalid.")
        if not all(isinstance(entry, ShapeAConfirmationBatchOwnerApprovalEntry) for entry in self.entries):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entry is invalid.")
        symbols = [entry.capability_symbol for entry in self.entries]
        if len(set(symbols)) != len(symbols):
            raise ShapeAConfirmationBatchOwnerApprovalError(
                "Batch owner approval must not contain duplicate capability_symbol."
            )
        if list(symbols) != sorted(symbols):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval entries must be canonically sorted.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval validity window is invalid.")


def build_shape_a_confirmation_batch_owner_approval_payload(
    manifest: ShapeAConfirmationBatchManifest, *, batch_id: str, issued_at: datetime, expires_at: datetime
) -> ShapeAConfirmationBatchOwnerApprovalPayload:
    """The one place a payload is built. `manifest_digest` is
    independently recomputed from `manifest` itself, never accepted as
    caller-supplied -- a caller cannot forge approval for content never
    actually built via `build_shape_a_confirmation_batch_manifest()`."""

    if not isinstance(manifest, ShapeAConfirmationBatchManifest):
        raise ShapeAConfirmationBatchOwnerApprovalError("Expected ShapeAConfirmationBatchManifest.")
    entries = tuple(
        ShapeAConfirmationBatchOwnerApprovalEntry(
            capability_symbol=entry.capability_symbol,
            contract_id=entry.contract_id,
            operation_id=entry.operation_id,
            intent_digest=entry.intent_digest,
        )
        for entry in manifest.entries
    )
    return ShapeAConfirmationBatchOwnerApprovalPayload(
        schema_version=SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION,
        batch_id=batch_id,
        manifest_digest=compute_shape_a_confirmation_batch_manifest_digest(manifest),
        expected_authority_id=manifest.expected_authority_id,
        expected_algorithm=manifest.expected_algorithm,
        entries=entries,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _payload_body(payload: ShapeAConfirmationBatchOwnerApprovalPayload) -> dict[str, CanonicalValue]:
    return {
        "digest_purpose": _SIGNING_DOMAIN,
        "schema_version": payload.schema_version,
        "batch_id": payload.batch_id,
        "manifest_digest": payload.manifest_digest,
        "expected_authority_id": payload.expected_authority_id,
        "expected_algorithm": payload.expected_algorithm,
        "entries": [
            {
                "capability_symbol": entry.capability_symbol,
                "contract_id": entry.contract_id,
                "operation_id": entry.operation_id,
                "intent_digest": entry.intent_digest,
            }
            for entry in payload.entries
        ],
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
    }


def shape_a_confirmation_batch_owner_approval_signing_payload(
    payload: ShapeAConfirmationBatchOwnerApprovalPayload,
) -> bytes:
    if not isinstance(payload, ShapeAConfirmationBatchOwnerApprovalPayload):
        raise ShapeAConfirmationBatchOwnerApprovalError("Expected ShapeAConfirmationBatchOwnerApprovalPayload.")
    return canonical_json(_payload_body(payload))


@dataclass(frozen=True)
class ShapeAConfirmationBatchOwnerApproval:
    schema_version: int
    batch_id: str
    manifest_digest: str
    expected_authority_id: str
    expected_algorithm: str
    entries: tuple[ShapeAConfirmationBatchOwnerApprovalEntry, ...]
    issued_at: datetime
    expires_at: datetime
    authority_id: str
    proof: bytes

    def __post_init__(self) -> None:
        ShapeAConfirmationBatchOwnerApprovalPayload(
            schema_version=self.schema_version,
            batch_id=self.batch_id,
            manifest_digest=self.manifest_digest,
            expected_authority_id=self.expected_authority_id,
            expected_algorithm=self.expected_algorithm,
            entries=self.entries,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not isinstance(self.authority_id, str) or not _SAFE_TOKEN.fullmatch(self.authority_id):
            raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval authority_id is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise ShapeAConfirmationBatchOwnerApprovalError(
                "Batch owner approval proof must be a 64-byte Ed25519 signature."
            )


def shape_a_confirmation_batch_owner_approval_payload_of(
    approval: ShapeAConfirmationBatchOwnerApproval,
) -> ShapeAConfirmationBatchOwnerApprovalPayload:
    if not isinstance(approval, ShapeAConfirmationBatchOwnerApproval):
        raise ShapeAConfirmationBatchOwnerApprovalError("Expected ShapeAConfirmationBatchOwnerApproval.")
    return ShapeAConfirmationBatchOwnerApprovalPayload(
        schema_version=approval.schema_version,
        batch_id=approval.batch_id,
        manifest_digest=approval.manifest_digest,
        expected_authority_id=approval.expected_authority_id,
        expected_algorithm=approval.expected_algorithm,
        entries=approval.entries,
        issued_at=approval.issued_at,
        expires_at=approval.expires_at,
    )


def sign_shape_a_confirmation_batch_owner_approval(
    payload: ShapeAConfirmationBatchOwnerApprovalPayload, *, authority_id: str, private_key: Ed25519PrivateKey
) -> ShapeAConfirmationBatchOwnerApproval:
    if not isinstance(payload, ShapeAConfirmationBatchOwnerApprovalPayload):
        raise ShapeAConfirmationBatchOwnerApprovalError("Expected ShapeAConfirmationBatchOwnerApprovalPayload.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise ShapeAConfirmationBatchOwnerApprovalError("authority_id is invalid.")
    proof = private_key.sign(shape_a_confirmation_batch_owner_approval_signing_payload(payload))
    return ShapeAConfirmationBatchOwnerApproval(
        schema_version=payload.schema_version,
        batch_id=payload.batch_id,
        manifest_digest=payload.manifest_digest,
        expected_authority_id=payload.expected_authority_id,
        expected_algorithm=payload.expected_algorithm,
        entries=payload.entries,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        authority_id=authority_id,
        proof=proof,
    )


def verify_shape_a_confirmation_batch_owner_approval_signature(
    approval: ShapeAConfirmationBatchOwnerApproval, authorities: PinnedAuthoritySet
) -> bool:
    if not isinstance(approval, ShapeAConfirmationBatchOwnerApproval):
        return False
    payload = shape_a_confirmation_batch_owner_approval_payload_of(approval)
    return authorities.verify_signature(
        authority_id=approval.authority_id,
        message=shape_a_confirmation_batch_owner_approval_signing_payload(payload),
        signature=approval.proof,
    )


def verify_confirmation_evidence_batch_membership(
    evidence: ConfirmationEvidence,
    approval: ShapeAConfirmationBatchOwnerApproval,
    *,
    capability_symbol: str,
    authorities: PinnedAuthoritySet,
) -> bool:
    """The confirmation-side mirror of
    `verify_plan_authorization_v2_batch_membership()`. Returns `False`
    (never raises) unless ALL of: `approval`'s own signature verifies;
    `evidence`'s own signature verifies (`Ed25519ConfirmationVerifier`);
    `approval` has exactly one entry for `capability_symbol`; that
    entry's `contract_id`/`operation_id`/`intent_digest` all equal
    `evidence`'s own fields. An evidence artifact genuinely signed under
    one batch's approval can never satisfy this check against a
    different batch's approval, because the different approval's own
    signature does not cover this evidence's `(contract_id,
    operation_id)` pair at all."""

    if not isinstance(evidence, ConfirmationEvidence) or not isinstance(approval, ShapeAConfirmationBatchOwnerApproval):
        return False
    if not verify_shape_a_confirmation_batch_owner_approval_signature(approval, authorities):
        return False
    if evidence.algorithm != ACCEPTED_ALGORITHM:
        return False
    if not authorities.verify_signature(
        authority_id=evidence.authority_id, message=signing_payload(evidence), signature=evidence.proof
    ):
        return False
    matching = [entry for entry in approval.entries if entry.capability_symbol == capability_symbol]
    if len(matching) != 1:
        return False
    entry = matching[0]
    return (
        entry.contract_id == evidence.contract_id
        and entry.operation_id == evidence.operation_id
        and entry.intent_digest == evidence.intent_digest
    )


def shape_a_confirmation_batch_owner_approval_to_bytes(approval: ShapeAConfirmationBatchOwnerApproval) -> bytes:
    payload = shape_a_confirmation_batch_owner_approval_payload_of(approval)
    body: dict[str, CanonicalValue] = _payload_body(payload)
    body["authority_id"] = approval.authority_id
    body["proof_hex"] = approval.proof.hex()
    return canonical_json(body)


def shape_a_confirmation_batch_owner_approval_from_bytes(raw: bytes) -> ShapeAConfirmationBatchOwnerApproval:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval file is not valid JSON.") from exc
    if not isinstance(body, dict):
        raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval file is not a JSON object.")
    required = {
        "digest_purpose",
        "schema_version",
        "batch_id",
        "manifest_digest",
        "expected_authority_id",
        "expected_algorithm",
        "entries",
        "issued_at",
        "expires_at",
        "authority_id",
        "proof_hex",
    }
    if set(body) != required:
        raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval file has an unexpected field set.")
    try:
        issued_at = datetime.fromisoformat(body["issued_at"])
        expires_at = datetime.fromisoformat(body["expires_at"])
        proof = bytes.fromhex(body["proof_hex"])
        raw_entries = body["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError
        entries = tuple(
            ShapeAConfirmationBatchOwnerApprovalEntry(
                capability_symbol=str(entry["capability_symbol"]),
                contract_id=str(entry["contract_id"]),
                operation_id=str(entry["operation_id"]),
                intent_digest=str(entry["intent_digest"]),
            )
            for entry in raw_entries
        )
    except (TypeError, ValueError, KeyError, ShapeAConfirmationBatchOwnerApprovalError) as exc:
        raise ShapeAConfirmationBatchOwnerApprovalError("Batch owner approval file has a malformed field.") from exc
    return ShapeAConfirmationBatchOwnerApproval(
        schema_version=body["schema_version"],
        batch_id=body["batch_id"],
        manifest_digest=body["manifest_digest"],
        expected_authority_id=body["expected_authority_id"],
        expected_algorithm=body["expected_algorithm"],
        entries=entries,
        issued_at=issued_at,
        expires_at=expires_at,
        authority_id=body["authority_id"],
        proof=proof,
    )


__all__ = [
    "SHAPE_A_CONFIRMATION_BATCH_OWNER_APPROVAL_SCHEMA_VERSION",
    "ShapeAConfirmationBatchOwnerApproval",
    "ShapeAConfirmationBatchOwnerApprovalEntry",
    "ShapeAConfirmationBatchOwnerApprovalError",
    "ShapeAConfirmationBatchOwnerApprovalPayload",
    "build_shape_a_confirmation_batch_owner_approval_payload",
    "shape_a_confirmation_batch_owner_approval_from_bytes",
    "shape_a_confirmation_batch_owner_approval_payload_of",
    "shape_a_confirmation_batch_owner_approval_signing_payload",
    "shape_a_confirmation_batch_owner_approval_to_bytes",
    "sign_shape_a_confirmation_batch_owner_approval",
    "verify_confirmation_evidence_batch_membership",
    "verify_shape_a_confirmation_batch_owner_approval_signature",
]
