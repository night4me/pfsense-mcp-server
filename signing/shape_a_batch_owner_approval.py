"""ShapeABatchOwnerApproval -- the single Ed25519-signed artifact that
cryptographically binds one owner-reviewed `ShapeABatchManifest` to the
exact set of `PlanAuthorizationV2.authorization_id` values the signer is
about to produce for it.

## Why this exists

2026-09-05 owner review of the batch-ceremony redesign
(`shape_a_batch_manifest.py`) identified a real gap: nothing in an
individually signed `PlanAuthorizationV2` proves which batch manifest --
or even that any batch manifest -- the owner approved before it was
signed. The prior design's only link was procedural ("the signer loop
ran this capability after the prompt"), which a verifier examining
artifacts after the fact cannot check cryptographically. This module
closes that gap without touching `PlanAuthorizationV2`'s existing,
already-shipped schema (`security_authorization.py`) or anything
downstream of it -- `write_execution_core.py`/`MutationExecutor` remain
completely unaware this artifact type exists.

## Binding mechanism

`PlanAuthorizationV2.authorization_id` is already one of that artifact
type's own signed-payload fields (`security_authorization.py`'s field
table: "every field ... participates ... except proof"). The caller
(`write_batch1_signing.py`) pre-generates each capability's
`authorization_id` *before* the owner is shown the batch review, and
this artifact's own signed payload commits, under ONE Ed25519
signature, to the exact `(capability_symbol, execution_intent_digest,
authorization_id)` triple for every capability in the batch, plus an
independently recomputed `manifest_digest` binding it to the exact
manifest content the owner read. A verifier holding this approval, an
individual signed `PlanAuthorizationV2`, and the pinned authority that
signed both can therefore prove the individual artifact belongs to
exactly this approved batch --
`verify_plan_authorization_v2_batch_membership()` below is that check.
Because both signatures come from the same authority key, an attacker
who tampers with either half (substitutes an `authorization_id`, moves
an entry into a different batch, changes an `execution_intent_digest`)
breaks that half's own signature -- there is no way to keep both
signatures valid over changed content, and no way to move a genuinely
signed `PlanAuthorizationV2` from one batch's approval into another's,
since each batch's approval commits to its own distinct
`authorization_id` set.

## What this module is not

Not a new source of authorization: a verifier still independently
re-checks each `PlanAuthorizationV2`'s own signature, freshness,
plan-digest match, and risk-class binding exactly as before -- this
artifact only adds one more fact a verifier CAN additionally check
(batch membership), never a replacement for any existing check. Not
consumed by `authorize_and_create()`/`confirm_and_handoff()` at all --
purely an off-band audit/verification artifact, exactly like
`AnchorEvidenceExport`, whose sign/verify/serialization shape this
module deliberately mirrors.

## Why this lives in `signing/`, not `src/pfsense_mcp/tier1/`

An earlier draft placed this module under `pfsense_mcp.tier1` (alongside
`shape_a_batch_manifest.py`, which has no such import). That broke
`tests/test_security_authorization_isolation.py`'s and
`tests/test_security_authorization_verifier_isolation.py`'s own
no-production-importer proofs -- both scan every file under
`src/pfsense_mcp` for exactly the imports this module needs
(`PlanAuthorizationV2`, `verify_plan_authorization_v2_signature`), and
neither test's reviewed-exception list (`execution_coordinator.py`,
`alias_description_execution.py`, `write_execution_core.py` --
real execution-path composers, none of which this module is) has any
reason to grow for a module that is never wired into
`MutationExecutor`/any request-handling path. Moving both this module
and its confirmation-side mirror into `signing/` -- entirely outside
`src/pfsense_mcp`, exactly where `write_batch1_signing.py` and
`alias_description_signing.py` already live and already import
`security_authorization`/`security_authorization_verifier` freely --
keeps the actual invariant intact (this code genuinely never ships
inside the MCP server's own importable tree) instead of merely
satisfying the isolation tests' narrower textual pattern.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pfsense_mcp.security_authorization import PlanAuthorizationV2
from pfsense_mcp.security_authorization_verifier import verify_plan_authorization_v2_signature
from pfsense_mcp.security_posture_types import AnchorAssurance, CapabilityPosture
from pfsense_mcp.tier1.canonical import CanonicalValue, canonical_json
from pfsense_mcp.tier1.ed25519_authority import PinnedAuthoritySet
from pfsense_mcp.tier1.errors import Tier1Error
from pfsense_mcp.tier1.shape_a_batch_manifest import ShapeABatchManifest, compute_shape_a_batch_manifest_digest

SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION = 1

#: Domain-separation literal, the same role `security_authorization.py`'s
#: `"digest_purpose"` and `anchor_evidence_export.py`'s `_SIGNING_DOMAIN`
#: play for their own artifact types -- a signature over this shape can
#: never be replayed as, or confused with, a signature over any other
#: signed artifact this codebase produces.
_SIGNING_DOMAIN = "pfsense-mcp-shape-a-batch-owner-approval-v1"

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_ED25519_SIGNATURE_BYTES = 64


class ShapeABatchOwnerApprovalError(Tier1Error):
    """Refused: malformed, unsigned, untrusted, expired, future-dated,
    or otherwise invalid `ShapeABatchOwnerApproval`/payload, or an
    attempt to build one from an entry set that does not exactly match
    the manifest it claims to approve."""


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


@dataclass(frozen=True)
class ShapeABatchOwnerApprovalEntry:
    capability_symbol: str
    execution_intent_digest: str
    authorization_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.capability_symbol, str) or not _SAFE_TOKEN.fullmatch(self.capability_symbol):
            raise ShapeABatchOwnerApprovalError("Batch owner approval entry capability_symbol is invalid.")
        if not isinstance(self.execution_intent_digest, str) or not _HEX_64.fullmatch(self.execution_intent_digest):
            raise ShapeABatchOwnerApprovalError("Batch owner approval entry execution_intent_digest is invalid.")
        if not isinstance(self.authorization_id, str) or not _SAFE_TOKEN.fullmatch(self.authorization_id):
            raise ShapeABatchOwnerApprovalError("Batch owner approval entry authorization_id is invalid.")


@dataclass(frozen=True)
class ShapeABatchOwnerApprovalPayload:
    """Every signed field except `proof` -- mirrors
    `AnchorEvidenceExportPayload`'s discipline exactly."""

    schema_version: int
    batch_id: str
    manifest_digest: str
    requested_plan_digest: str
    requested_step_id: str
    target_capability_posture: CapabilityPosture
    target_anchor_assurance: AnchorAssurance
    entries: tuple[ShapeABatchOwnerApprovalEntry, ...]
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION:
            raise ShapeABatchOwnerApprovalError("Batch owner approval schema_version is unsupported.")
        if not isinstance(self.batch_id, str) or not _SAFE_TOKEN.fullmatch(self.batch_id):
            raise ShapeABatchOwnerApprovalError("Batch owner approval batch_id is invalid.")
        if not isinstance(self.manifest_digest, str) or not _HEX_64.fullmatch(self.manifest_digest):
            raise ShapeABatchOwnerApprovalError("Batch owner approval manifest_digest is invalid.")
        if not isinstance(self.requested_plan_digest, str) or not _HEX_64.fullmatch(self.requested_plan_digest):
            raise ShapeABatchOwnerApprovalError("Batch owner approval requested_plan_digest is invalid.")
        if not isinstance(self.requested_step_id, str) or not _SAFE_TOKEN.fullmatch(self.requested_step_id):
            raise ShapeABatchOwnerApprovalError("Batch owner approval requested_step_id is invalid.")
        if not isinstance(self.target_capability_posture, CapabilityPosture):
            raise ShapeABatchOwnerApprovalError("Batch owner approval target_capability_posture is invalid.")
        if not isinstance(self.target_anchor_assurance, AnchorAssurance):
            raise ShapeABatchOwnerApprovalError("Batch owner approval target_anchor_assurance is invalid.")
        if not isinstance(self.entries, tuple) or not self.entries:
            raise ShapeABatchOwnerApprovalError("Batch owner approval entries are invalid.")
        if not all(isinstance(entry, ShapeABatchOwnerApprovalEntry) for entry in self.entries):
            raise ShapeABatchOwnerApprovalError("Batch owner approval entry is invalid.")
        symbols = [entry.capability_symbol for entry in self.entries]
        if len(set(symbols)) != len(symbols):
            raise ShapeABatchOwnerApprovalError("Batch owner approval must not contain duplicate capability_symbol.")
        authorization_ids = [entry.authorization_id for entry in self.entries]
        if len(set(authorization_ids)) != len(authorization_ids):
            raise ShapeABatchOwnerApprovalError("Batch owner approval must not contain duplicate authorization_id.")
        if list(symbols) != sorted(symbols):
            raise ShapeABatchOwnerApprovalError("Batch owner approval entries must be in canonical sorted order.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise ShapeABatchOwnerApprovalError("Batch owner approval timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise ShapeABatchOwnerApprovalError("Batch owner approval validity window is invalid.")


def build_shape_a_batch_owner_approval_payload(
    manifest: ShapeABatchManifest,
    *,
    batch_id: str,
    authorization_ids: dict[str, str],
    issued_at: datetime,
    expires_at: datetime,
) -> ShapeABatchOwnerApprovalPayload:
    """The one place a payload is built. `authorization_ids` must supply
    an entry for EXACTLY the capabilities in `manifest` -- no more, no
    fewer -- or construction is refused; this is what makes the
    resulting approval commit to the exact reviewed set, never a
    superset/subset. `manifest_digest` is independently recomputed from
    `manifest` itself here, never accepted as a caller-supplied value,
    so a caller cannot forge approval for content that was never
    actually reviewed under this exact manifest."""

    if not isinstance(manifest, ShapeABatchManifest):
        raise ShapeABatchOwnerApprovalError("Expected ShapeABatchManifest.")
    if not isinstance(authorization_ids, dict) or set(authorization_ids) != set(manifest.capability_symbols):
        raise ShapeABatchOwnerApprovalError(
            "authorization_ids must supply exactly one entry for every capability in the manifest, no more, no fewer."
        )
    entries = tuple(
        ShapeABatchOwnerApprovalEntry(
            capability_symbol=capability_entry.capability_symbol,
            execution_intent_digest=capability_entry.execution_intent_digest,
            authorization_id=authorization_ids[capability_entry.capability_symbol],
        )
        for capability_entry in manifest.entries
    )
    return ShapeABatchOwnerApprovalPayload(
        schema_version=SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION,
        batch_id=batch_id,
        manifest_digest=compute_shape_a_batch_manifest_digest(manifest),
        requested_plan_digest=manifest.requested_plan_digest,
        requested_step_id=manifest.requested_step_id,
        target_capability_posture=manifest.target_capability_posture,
        target_anchor_assurance=manifest.target_anchor_assurance,
        entries=entries,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def _payload_body(payload: ShapeABatchOwnerApprovalPayload) -> dict[str, CanonicalValue]:
    return {
        "digest_purpose": _SIGNING_DOMAIN,
        "schema_version": payload.schema_version,
        "batch_id": payload.batch_id,
        "manifest_digest": payload.manifest_digest,
        "requested_plan_digest": payload.requested_plan_digest,
        "requested_step_id": payload.requested_step_id,
        "target_capability_posture": payload.target_capability_posture.value,
        "target_anchor_assurance": payload.target_anchor_assurance.value,
        "entries": [
            {
                "capability_symbol": entry.capability_symbol,
                "execution_intent_digest": entry.execution_intent_digest,
                "authorization_id": entry.authorization_id,
            }
            for entry in payload.entries
        ],
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
    }


def shape_a_batch_owner_approval_signing_payload(payload: ShapeABatchOwnerApprovalPayload) -> bytes:
    if not isinstance(payload, ShapeABatchOwnerApprovalPayload):
        raise ShapeABatchOwnerApprovalError("Expected ShapeABatchOwnerApprovalPayload.")
    return canonical_json(_payload_body(payload))


@dataclass(frozen=True)
class ShapeABatchOwnerApproval:
    schema_version: int
    batch_id: str
    manifest_digest: str
    requested_plan_digest: str
    requested_step_id: str
    target_capability_posture: CapabilityPosture
    target_anchor_assurance: AnchorAssurance
    entries: tuple[ShapeABatchOwnerApprovalEntry, ...]
    issued_at: datetime
    expires_at: datetime
    authority_id: str
    proof: bytes

    def __post_init__(self) -> None:
        ShapeABatchOwnerApprovalPayload(
            schema_version=self.schema_version,
            batch_id=self.batch_id,
            manifest_digest=self.manifest_digest,
            requested_plan_digest=self.requested_plan_digest,
            requested_step_id=self.requested_step_id,
            target_capability_posture=self.target_capability_posture,
            target_anchor_assurance=self.target_anchor_assurance,
            entries=self.entries,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not isinstance(self.authority_id, str) or not _SAFE_TOKEN.fullmatch(self.authority_id):
            raise ShapeABatchOwnerApprovalError("Batch owner approval authority_id is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise ShapeABatchOwnerApprovalError("Batch owner approval proof must be a 64-byte Ed25519 signature.")


def shape_a_batch_owner_approval_payload_of(approval: ShapeABatchOwnerApproval) -> ShapeABatchOwnerApprovalPayload:
    if not isinstance(approval, ShapeABatchOwnerApproval):
        raise ShapeABatchOwnerApprovalError("Expected ShapeABatchOwnerApproval.")
    return ShapeABatchOwnerApprovalPayload(
        schema_version=approval.schema_version,
        batch_id=approval.batch_id,
        manifest_digest=approval.manifest_digest,
        requested_plan_digest=approval.requested_plan_digest,
        requested_step_id=approval.requested_step_id,
        target_capability_posture=approval.target_capability_posture,
        target_anchor_assurance=approval.target_anchor_assurance,
        entries=approval.entries,
        issued_at=approval.issued_at,
        expires_at=approval.expires_at,
    )


def sign_shape_a_batch_owner_approval(
    payload: ShapeABatchOwnerApprovalPayload, *, authority_id: str, private_key: Ed25519PrivateKey
) -> ShapeABatchOwnerApproval:
    """Signing-side only. Uses the same authorization private key/
    authority as the individual `PlanAuthorizationV2` artifacts this
    approval binds to -- one trust root for the whole batch ceremony,
    not a new key custody question."""

    if not isinstance(payload, ShapeABatchOwnerApprovalPayload):
        raise ShapeABatchOwnerApprovalError("Expected ShapeABatchOwnerApprovalPayload.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise ShapeABatchOwnerApprovalError("authority_id is invalid.")
    proof = private_key.sign(shape_a_batch_owner_approval_signing_payload(payload))
    return ShapeABatchOwnerApproval(
        schema_version=payload.schema_version,
        batch_id=payload.batch_id,
        manifest_digest=payload.manifest_digest,
        requested_plan_digest=payload.requested_plan_digest,
        requested_step_id=payload.requested_step_id,
        target_capability_posture=payload.target_capability_posture,
        target_anchor_assurance=payload.target_anchor_assurance,
        entries=payload.entries,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        authority_id=authority_id,
        proof=proof,
    )


def verify_shape_a_batch_owner_approval_signature(
    approval: ShapeABatchOwnerApproval, authorities: PinnedAuthoritySet
) -> bool:
    """Verification-side only. Never raises for an ordinary bad
    signature -- returns `False` exactly like
    `PinnedAuthoritySet.verify_signature()` itself does."""

    if not isinstance(approval, ShapeABatchOwnerApproval):
        return False
    payload = shape_a_batch_owner_approval_payload_of(approval)
    return authorities.verify_signature(
        authority_id=approval.authority_id,
        message=shape_a_batch_owner_approval_signing_payload(payload),
        signature=approval.proof,
    )


def verify_plan_authorization_v2_batch_membership(
    authz: PlanAuthorizationV2,
    approval: ShapeABatchOwnerApproval,
    *,
    capability_symbol: str,
    authorities: PinnedAuthoritySet,
) -> bool:
    """The property the owner's review required: proves `authz` belongs
    to exactly the batch `approval` cryptographically commits to for
    `capability_symbol` -- not merely that both files happen to sit in
    the same directory. Returns `False` (never raises) unless ALL of:
    both signatures independently verify against `authorities`; `approval`
    has exactly one entry for `capability_symbol`; that entry's
    `authorization_id` equals `authz.authorization_id` (the field that is
    itself part of `authz`'s own signed payload); that entry's
    `execution_intent_digest` matches one of `authz.authorized_executions`;
    and `approval.requested_plan_digest == authz.plan_digest`. An
    authorization genuinely signed for one batch can never satisfy this
    check against a different batch's approval, because the different
    approval's own signature does not cover that authorization_id."""

    if not isinstance(authz, PlanAuthorizationV2) or not isinstance(approval, ShapeABatchOwnerApproval):
        return False
    if not verify_shape_a_batch_owner_approval_signature(approval, authorities):
        return False
    if not verify_plan_authorization_v2_signature(authz, authorities):
        return False
    matching = [entry for entry in approval.entries if entry.capability_symbol == capability_symbol]
    if len(matching) != 1:
        return False
    entry = matching[0]
    if entry.authorization_id != authz.authorization_id:
        return False
    if approval.requested_plan_digest != authz.plan_digest:
        return False
    return any(
        binding.execution_intent_digest == entry.execution_intent_digest for binding in authz.authorized_executions
    )


def shape_a_batch_owner_approval_to_bytes(approval: ShapeABatchOwnerApproval) -> bytes:
    payload = shape_a_batch_owner_approval_payload_of(approval)
    body: dict[str, CanonicalValue] = _payload_body(payload)
    body["authority_id"] = approval.authority_id
    body["proof_hex"] = approval.proof.hex()
    return canonical_json(body)


def shape_a_batch_owner_approval_from_bytes(raw: bytes) -> ShapeABatchOwnerApproval:
    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise ShapeABatchOwnerApprovalError("Batch owner approval file is not valid JSON.") from exc
    if not isinstance(body, dict):
        raise ShapeABatchOwnerApprovalError("Batch owner approval file is not a JSON object.")
    required = {
        "digest_purpose",
        "schema_version",
        "batch_id",
        "manifest_digest",
        "requested_plan_digest",
        "requested_step_id",
        "target_capability_posture",
        "target_anchor_assurance",
        "entries",
        "issued_at",
        "expires_at",
        "authority_id",
        "proof_hex",
    }
    if set(body) != required:
        raise ShapeABatchOwnerApprovalError("Batch owner approval file has an unexpected field set.")
    try:
        issued_at = datetime.fromisoformat(body["issued_at"])
        expires_at = datetime.fromisoformat(body["expires_at"])
        proof = bytes.fromhex(body["proof_hex"])
        raw_entries = body["entries"]
        if not isinstance(raw_entries, list):
            raise ValueError
        entries = tuple(
            ShapeABatchOwnerApprovalEntry(
                capability_symbol=str(entry["capability_symbol"]),
                execution_intent_digest=str(entry["execution_intent_digest"]),
                authorization_id=str(entry["authorization_id"]),
            )
            for entry in raw_entries
        )
        target_capability_posture = CapabilityPosture(body["target_capability_posture"])
        target_anchor_assurance = AnchorAssurance(body["target_anchor_assurance"])
    except (TypeError, ValueError, KeyError, ShapeABatchOwnerApprovalError) as exc:
        raise ShapeABatchOwnerApprovalError("Batch owner approval file has a malformed field.") from exc
    return ShapeABatchOwnerApproval(
        schema_version=body["schema_version"],
        batch_id=body["batch_id"],
        manifest_digest=body["manifest_digest"],
        requested_plan_digest=body["requested_plan_digest"],
        requested_step_id=body["requested_step_id"],
        target_capability_posture=target_capability_posture,
        target_anchor_assurance=target_anchor_assurance,
        entries=entries,
        issued_at=issued_at,
        expires_at=expires_at,
        authority_id=body["authority_id"],
        proof=proof,
    )


__all__ = [
    "SHAPE_A_BATCH_OWNER_APPROVAL_SCHEMA_VERSION",
    "ShapeABatchOwnerApproval",
    "ShapeABatchOwnerApprovalEntry",
    "ShapeABatchOwnerApprovalError",
    "ShapeABatchOwnerApprovalPayload",
    "build_shape_a_batch_owner_approval_payload",
    "shape_a_batch_owner_approval_from_bytes",
    "shape_a_batch_owner_approval_payload_of",
    "shape_a_batch_owner_approval_signing_payload",
    "shape_a_batch_owner_approval_to_bytes",
    "sign_shape_a_batch_owner_approval",
    "verify_plan_authorization_v2_batch_membership",
    "verify_shape_a_batch_owner_approval_signature",
]
