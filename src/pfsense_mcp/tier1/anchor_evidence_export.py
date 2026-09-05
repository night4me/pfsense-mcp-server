"""AnchorEvidenceExport -- a narrow, Ed25519-signed, independently
verifiable representation of exactly the anchor-store-derived evidence
`security_plan_digest.py`'s canonical `PlanDigest` actually consumes.

## Why this exists

`discover_anchor_assurance()` (`security_discovery.py`) derives
`AnchorAssuranceDiscovery.{baseline, provisioned_at, handle}` from
`read_only_anchor_provisioning_status()` -- itself reading only the
`anchor_state` table's two authenticated rows out of the full
`RecoveryContract` SQLite store. An off-runtime verifier (an isolated
signer) that needs to independently re-derive `compute_plan_digest()`
has, until now, only had one option: hold a copy of that same store
file plus its integrity key. That is broader than the evidence
actually requires (the store also holds contract/consumption state and
is a *mutable, periodically-diverging* copy -- see the 2026-09-05
Batch-1 Round-1 stale-digest incident this module's introduction
directly responds to) and gives the verifier the same symmetric key
that authenticates the real store, which would let it forge future
copies too, not just verify one.

This module carries only: `schema_version`, `store_id`, `handle`,
`baseline`, `provisioned_at`, `issued_at`, `expires_at` -- the exact set
`ADR-021/022 amendment (2026-09-05)` names as sufficient, no more. It is
signed with a **dedicated** Ed25519 keypair, distinct from the
authorization/confirmation/reconciliation authorities and from the
store's own HMAC integrity key -- an asymmetric signature means the
verifier (signer) holds only a public key, never anything that lets it
forge a future export, unlike handing over a symmetric HMAC key would.

**No private key is provisioned by this module or anywhere in this
change.** `sign_anchor_evidence_export()` exists so the mechanism is
implementable and testable with synthetic, ephemeral keys (exactly like
every other signing primitive in this codebase's own test suite); the
real key's placement is a separate, explicit owner decision (see
`docs/tier1/specs/anchor_evidence_export_trust_boundary.md`).

Mirrors `security_authorization.py`'s `PlanAuthorizationV2` shape and
`tier1/ed25519_authority.py`'s `PinnedAuthority`/`PinnedAuthoritySet`
verification mechanics deliberately -- reused, not reinvented.
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

#: Bumped whenever a field is added, removed, or reinterpreted -- an
#: export signed under a prior schema can never silently verify under a
#: new one, because the version is itself part of the signed payload.
ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION = 1

#: Domain-separation literal included in the signed payload -- the same
#: role `security_authorization.py`'s own `"digest_purpose"` field
#: plays for `PlanAuthorizationV2` -- so a signature over this shape can
#: never be replayed as, or confused with, a signature over any other
#: signed artifact this codebase produces.
_SIGNING_DOMAIN = "pfsense-mcp-anchor-evidence-export-v1"

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HANDLE_PATTERN = re.compile(r"0x[0-9a-fA-F]{8}")
_ED25519_SIGNATURE_BYTES = 64


class AnchorEvidenceExportError(Tier1Error):
    """Refused: malformed, unsigned, untrusted, expired, future-dated,
    or otherwise invalid `AnchorEvidenceExport`/payload. Never raised by
    a successful verification -- callers get `False` from
    `verify_anchor_evidence_export_signature()` for a bad signature
    specifically, matching `PinnedAuthoritySet.verify_signature()`'s own
    "no detail beyond True/False" discipline; this exception is for
    structurally invalid data, not "signature didn't match"."""


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


@dataclass(frozen=True)
class AnchorEvidenceExportPayload:
    """Every signed field except `proof`. Validated eagerly -- an
    invalid payload can never be constructed, let alone signed."""

    schema_version: int
    store_id: str
    handle: str
    baseline: int
    provisioned_at: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION:
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload schema_version is unsupported.")
        if not isinstance(self.store_id, str) or not _SAFE_TOKEN.fullmatch(self.store_id):
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload store_id is invalid.")
        if not isinstance(self.handle, str) or not _HANDLE_PATTERN.fullmatch(self.handle):
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload handle is invalid.")
        if type(self.baseline) is not int or isinstance(self.baseline, bool) or self.baseline < 0:
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload baseline must be a non-negative integer.")
        if not isinstance(self.provisioned_at, str) or not self.provisioned_at:
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload provisioned_at is invalid.")
        if not isinstance(self.issued_at, datetime) or not isinstance(self.expires_at, datetime):
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload timestamps must be UTC datetimes.")
        if not _is_utc(self.issued_at) or not _is_utc(self.expires_at) or self.expires_at <= self.issued_at:
            raise AnchorEvidenceExportError("AnchorEvidenceExport payload validity window is invalid.")


def build_anchor_evidence_export_payload(
    *,
    store_id: str,
    handle: str,
    baseline: int,
    provisioned_at: str,
    issued_at: datetime,
    expires_at: datetime,
) -> AnchorEvidenceExportPayload:
    """The one place a payload is built from already-observed evidence.
    Callers pass the exact fields `AnchorProvisioningStatus`/
    `read_only_anchor_provisioning_status()` already produced -- this
    function never itself reads a store, a witness, or anything else;
    it is pure data assembly plus the validation `__post_init__`
    already enforces."""

    return AnchorEvidenceExportPayload(
        schema_version=ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION,
        store_id=store_id,
        handle=handle,
        baseline=baseline,
        provisioned_at=provisioned_at,
        issued_at=issued_at,
        expires_at=expires_at,
    )


def anchor_evidence_export_signing_payload(payload: AnchorEvidenceExportPayload) -> bytes:
    """Canonical signing bytes -- key-sorted, whitespace-free, Unicode-
    normalized JSON via `tier1.canonical.canonical_json()`, the same
    primitive every other signed artifact in this codebase uses."""

    if not isinstance(payload, AnchorEvidenceExportPayload):
        raise AnchorEvidenceExportError("Expected AnchorEvidenceExportPayload.")
    body: dict[str, CanonicalValue] = {
        "digest_purpose": _SIGNING_DOMAIN,
        "schema_version": payload.schema_version,
        "store_id": payload.store_id,
        "handle": payload.handle,
        "baseline": payload.baseline,
        "provisioned_at": payload.provisioned_at,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
    }
    return canonical_json(body)


@dataclass(frozen=True)
class AnchorEvidenceExport:
    """Signed export -- the one artifact type a signer-side verifier
    ever loads. Carries its own `authority_id` so a verifier holding
    more than one pinned posture-evidence authority (e.g. during key
    rotation) knows which public key to check against, exactly like
    `PlanAuthorizationV2.authority_id` already does."""

    schema_version: int
    store_id: str
    handle: str
    baseline: int
    provisioned_at: str
    issued_at: datetime
    expires_at: datetime
    authority_id: str
    proof: bytes

    def __post_init__(self) -> None:
        # Re-validates via the same payload shape -- constructing an
        # AnchorEvidenceExport with an invalid field is impossible,
        # exactly like PlanAuthorizationV2's own discipline.
        AnchorEvidenceExportPayload(
            schema_version=self.schema_version,
            store_id=self.store_id,
            handle=self.handle,
            baseline=self.baseline,
            provisioned_at=self.provisioned_at,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
        )
        if not isinstance(self.authority_id, str) or not _SAFE_TOKEN.fullmatch(self.authority_id):
            raise AnchorEvidenceExportError("AnchorEvidenceExport authority_id is invalid.")
        if not isinstance(self.proof, bytes) or len(self.proof) != _ED25519_SIGNATURE_BYTES:
            raise AnchorEvidenceExportError("AnchorEvidenceExport proof must be a 64-byte Ed25519 signature.")


def anchor_evidence_export_payload_of(export: AnchorEvidenceExport) -> AnchorEvidenceExportPayload:
    """Reconstruct the exact signed payload from the artifact itself --
    the same pattern `plan_authorization_v2_payload_of()` uses."""

    if not isinstance(export, AnchorEvidenceExport):
        raise AnchorEvidenceExportError("Expected AnchorEvidenceExport.")
    return AnchorEvidenceExportPayload(
        schema_version=export.schema_version,
        store_id=export.store_id,
        handle=export.handle,
        baseline=export.baseline,
        provisioned_at=export.provisioned_at,
        issued_at=export.issued_at,
        expires_at=export.expires_at,
    )


def sign_anchor_evidence_export(
    payload: AnchorEvidenceExportPayload, *, authority_id: str, private_key: Ed25519PrivateKey
) -> AnchorEvidenceExport:
    """Signing-side only -- runs wherever the real posture-evidence
    private key lives (an explicit, separate owner decision; see this
    module's own docstring). Never called with a real key by anything
    in this change; used only by tests, with synthetic, ephemeral keys."""

    if not isinstance(payload, AnchorEvidenceExportPayload):
        raise AnchorEvidenceExportError("Expected AnchorEvidenceExportPayload.")
    if not isinstance(authority_id, str) or not _SAFE_TOKEN.fullmatch(authority_id):
        raise AnchorEvidenceExportError("authority_id is invalid.")
    proof = private_key.sign(anchor_evidence_export_signing_payload(payload))
    return AnchorEvidenceExport(
        schema_version=payload.schema_version,
        store_id=payload.store_id,
        handle=payload.handle,
        baseline=payload.baseline,
        provisioned_at=payload.provisioned_at,
        issued_at=payload.issued_at,
        expires_at=payload.expires_at,
        authority_id=authority_id,
        proof=proof,
    )


def verify_anchor_evidence_export_signature(export: AnchorEvidenceExport, authorities: PinnedAuthoritySet) -> bool:
    """Verification-side only -- the one function the signer's own
    discovery path calls. Never raises for an ordinary bad signature;
    returns `False` exactly like `PinnedAuthoritySet.verify_signature()`
    itself does for an unknown/inactive authority or a malformed proof."""

    if not isinstance(export, AnchorEvidenceExport):
        return False
    payload = anchor_evidence_export_payload_of(export)
    return authorities.verify_signature(
        authority_id=export.authority_id,
        message=anchor_evidence_export_signing_payload(payload),
        signature=export.proof,
    )


def anchor_evidence_export_to_bytes(export: AnchorEvidenceExport) -> bytes:
    """Self-authenticating serialization -- no additional HMAC/integrity
    wrapping is needed (unlike the Shape-A artifact-exchange types),
    because the Ed25519 signature already makes tampering detectable.
    Plain, explicit JSON; never `repr()`/`pickle`/anything ambiguous."""

    payload = anchor_evidence_export_payload_of(export)
    body: dict[str, CanonicalValue] = {
        "schema_version": payload.schema_version,
        "store_id": payload.store_id,
        "handle": payload.handle,
        "baseline": payload.baseline,
        "provisioned_at": payload.provisioned_at,
        "issued_at": payload.issued_at.isoformat(),
        "expires_at": payload.expires_at.isoformat(),
        "authority_id": export.authority_id,
        "proof_hex": export.proof.hex(),
    }
    return canonical_json(body)


def anchor_evidence_export_from_bytes(raw: bytes) -> AnchorEvidenceExport:
    """Parses untrusted bytes into an `AnchorEvidenceExport`. Never
    trusts the parsed content beyond what `AnchorEvidenceExport.
    __post_init__` already validates -- a malformed, truncated, or
    wrong-shaped file fails closed with `AnchorEvidenceExportError`,
    never a partially-populated object. Signature validity is NOT
    checked here -- that is the caller's job via
    `verify_anchor_evidence_export_signature()`, kept as an explicit,
    separate step so "parses" and "is trustworthy" can never be
    conflated."""

    try:
        body = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise AnchorEvidenceExportError("AnchorEvidenceExport file is not valid JSON.") from exc
    if not isinstance(body, dict):
        raise AnchorEvidenceExportError("AnchorEvidenceExport file is not a JSON object.")
    required = {
        "schema_version",
        "store_id",
        "handle",
        "baseline",
        "provisioned_at",
        "issued_at",
        "expires_at",
        "authority_id",
        "proof_hex",
    }
    if set(body) != required:
        raise AnchorEvidenceExportError("AnchorEvidenceExport file has an unexpected field set.")
    try:
        issued_at = datetime.fromisoformat(body["issued_at"])
        expires_at = datetime.fromisoformat(body["expires_at"])
        proof = bytes.fromhex(body["proof_hex"])
    except (TypeError, ValueError) as exc:
        raise AnchorEvidenceExportError("AnchorEvidenceExport file has a malformed field.") from exc
    return AnchorEvidenceExport(
        schema_version=body["schema_version"],
        store_id=body["store_id"],
        handle=body["handle"],
        baseline=body["baseline"],
        provisioned_at=body["provisioned_at"],
        issued_at=issued_at,
        expires_at=expires_at,
        authority_id=body["authority_id"],
        proof=proof,
    )


__all__ = [
    "ANCHOR_EVIDENCE_EXPORT_SCHEMA_VERSION",
    "AnchorEvidenceExport",
    "AnchorEvidenceExportError",
    "AnchorEvidenceExportPayload",
    "anchor_evidence_export_from_bytes",
    "anchor_evidence_export_payload_of",
    "anchor_evidence_export_signing_payload",
    "anchor_evidence_export_to_bytes",
    "build_anchor_evidence_export_payload",
    "sign_anchor_evidence_export",
    "verify_anchor_evidence_export_signature",
]
