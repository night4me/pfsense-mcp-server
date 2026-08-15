"""Production artifact-exchange primitives (ADR-028 W3-D1, W3 Slice 2;
extended by W3 Slice 5A).

Generalizes `lab/reconciliation_authority.py`'s already-accepted
pending/signed secure-file pattern to the two artifact kinds the
first-WRITE authorization/confirmation delivery seam requires: a signed
`PlanAuthorizationV2` (authorization) and a signed `ConfirmationEvidence`
(confirmation), plus one unsigned `PendingConfirmationRequest` a human
signer reviews before returning a signed `ConfirmationEvidence` --
mirroring `lab/reconciliation_authority.py`'s `PendingReconciliation`'s
role, since a `ConfirmationEvidence.contract_id` does not exist until
`AliasDescriptionExecutionCoreV1.authorize_and_create()` creates it and
therefore cannot be pre-signed (see that module's docstring).

**W3 Slice 5A** adds one further, purely additive artifact kind,
`AuthorizationPreview`, plus three new plaintext fields on
`PendingConfirmationRequest` (schema version 2). Both close the exact gap
a prior W3 Slice 5 investigation found and stopped on
(`reports-ai/handoff/20260815T-w3-slice5-stop-missing-review-seam.md`):
neither an off-host signer's `execution_intent_digest` derivation nor the
required G5 human-readable confirmation review (alias name, previous
description, requested description) had any artifact to draw from --
`RecoveryContract` itself never stores plaintext content, only digests
and encrypted `ProtectedArtifact` ciphertext (`store.py`'s own documented
invariant). Both new artifact kinds are **non-authorizing**: they exist
solely so a signer can perform semantic review without live pfSense
network access of its own; they participate in no signature, no
`ConfirmationEvidence.verify_bindings()` check, and no
`PlanAuthorizationV2` verification path. If a preview's content and the
canonical/digest content it was generated from ever disagreed, that
would be a bug in this module -- not a condition any consumer needs to
reconcile, since a signer's own trust never rests on the preview at all,
only on independently re-deriving what it needs from the same shared,
security-owned constants and canonical functions production itself uses
(`security_plan.ALIAS_DESCRIPTION_WRITE_*`, `compute_plan_digest()`,
`compute_execution_intent_digest()`). The signing-side CLI itself
remains unimplemented -- this slice only closes the artifact-schema
gap that blocked it.

**Not yet wired into `production_runtime.py`, `execution_core`, or any
execution path.** This module is pure encode/decode/secure-file-I/O --
no directory discovery/matching logic, no store coupling, no
`AliasDescriptionExecutionCoreV1` coupling. A later, separately
authorized slice composes these primitives into the actual product
operation (ADR-028's product state model: `REQUESTED`/
`AWAITING_CONFIRMATION`/`VERIFIED`/`RECONCILIATION_REQUIRED`/`REFUSED`)
against a fixed, environment-derived inbox/outbox configuration owned by
`production_runtime.py`, per ADR-028's "Ownership and configuration".
Mirrors this codebase's own W1-before-W2 precedent: `alias_description_
execution.py` was built and fully tested as an inert, uncomposed unit
before `production_runtime.py` wired it against real dependencies.

No dataclass here changes `PlanAuthorizationV2` or `ConfirmationEvidence`
themselves -- both remain exactly as defined in `security_authorization.py`/
`confirmation.py`. Every encode function here is the reverse of that
type's own established signing-payload shape plus its `proof`; every
decode function reconstructs through the target dataclass's own
`__post_init__` validation, so structural validation is never duplicated
here -- this module only adds the file-format envelope (schema version,
key set, encoding) and the descriptor-level fail-closed checks
(`secure_file.open_nofollow`/`validate_descriptor`, reused unchanged).

Fail-closed matrix: a missing, malformed, truncated, oversized, non-JSON,
wrong-schema-version, extra/missing-key, non-regular-file, symlinked,
wrong-owner, wrong-permission, or (for the pending confirmation request)
integrity-tampered artifact always raises `ArtifactExchangeError` --
never silently treated as absent and never partially trusted. This
module makes no runtime-authorization-validity judgment (expired,
consumed, wrong authority) -- that remains
`verify_plan_authorization_v2_signature()`/`ConfirmationVerifier.verify()`/
`ConfirmationEvidence.verify_bindings()`'s responsibility, exactly as
today; a value this module successfully decodes is a structurally valid
artifact, never an authorized one.

`write_secure_new()` reimplements `lab/reconciliation_authority.py`'s own
`write_secure_new()`'s exact exclusive-creation-only discipline (refuse a
second write rather than discard the first -- ADR-028's own "Artifact
lifecycle and cleanup" requirement) rather than importing it: production
code must never import from `lab/`, a backwards layering direction this
module does not introduce (matching `production_runtime.py`'s own
documented precedent for the witness-anchor mTLS recipe).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from pfsense_mcp.security_authorization import (
    PLAN_AUTHORIZATION_V2_SCHEMA_VERSION,
    AuthorizationEvidenceFingerprint,
    PlanAuthorizationStepBinding,
    PlanAuthorizationV2,
    SecurityAuthorizationError,
)
from pfsense_mcp.security_discovery import AnchorAssurance, CapabilityPosture
from pfsense_mcp.security_plan import AuthorizationLevel

from ..secure_file import open_nofollow, validate_descriptor
from .alias_description import SEMANTIC_UNIT, AliasDescriptionChangeV1, PreparedAliasDescriptionExecutionV1
from .confirmation import ConfirmationEvidence
from .confirmation_providers import ACCEPTED_ALGORITHM as ACCEPTED_CONFIRMATION_ALGORITHM
from .contract import RecoveryContract
from .errors import ArtifactExchangeError, ConfirmationError
from .prepared_execution_intent import compute_execution_intent_digest

__all__ = [
    "AuthorizationPreview",
    "PendingConfirmationRequest",
    "authorization_preview_from_preparation",
    "authorization_preview_to_bytes",
    "confirmation_evidence_to_bytes",
    "load_authorization_preview",
    "load_pending_confirmation_request",
    "load_signed_confirmation_evidence",
    "load_signed_plan_authorization_v2",
    "pending_confirmation_request_from_contract",
    "pending_confirmation_request_to_bytes",
    "plan_authorization_v2_to_bytes",
    "write_secure_new",
]

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")

#: Matches lab/reconciliation_authority.py's own bound -- every artifact
#: kind here is a small, fixed-shape JSON document, never a bulk payload.
_MAX_FILE = 16 * 1024

#: W3 Slice 5A (ADR-028 signing-side CLI trust boundary): bumped from 1 to
#: 2 to add the plaintext G5 review fields (`alias_name`/
#: `previous_description`/`requested_description`) no artifact previously
#: carried. No live artifact of schema 1 was ever produced or consumed
#: (the signing-side CLI was never built), so this is a clean version
#: bump, not a migration.
_PENDING_CONFIRMATION_SCHEMA_VERSION = 2
_PENDING_CONFIRMATION_MAC_DOMAIN = b"tier1-pending-confirmation-request-v2\0"
_CONFIRMATION_EVIDENCE_ARTIFACT_SCHEMA_VERSION = 1
_AUTHORIZATION_PREVIEW_SCHEMA_VERSION = 1
_AUTHORIZATION_PREVIEW_MAC_DOMAIN = b"tier1-authorization-preview-v1\0"
_MAX_ALIAS_NAME_LENGTH = 32
_MAX_DESCRIPTION_LENGTH = 1024


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _read_secure(path: Path) -> bytes:
    descriptor = open_nofollow(path, on_error=ArtifactExchangeError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_MAX_FILE, on_error=ArtifactExchangeError)
        return os.read(descriptor, _MAX_FILE + 1)
    finally:
        os.close(descriptor)


def write_secure_new(path: Path, value: bytes) -> None:
    """Exclusive-creation-only write. Refuses to overwrite an existing
    file at `path` -- a second write attempt fails rather than
    discarding the first, which is itself the fail-closed behavior
    ADR-028 requires for leftover/duplicate artifacts, not an
    inconvenience to be engineered around. Any failure after the file is
    created (a short write, an interrupted write) removes the
    incomplete artifact rather than leaving a partially-written file
    that a later reader could misinterpret."""

    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError:
        raise ArtifactExchangeError(f"secure artifact output could not be created: {path}") from None
    complete = False
    try:
        offset = 0
        while offset < len(value):
            written = os.write(descriptor, value[offset:])
            if written <= 0:
                raise ArtifactExchangeError(f"secure artifact output could not be written: {path}")
            offset += written
        os.fsync(descriptor)
        complete = True
    finally:
        os.close(descriptor)
        if not complete:
            with suppress(OSError):
                path.unlink()


# --------------------------------------------------------------------------
# PlanAuthorizationV2 -- signed authorization artifact (decode; encode is
# provided for symmetry/testability and future signing-tool reuse).
# --------------------------------------------------------------------------


def plan_authorization_v2_to_bytes(authorization: PlanAuthorizationV2) -> bytes:
    """The exact file encoding a signing tool would write. Never called
    from any production consumption path today -- production only ever
    decodes an already-signed artifact; this exists so encode/decode
    round-trip symmetrically and so a future, separate signing tool
    (ADR-028's signing-side CLI trust boundary) has a precise, reviewed
    encoder to reuse rather than inventing its own file format."""

    if not isinstance(authorization, PlanAuthorizationV2):
        raise ArtifactExchangeError("Expected PlanAuthorizationV2.")
    payload = {
        "schema_version": authorization.schema_version,
        "authorization_id": authorization.authorization_id,
        "plan_digest": authorization.plan_digest,
        "authorized_executions": [
            {"step_id": binding.step_id, "execution_intent_digest": binding.execution_intent_digest}
            for binding in authorization.authorized_executions
        ],
        "authority_id": authorization.authority_id,
        "algorithm": authorization.algorithm,
        "proof": base64.b64encode(authorization.proof).decode("ascii"),
        "issued_at": authorization.issued_at.isoformat(),
        "expires_at": authorization.expires_at.isoformat(),
        "risk_class": authorization.risk_class.value,
        "evidence_fingerprint": authorization.evidence_fingerprint.to_payload(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_signed_plan_authorization_v2(path: Path) -> PlanAuthorizationV2:
    """Decode and structurally validate a signed `PlanAuthorizationV2`
    artifact discovered on disk. Never verifies the signature itself, a
    freshness/expiry/replay judgment, or a plan/step/digest binding --
    those remain `verify_plan_authorization_v2_signature()`/
    `plan_authorization_v2_authorizes_execution()`'s exclusive
    responsibility (`AliasDescriptionExecutionCoreV1.authorize_and_create()`
    already calls both, unconditionally, on every authorization it is
    given, discovered this way or otherwise)."""

    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "authorization_id",
            "plan_digest",
            "authorized_executions",
            "authority_id",
            "algorithm",
            "proof",
            "issued_at",
            "expires_at",
            "risk_class",
            "evidence_fingerprint",
        }
        if set(raw) != expected_keys or raw["schema_version"] != PLAN_AUTHORIZATION_V2_SCHEMA_VERSION:
            raise ValueError
        if not isinstance(raw["authorized_executions"], list) or not raw["authorized_executions"]:
            raise ValueError
        bindings = tuple(
            PlanAuthorizationStepBinding(
                step_id=binding["step_id"],
                execution_intent_digest=binding["execution_intent_digest"],
            )
            for binding in raw["authorized_executions"]
        )
        fingerprint_raw = raw["evidence_fingerprint"]
        if not isinstance(fingerprint_raw, dict):
            raise ValueError
        fingerprint = AuthorizationEvidenceFingerprint(
            capability_posture_value=fingerprint_raw["capability_posture_value"],
            anchor_assurance_value=fingerprint_raw["anchor_assurance_value"],
            anchor_evidence_state=fingerprint_raw["anchor_evidence_state"],
            anchor_baseline=fingerprint_raw["anchor_baseline"],
            anchor_witness_value=fingerprint_raw["anchor_witness_value"],
            anchor_provisioned_at=fingerprint_raw["anchor_provisioned_at"],
        )
        return PlanAuthorizationV2(
            schema_version=raw["schema_version"],
            authorization_id=raw["authorization_id"],
            plan_digest=raw["plan_digest"],
            authorized_executions=bindings,
            authority_id=raw["authority_id"],
            algorithm=raw["algorithm"],
            proof=base64.b64decode(raw["proof"], validate=True),
            issued_at=datetime.fromisoformat(raw["issued_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            risk_class=AuthorizationLevel(raw["risk_class"]),
            evidence_fingerprint=fingerprint,
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError, SecurityAuthorizationError):
        raise ArtifactExchangeError(f"signed PlanAuthorizationV2 artifact is malformed: {path}") from None


# --------------------------------------------------------------------------
# AuthorizationPreview -- W3 Slice 5A (ADR-028 signing-side CLI trust
# boundary): a non-authorizing, human-readable preview of exactly what a
# PlanAuthorizationV2 for the alias-description first-WRITE operation
# would authorize, so an off-host signer can perform the required G5
# semantic review without any pfSense network access of its own.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthorizationPreview:
    """Non-authorizing, human-readable preview of exactly what a
    `PlanAuthorizationV2` for the alias-description first-WRITE
    operation would authorize -- generated by production from the SAME
    fresh, authoritative preparation (`AliasDescriptionPreparerV1.prepare()`)
    the security-critical authorization path itself uses, via the same
    unmodified `compute_execution_intent_digest()`. Possessing, reading,
    or tampering with this artifact proves and authorizes nothing: the
    actual authorization decision remains exclusively
    `verify_plan_authorization_v2_signature()`/
    `plan_authorization_v2_authorizes_execution()`/
    `plan_authorization_is_fresh()`'s responsibility, entirely unchanged
    by this artifact's existence. `target_capability_posture`/
    `target_anchor_assurance`/`requested_plan_digest`/`requested_step_id`
    are shown for operator review and cross-check only -- a signer must
    still independently derive its own expectation via
    `security_plan.ALIAS_DESCRIPTION_WRITE_*` (the shared, security-owned
    constants) and the existing canonical plan-digest computation, never
    trust this preview's copy of them as authoritative."""

    operation: str
    alias_name: str
    previous_description: str
    requested_description: str
    execution_intent_digest: str
    requested_plan_digest: str
    requested_step_id: str
    target_capability_posture: CapabilityPosture
    target_anchor_assurance: AnchorAssurance
    generated_at: datetime

    def __post_init__(self) -> None:
        if self.operation != SEMANTIC_UNIT:
            raise ArtifactExchangeError("authorization preview operation identity is invalid")
        if not isinstance(self.alias_name, str) or not self.alias_name or len(self.alias_name) > _MAX_ALIAS_NAME_LENGTH:
            raise ArtifactExchangeError("authorization preview alias_name is invalid")
        for value in (self.previous_description, self.requested_description):
            if not isinstance(value, str) or len(value) > _MAX_DESCRIPTION_LENGTH:
                raise ArtifactExchangeError("authorization preview description is invalid")
        digests = (self.execution_intent_digest, self.requested_plan_digest)
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ArtifactExchangeError("authorization preview digest is invalid")
        if not isinstance(self.requested_step_id, str) or not _SAFE_TOKEN.fullmatch(self.requested_step_id):
            raise ArtifactExchangeError("authorization preview step_id is invalid")
        if not isinstance(self.target_capability_posture, CapabilityPosture):
            raise ArtifactExchangeError("authorization preview target capability posture is invalid")
        if not isinstance(self.target_anchor_assurance, AnchorAssurance):
            raise ArtifactExchangeError("authorization preview target anchor assurance is invalid")
        if not _is_utc(self.generated_at):
            raise ArtifactExchangeError("authorization preview generated_at must be a UTC datetime")


def authorization_preview_from_preparation(
    request: AliasDescriptionChangeV1,
    prepared: PreparedAliasDescriptionExecutionV1,
    *,
    requested_plan_digest: str,
    requested_step_id: str,
    target_capability_posture: CapabilityPosture,
    target_anchor_assurance: AnchorAssurance,
    generated_at: datetime,
) -> AuthorizationPreview:
    """The one place an `AuthorizationPreview`'s fields are read from the
    same fresh, authoritative preparation production's own
    security-critical path uses. `execution_intent_digest` is always
    computed here, via the existing, unmodified
    `compute_execution_intent_digest()` -- never accepted as a
    parameter, so a caller cannot substitute a digest that does not
    correspond to `prepared.intent`, and cannot reuse a digest computed
    for a different alias/description pair."""

    if not isinstance(request, AliasDescriptionChangeV1) or not isinstance(
        prepared, PreparedAliasDescriptionExecutionV1
    ):
        raise ArtifactExchangeError("Expected AliasDescriptionChangeV1 and PreparedAliasDescriptionExecutionV1.")
    return AuthorizationPreview(
        operation=SEMANTIC_UNIT,
        alias_name=request.alias_name,
        previous_description=prepared.authoritative_a.descr,
        requested_description=request.description,
        execution_intent_digest=compute_execution_intent_digest(prepared.intent),
        requested_plan_digest=requested_plan_digest,
        requested_step_id=requested_step_id,
        target_capability_posture=CapabilityPosture(target_capability_posture),
        target_anchor_assurance=AnchorAssurance(target_anchor_assurance),
        generated_at=generated_at,
    )


def _authorization_preview_payload(preview: AuthorizationPreview) -> dict[str, object]:
    return {
        "schema_version": _AUTHORIZATION_PREVIEW_SCHEMA_VERSION,
        "operation": preview.operation,
        "alias_name": preview.alias_name,
        "previous_description": preview.previous_description,
        "requested_description": preview.requested_description,
        "execution_intent_digest": preview.execution_intent_digest,
        "requested_plan_digest": preview.requested_plan_digest,
        "requested_step_id": preview.requested_step_id,
        "target_capability_posture": preview.target_capability_posture.value,
        "target_anchor_assurance": preview.target_anchor_assurance.value,
        "generated_at": preview.generated_at.isoformat(),
    }


def _authorization_preview_mac(preview: AuthorizationPreview, integrity_key: bytes) -> str:
    if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
        raise ArtifactExchangeError("authorization preview integrity key is invalid")
    canonical = json.dumps(_authorization_preview_payload(preview), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(integrity_key, _AUTHORIZATION_PREVIEW_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()


def authorization_preview_to_bytes(preview: AuthorizationPreview, *, integrity_key: bytes) -> bytes:
    if not isinstance(preview, AuthorizationPreview):
        raise ArtifactExchangeError("Expected AuthorizationPreview.")
    payload = _authorization_preview_payload(preview)
    payload["integrity_mac"] = _authorization_preview_mac(preview, integrity_key)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_authorization_preview(path: Path, *, integrity_key: bytes) -> AuthorizationPreview:
    """Decode and integrity-verify an authorization preview written by
    `authorization_preview_to_bytes()`. Grants no authority by itself --
    a value this function successfully decodes is a structurally valid,
    untampered PREVIEW, never an authorization; the real authorization
    decision remains exclusively the pinned `PlanAuthorizationV2`
    signature verifier's responsibility, entirely independent of this
    function's existence."""

    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "operation",
            "alias_name",
            "previous_description",
            "requested_description",
            "execution_intent_digest",
            "requested_plan_digest",
            "requested_step_id",
            "target_capability_posture",
            "target_anchor_assurance",
            "generated_at",
            "integrity_mac",
        }
        if set(raw) != expected_keys or raw["schema_version"] != _AUTHORIZATION_PREVIEW_SCHEMA_VERSION:
            raise ValueError
        generated_at = datetime.fromisoformat(raw["generated_at"])
        if not _is_utc(generated_at):
            raise ValueError
        preview = AuthorizationPreview(
            operation=raw["operation"],
            alias_name=raw["alias_name"],
            previous_description=raw["previous_description"],
            requested_description=raw["requested_description"],
            execution_intent_digest=raw["execution_intent_digest"],
            requested_plan_digest=raw["requested_plan_digest"],
            requested_step_id=raw["requested_step_id"],
            target_capability_posture=CapabilityPosture(raw["target_capability_posture"]),
            target_anchor_assurance=AnchorAssurance(raw["target_anchor_assurance"]),
            generated_at=generated_at,
        )
        mac = raw["integrity_mac"]
        if not isinstance(mac, str):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError, ArtifactExchangeError):
        raise ArtifactExchangeError(f"authorization preview is malformed: {path}") from None

    if not hmac.compare_digest(mac, _authorization_preview_mac(preview, integrity_key)):
        raise ArtifactExchangeError(f"authorization preview failed integrity verification: {path}")
    return preview


# --------------------------------------------------------------------------
# ConfirmationEvidence -- pending (unsigned) request emission, plus
# signed-evidence decode.
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class PendingConfirmationRequest:
    """An unsigned, integrity-protected description of exactly the facts
    a human signer must review before returning a signed
    `ConfirmationEvidence` -- never itself an authorization or a bearer
    of any authority; possessing or tampering with one proves nothing
    and authorizes nothing. Mirrors `lab/reconciliation_authority.py`'s
    `PendingReconciliation`'s role for the confirmation artifact kind.

    W3 Slice 5A (ADR-028 signing-side CLI trust boundary, schema version
    2): `alias_name`/`previous_description`/`requested_description` are
    the plaintext G5 review fields no earlier schema carried -- the only
    human-readable content anywhere in the confirmation artifact chain,
    since `RecoveryContract` itself never stores plaintext (only digests
    and encrypted `ProtectedArtifact` content, per `store.py`'s own
    documented invariant). These fields are for review only: they never
    participate in `ConfirmationEvidence`'s own signed payload or
    `verify_bindings()`'s contract-correspondence check, and disagreement
    between this preview and the authoritative contract is never
    possible to smuggle past verification -- the digest fields below
    remain the sole binding target."""

    operation: str
    contract_id: str
    operation_id: str
    alias_name: str
    previous_description: str
    requested_description: str
    target_identity_digest: str
    target_fingerprint: str
    intent_digest: str
    expires_at: datetime
    expected_authority_id: str
    expected_algorithm: str

    def __post_init__(self) -> None:
        if self.operation != SEMANTIC_UNIT:
            raise ArtifactExchangeError("pending confirmation request operation identity is invalid")
        tokens = (self.contract_id, self.operation_id, self.expected_authority_id, self.expected_algorithm)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise ArtifactExchangeError("pending confirmation request identity is invalid")
        if not isinstance(self.alias_name, str) or not self.alias_name or len(self.alias_name) > _MAX_ALIAS_NAME_LENGTH:
            raise ArtifactExchangeError("pending confirmation request alias_name is invalid")
        for value in (self.previous_description, self.requested_description):
            if not isinstance(value, str) or len(value) > _MAX_DESCRIPTION_LENGTH:
                raise ArtifactExchangeError("pending confirmation request description is invalid")
        digests = (self.target_identity_digest, self.target_fingerprint, self.intent_digest)
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ArtifactExchangeError("pending confirmation request digest is invalid")
        if not _is_utc(self.expires_at):
            raise ArtifactExchangeError("pending confirmation request expiry must be a UTC datetime")


def pending_confirmation_request_from_contract(
    contract: RecoveryContract,
    *,
    alias_name: str,
    previous_description: str,
    requested_description: str,
    expected_authority_id: str,
    expected_algorithm: str = ACCEPTED_CONFIRMATION_ALGORITHM,
) -> PendingConfirmationRequest:
    """The one place a `PendingConfirmationRequest`'s binding facts are
    read from an authoritative `RecoveryContract` -- never re-derived a
    second, possibly-inconsistent way elsewhere in this module. The
    semantic review fields (`alias_name`/`previous_description`/
    `requested_description`) are supplied by the caller from the SAME
    fresh, authoritative preparation that created `contract` in the
    first place (`production_runtime.py`'s own
    `request_alias_description_change()`) -- this function does not,
    and cannot, independently re-derive them; it only assembles what it
    is given, exactly like every other field here."""

    return PendingConfirmationRequest(
        operation=SEMANTIC_UNIT,
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        alias_name=alias_name,
        previous_description=previous_description,
        requested_description=requested_description,
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        expected_authority_id=expected_authority_id,
        expected_algorithm=expected_algorithm,
    )


def _pending_confirmation_payload(pending: PendingConfirmationRequest) -> dict[str, object]:
    return {
        "schema_version": _PENDING_CONFIRMATION_SCHEMA_VERSION,
        "operation": pending.operation,
        "contract_id": pending.contract_id,
        "operation_id": pending.operation_id,
        "alias_name": pending.alias_name,
        "previous_description": pending.previous_description,
        "requested_description": pending.requested_description,
        "target_identity_digest": pending.target_identity_digest,
        "target_fingerprint": pending.target_fingerprint,
        "intent_digest": pending.intent_digest,
        "expires_at": pending.expires_at.isoformat(),
        "expected_authority_id": pending.expected_authority_id,
        "expected_algorithm": pending.expected_algorithm,
    }


def _pending_confirmation_mac(pending: PendingConfirmationRequest, integrity_key: bytes) -> str:
    if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
        raise ArtifactExchangeError("pending confirmation request integrity key is invalid")
    canonical = json.dumps(_pending_confirmation_payload(pending), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(integrity_key, _PENDING_CONFIRMATION_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()


def pending_confirmation_request_to_bytes(pending: PendingConfirmationRequest, *, integrity_key: bytes) -> bytes:
    if not isinstance(pending, PendingConfirmationRequest):
        raise ArtifactExchangeError("Expected PendingConfirmationRequest.")
    payload = _pending_confirmation_payload(pending)
    payload["integrity_mac"] = _pending_confirmation_mac(pending, integrity_key)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_pending_confirmation_request(path: Path, *, integrity_key: bytes) -> PendingConfirmationRequest:
    """Decode and integrity-verify a pending confirmation request written
    by `pending_confirmation_request_to_bytes()`. The MAC (over the same
    integrity key convention `key_lifecycle.py`'s other integrity-keyed
    stores already use) is defense in depth against local tampering
    between emission and human review -- it is never itself a substitute
    for the signed `ConfirmationEvidence`'s own authority verification."""

    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "operation",
            "contract_id",
            "operation_id",
            "alias_name",
            "previous_description",
            "requested_description",
            "target_identity_digest",
            "target_fingerprint",
            "intent_digest",
            "expires_at",
            "expected_authority_id",
            "expected_algorithm",
            "integrity_mac",
        }
        if set(raw) != expected_keys or raw["schema_version"] != _PENDING_CONFIRMATION_SCHEMA_VERSION:
            raise ValueError
        expires_at = datetime.fromisoformat(raw["expires_at"])
        if not _is_utc(expires_at):
            raise ValueError
        pending = PendingConfirmationRequest(
            operation=raw["operation"],
            contract_id=raw["contract_id"],
            operation_id=raw["operation_id"],
            alias_name=raw["alias_name"],
            previous_description=raw["previous_description"],
            requested_description=raw["requested_description"],
            target_identity_digest=raw["target_identity_digest"],
            target_fingerprint=raw["target_fingerprint"],
            intent_digest=raw["intent_digest"],
            expires_at=expires_at,
            expected_authority_id=raw["expected_authority_id"],
            expected_algorithm=raw["expected_algorithm"],
        )
        mac = raw["integrity_mac"]
        if not isinstance(mac, str):
            raise ValueError
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError, ArtifactExchangeError):
        raise ArtifactExchangeError(f"pending confirmation request is malformed: {path}") from None

    if not hmac.compare_digest(mac, _pending_confirmation_mac(pending, integrity_key)):
        raise ArtifactExchangeError(f"pending confirmation request failed integrity verification: {path}")
    return pending


def confirmation_evidence_to_bytes(evidence: ConfirmationEvidence) -> bytes:
    """The exact file encoding a signing tool would write back into the
    confirmation inbox. Never called from any production consumption
    path today; exists for encode/decode symmetry and future signing-CLI
    reuse, exactly like `plan_authorization_v2_to_bytes()`."""

    if not isinstance(evidence, ConfirmationEvidence):
        raise ArtifactExchangeError("Expected ConfirmationEvidence.")
    payload = {
        "schema_version": _CONFIRMATION_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
        "authority_id": evidence.authority_id,
        "algorithm": evidence.algorithm,
        "nonce": evidence.nonce,
        "contract_id": evidence.contract_id,
        "operation_id": evidence.operation_id,
        "target_identity_digest": evidence.target_identity_digest,
        "target_fingerprint": evidence.target_fingerprint,
        "intent_digest": evidence.intent_digest,
        "issued_at": evidence.issued_at.isoformat(),
        "expires_at": evidence.expires_at.isoformat(),
        "proof": base64.b64encode(evidence.proof).decode("ascii"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_signed_confirmation_evidence(path: Path) -> ConfirmationEvidence:
    """Decode and structurally validate a signed `ConfirmationEvidence`
    artifact discovered on disk. Never verifies the signature or the
    exact-contract binding -- those remain `ConfirmationVerifier.verify()`/
    `ConfirmationEvidence.verify_bindings()`'s exclusive responsibility,
    exactly as today; a value this module successfully decodes is a
    structurally valid artifact, never an authenticated one."""

    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "authority_id",
            "algorithm",
            "nonce",
            "contract_id",
            "operation_id",
            "target_identity_digest",
            "target_fingerprint",
            "intent_digest",
            "issued_at",
            "expires_at",
            "proof",
        }
        if set(raw) != expected_keys or raw["schema_version"] != _CONFIRMATION_EVIDENCE_ARTIFACT_SCHEMA_VERSION:
            raise ValueError
        return ConfirmationEvidence(
            authority_id=raw["authority_id"],
            algorithm=raw["algorithm"],
            nonce=raw["nonce"],
            contract_id=raw["contract_id"],
            operation_id=raw["operation_id"],
            target_identity_digest=raw["target_identity_digest"],
            target_fingerprint=raw["target_fingerprint"],
            intent_digest=raw["intent_digest"],
            issued_at=datetime.fromisoformat(raw["issued_at"]),
            expires_at=datetime.fromisoformat(raw["expires_at"]),
            proof=base64.b64decode(raw["proof"], validate=True),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError, UnicodeDecodeError, ConfirmationError):
        raise ArtifactExchangeError(f"signed ConfirmationEvidence artifact is malformed: {path}") from None
