"""ADR-037 Shape-A generalized artifact exchange.

A NEW, separate module -- `artifact_exchange.py` (the alias capability's
own `AuthorizationPreview`/`PendingConfirmationRequest` schema) is
completely unmodified by this file. That module's dataclasses hardcode
alias-specific semantics (`operation` pinned to `SEMANTIC_UNIT`, fields
named `alias_name`/`previous_description`/`requested_description`,
`__post_init__` type-checks against `AliasDescriptionChangeV1`/
`PreparedAliasDescriptionExecutionV1`) -- reusing it for five differently
shaped capabilities (an NTP server toggle, six NTP observability booleans,
log display preferences, log retention settings, a timezone string) is not
possible without either weakening its validation or duplicating its
cryptographic/MAC logic under alias-specific names five more times. Neither
is acceptable, so this module generalizes the SAME security discipline
(HMAC-integrity-protected JSON envelope, O_NOFOLLOW-validated read,
exclusive-create-only write, schema-version pinning, bounded field sizes)
over `shape_a_registry.SHAPE_A_REGISTRATIONS`'s finite, statically reviewed
capability set instead of one hardcoded operation name.

Cross-capability/cross-consumption prevention: every artifact carries its
own `capability_symbol`, validated in `__post_init__` against
`shape_a_registry.is_registered_capability()` -- an artifact naming an
unregistered or wrong capability symbol simply cannot be constructed, by
construction, not by a caller-side check that could be skipped.

Semantic review fields (what a human signer reads before approving) are
derived generically, via `_render_semantic_fields()` below, from the
request's own Pydantic `model_dump()` and the prepared execution's
`authoritative_a` dataclass fields -- there is no per-capability review
renderer to keep in sync as new Shape-A capabilities are added; the same
function already works for all five today and for any future
capability whose request/prepared types follow the same established shape
(a frozen Pydantic `BaseModel` request, a `@dataclass` prepared type with
an `authoritative_a` field).

Mirrors `artifact_exchange.py`'s exact security properties; does not
duplicate its cryptographic/MAC *decision* logic (HMAC-SHA256 over a
canonical JSON payload with a domain-separation prefix) -- it reimplements
the same well-understood primitive generically, exactly as
`artifact_exchange.py` itself reimplements (rather than imports)
`lab/reconciliation_authority.py`'s own `write_secure_new()` for the
identical layering reason documented there.
"""

from __future__ import annotations

import contextlib
import dataclasses
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel

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
from .confirmation import ConfirmationEvidence
from .confirmation_providers import ACCEPTED_ALGORITHM as ACCEPTED_CONFIRMATION_ALGORITHM
from .contract import RecoveryContract
from .errors import ArtifactExchangeError, ConfirmationError
from .prepared_execution_intent import compute_execution_intent_digest
from .shape_a_registry import is_registered_capability

__all__ = [
    "ShapeAAuthorizationPreview",
    "ShapeAPendingConfirmationRequest",
    "confirmation_evidence_to_bytes",
    "load_shape_a_authorization_preview",
    "load_shape_a_pending_confirmation_request",
    "load_signed_confirmation_evidence",
    "load_signed_plan_authorization_v2",
    "pending_confirmation_request_from_contract",
    "plan_authorization_v2_to_bytes",
    "preview_from_preparation",
    "shape_a_authorization_preview_to_bytes",
    "shape_a_pending_confirmation_request_to_bytes",
    "write_secure_new",
]

import os as _os

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")

_MAX_FILE = 16 * 1024
_MAX_SEMANTIC_FIELDS = 16
_MAX_SEMANTIC_LABEL_LENGTH = 64
_MAX_SEMANTIC_VALUE_LENGTH = 256

_SHAPE_A_PREVIEW_SCHEMA_VERSION = 1
_SHAPE_A_PREVIEW_MAC_DOMAIN = b"tier1-shape-a-authorization-preview-v1\0"
_SHAPE_A_PENDING_SCHEMA_VERSION = 1
_SHAPE_A_PENDING_MAC_DOMAIN = b"tier1-shape-a-pending-confirmation-request-v1\0"
_CONFIRMATION_EVIDENCE_ARTIFACT_SCHEMA_VERSION = 1


def _is_utc(value: datetime) -> bool:
    return (
        isinstance(value, datetime) and value.tzinfo is not None and value.utcoffset() == timezone.utc.utcoffset(value)
    )


def _read_secure(path: Path) -> bytes:
    descriptor = open_nofollow(path, on_error=ArtifactExchangeError)
    try:
        validate_descriptor(path, descriptor, max_bytes=_MAX_FILE, on_error=ArtifactExchangeError)
        return _os.read(descriptor, _MAX_FILE + 1)
    finally:
        _os.close(descriptor)


def write_secure_new(path: Path, value: bytes) -> None:
    """Byte-identical discipline to `artifact_exchange.write_secure_new()`
    -- exclusive creation only, incomplete writes are removed, never
    imported from there (this module must not depend on the alias-specific
    module, the same layering direction `artifact_exchange.py` itself
    avoids relative to `lab/`)."""

    flags = _os.O_WRONLY | _os.O_CREAT | _os.O_EXCL | getattr(_os, "O_NOFOLLOW", 0)
    try:
        descriptor = _os.open(path, flags, 0o600)
    except OSError:
        raise ArtifactExchangeError(f"secure artifact output could not be created: {path}") from None
    complete = False
    try:
        offset = 0
        while offset < len(value):
            written = _os.write(descriptor, value[offset:])
            if written <= 0:
                raise ArtifactExchangeError(f"secure artifact output could not be written: {path}")
            offset += written
        _os.fsync(descriptor)
        complete = True
    finally:
        _os.close(descriptor)
        if not complete:
            with contextlib.suppress(OSError):
                path.unlink()


def _render_semantic_fields(request: object, prepared: object) -> tuple[tuple[str, str], ...]:
    """Generic, capability-agnostic G5 review rendering. `request` must be
    a Pydantic `BaseModel` (every Shape-A request type is); `prepared`'s
    `authoritative_a` attribute, if present, must be a `@dataclass`
    instance -- every Shape-A prepared type's `authoritative_a` already
    is one. Never executes anything from either object beyond attribute
    access -- no `__str__`/`__repr__` override is trusted for anything
    beyond producing display text, and every rendered value is truncated
    to a fixed bound before being embedded in an artifact."""

    fields: list[tuple[str, str]] = []
    if isinstance(request, BaseModel):
        for name, value in sorted(request.model_dump().items()):
            fields.append((f"requested.{name}", str(value)[:_MAX_SEMANTIC_VALUE_LENGTH]))
    authoritative_a = getattr(prepared, "authoritative_a", None)
    if dataclasses.is_dataclass(authoritative_a) and not isinstance(authoritative_a, type):
        for field in dataclasses.fields(authoritative_a):
            value = getattr(authoritative_a, field.name, None)
            fields.append((f"previous.{field.name}", str(value)[:_MAX_SEMANTIC_VALUE_LENGTH]))
    bounded = tuple((label[:_MAX_SEMANTIC_LABEL_LENGTH], value) for label, value in fields[:_MAX_SEMANTIC_FIELDS])
    return bounded


def _validate_semantic_fields(fields: tuple[tuple[str, str], ...]) -> None:
    if not isinstance(fields, tuple) or len(fields) > _MAX_SEMANTIC_FIELDS:
        raise ArtifactExchangeError("semantic review fields are invalid")
    for entry in fields:
        if (
            not isinstance(entry, tuple)
            or len(entry) != 2
            or not isinstance(entry[0], str)
            or not isinstance(entry[1], str)
            or not entry[0]
            or len(entry[0]) > _MAX_SEMANTIC_LABEL_LENGTH
            or len(entry[1]) > _MAX_SEMANTIC_VALUE_LENGTH
        ):
            raise ArtifactExchangeError("semantic review field entry is invalid")


# --------------------------------------------------------------------------
# ShapeAAuthorizationPreview
# --------------------------------------------------------------------------


class ShapeAAuthorizationPreview:
    """Non-authorizing, human-readable preview of exactly what a
    `PlanAuthorizationV2` for `capability_symbol` would authorize -- the
    generalized counterpart to `artifact_exchange.AuthorizationPreview`.
    Possessing, reading, or tampering with this artifact proves and
    authorizes nothing: the actual authorization decision remains
    exclusively `verify_plan_authorization_v2_signature()`/
    `plan_authorization_v2_authorizes_execution()`'s responsibility,
    entirely unchanged by this artifact's existence."""

    __slots__ = (
        "capability_symbol",
        "execution_intent_digest",
        "generated_at",
        "requested_plan_digest",
        "requested_step_id",
        "semantic_fields",
        "target_anchor_assurance",
        "target_capability_posture",
    )

    def __init__(
        self,
        *,
        capability_symbol: str,
        semantic_fields: tuple[tuple[str, str], ...],
        execution_intent_digest: str,
        requested_plan_digest: str,
        requested_step_id: str,
        target_capability_posture: CapabilityPosture,
        target_anchor_assurance: AnchorAssurance,
        generated_at: datetime,
    ) -> None:
        if not is_registered_capability(capability_symbol):
            raise ArtifactExchangeError("authorization preview names an unregistered Shape-A capability")
        _validate_semantic_fields(semantic_fields)
        digests = (execution_intent_digest, requested_plan_digest)
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ArtifactExchangeError("authorization preview digest is invalid")
        if not isinstance(requested_step_id, str) or not _SAFE_TOKEN.fullmatch(requested_step_id):
            raise ArtifactExchangeError("authorization preview step_id is invalid")
        if not isinstance(target_capability_posture, CapabilityPosture):
            raise ArtifactExchangeError("authorization preview target capability posture is invalid")
        if not isinstance(target_anchor_assurance, AnchorAssurance):
            raise ArtifactExchangeError("authorization preview target anchor assurance is invalid")
        if not _is_utc(generated_at):
            raise ArtifactExchangeError("authorization preview generated_at must be a UTC datetime")

        self.capability_symbol = capability_symbol
        self.semantic_fields = semantic_fields
        self.execution_intent_digest = execution_intent_digest
        self.requested_plan_digest = requested_plan_digest
        self.requested_step_id = requested_step_id
        self.target_capability_posture = target_capability_posture
        self.target_anchor_assurance = target_anchor_assurance
        self.generated_at = generated_at


def preview_from_preparation(
    *,
    capability_symbol: str,
    request: object,
    prepared: object,
    requested_plan_digest: str,
    requested_step_id: str,
    target_capability_posture: CapabilityPosture,
    target_anchor_assurance: AnchorAssurance,
    generated_at: datetime,
) -> ShapeAAuthorizationPreview:
    """`execution_intent_digest` is always computed here from `prepared`'s
    own `.intent`, via the existing, unmodified
    `compute_execution_intent_digest()` -- never accepted as a parameter,
    exactly like `artifact_exchange.authorization_preview_from_preparation()`."""

    intent = getattr(prepared, "intent", None)
    if intent is None:
        raise ArtifactExchangeError("prepared execution has no intent to preview")
    return ShapeAAuthorizationPreview(
        capability_symbol=capability_symbol,
        semantic_fields=_render_semantic_fields(request, prepared),
        execution_intent_digest=compute_execution_intent_digest(intent),
        requested_plan_digest=requested_plan_digest,
        requested_step_id=requested_step_id,
        target_capability_posture=CapabilityPosture(target_capability_posture),
        target_anchor_assurance=AnchorAssurance(target_anchor_assurance),
        generated_at=generated_at,
    )


def _preview_payload(preview: ShapeAAuthorizationPreview) -> dict[str, object]:
    return {
        "schema_version": _SHAPE_A_PREVIEW_SCHEMA_VERSION,
        "capability_symbol": preview.capability_symbol,
        "semantic_fields": [list(pair) for pair in preview.semantic_fields],
        "execution_intent_digest": preview.execution_intent_digest,
        "requested_plan_digest": preview.requested_plan_digest,
        "requested_step_id": preview.requested_step_id,
        "target_capability_posture": preview.target_capability_posture.value,
        "target_anchor_assurance": preview.target_anchor_assurance.value,
        "generated_at": preview.generated_at.isoformat(),
    }


def _preview_mac(preview: ShapeAAuthorizationPreview, integrity_key: bytes) -> str:
    if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
        raise ArtifactExchangeError("authorization preview integrity key is invalid")
    canonical = json.dumps(_preview_payload(preview), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(integrity_key, _SHAPE_A_PREVIEW_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()


def shape_a_authorization_preview_to_bytes(preview: ShapeAAuthorizationPreview, *, integrity_key: bytes) -> bytes:
    if not isinstance(preview, ShapeAAuthorizationPreview):
        raise ArtifactExchangeError("Expected ShapeAAuthorizationPreview.")
    payload = _preview_payload(preview)
    payload["integrity_mac"] = _preview_mac(preview, integrity_key)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_shape_a_authorization_preview(path: Path, *, integrity_key: bytes) -> ShapeAAuthorizationPreview:
    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "capability_symbol",
            "semantic_fields",
            "execution_intent_digest",
            "requested_plan_digest",
            "requested_step_id",
            "target_capability_posture",
            "target_anchor_assurance",
            "generated_at",
            "integrity_mac",
        }
        if set(raw) != expected_keys or raw["schema_version"] != _SHAPE_A_PREVIEW_SCHEMA_VERSION:
            raise ValueError
        generated_at = datetime.fromisoformat(raw["generated_at"])
        if not _is_utc(generated_at):
            raise ValueError
        raw_fields = raw["semantic_fields"]
        if not isinstance(raw_fields, list):
            raise ValueError
        semantic_fields = tuple(
            (str(pair[0]), str(pair[1])) for pair in raw_fields if isinstance(pair, list) and len(pair) == 2
        )
        preview = ShapeAAuthorizationPreview(
            capability_symbol=raw["capability_symbol"],
            semantic_fields=semantic_fields,
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
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ArtifactExchangeError,
    ):
        raise ArtifactExchangeError(f"authorization preview is malformed: {path}") from None

    if not hmac.compare_digest(mac, _preview_mac(preview, integrity_key)):
        raise ArtifactExchangeError(f"authorization preview failed integrity verification: {path}")
    return preview


# --------------------------------------------------------------------------
# ShapeAPendingConfirmationRequest
# --------------------------------------------------------------------------


class ShapeAPendingConfirmationRequest:
    """The generalized counterpart to
    `artifact_exchange.PendingConfirmationRequest`. Never itself an
    authorization or a bearer of any authority."""

    __slots__ = (
        "capability_symbol",
        "contract_id",
        "expected_algorithm",
        "expected_authority_id",
        "expires_at",
        "intent_digest",
        "operation_id",
        "semantic_fields",
        "target_fingerprint",
        "target_identity_digest",
    )

    def __init__(
        self,
        *,
        capability_symbol: str,
        contract_id: str,
        operation_id: str,
        semantic_fields: tuple[tuple[str, str], ...],
        target_identity_digest: str,
        target_fingerprint: str,
        intent_digest: str,
        expires_at: datetime,
        expected_authority_id: str,
        expected_algorithm: str,
    ) -> None:
        if not is_registered_capability(capability_symbol):
            raise ArtifactExchangeError("pending confirmation request names an unregistered Shape-A capability")
        _validate_semantic_fields(semantic_fields)
        tokens = (contract_id, operation_id, expected_authority_id, expected_algorithm)
        if not all(isinstance(value, str) and _SAFE_TOKEN.fullmatch(value) for value in tokens):
            raise ArtifactExchangeError("pending confirmation request identity is invalid")
        digests = (target_identity_digest, target_fingerprint, intent_digest)
        if not all(isinstance(value, str) and _HEX_64.fullmatch(value) for value in digests):
            raise ArtifactExchangeError("pending confirmation request digest is invalid")
        if not _is_utc(expires_at):
            raise ArtifactExchangeError("pending confirmation request expiry must be a UTC datetime")

        self.capability_symbol = capability_symbol
        self.contract_id = contract_id
        self.operation_id = operation_id
        self.semantic_fields = semantic_fields
        self.target_identity_digest = target_identity_digest
        self.target_fingerprint = target_fingerprint
        self.intent_digest = intent_digest
        self.expires_at = expires_at
        self.expected_authority_id = expected_authority_id
        self.expected_algorithm = expected_algorithm


def pending_confirmation_request_from_contract(
    contract: RecoveryContract,
    *,
    capability_symbol: str,
    request: object,
    prepared: object,
    expected_authority_id: str,
    expected_algorithm: str = ACCEPTED_CONFIRMATION_ALGORITHM,
) -> ShapeAPendingConfirmationRequest:
    """The one place a `ShapeAPendingConfirmationRequest`'s binding facts
    are read from an authoritative `RecoveryContract` -- mirrors
    `artifact_exchange.pending_confirmation_request_from_contract()`."""

    return ShapeAPendingConfirmationRequest(
        capability_symbol=capability_symbol,
        contract_id=contract.contract_id,
        operation_id=contract.operation_id,
        semantic_fields=_render_semantic_fields(request, prepared),
        target_identity_digest=contract.target_identity_digest,
        target_fingerprint=contract.target_fingerprint,
        intent_digest=contract.intent_digest,
        expires_at=contract.expires_at,
        expected_authority_id=expected_authority_id,
        expected_algorithm=expected_algorithm,
    )


def _pending_payload(pending: ShapeAPendingConfirmationRequest) -> dict[str, object]:
    return {
        "schema_version": _SHAPE_A_PENDING_SCHEMA_VERSION,
        "capability_symbol": pending.capability_symbol,
        "contract_id": pending.contract_id,
        "operation_id": pending.operation_id,
        "semantic_fields": [list(pair) for pair in pending.semantic_fields],
        "target_identity_digest": pending.target_identity_digest,
        "target_fingerprint": pending.target_fingerprint,
        "intent_digest": pending.intent_digest,
        "expires_at": pending.expires_at.isoformat(),
        "expected_authority_id": pending.expected_authority_id,
        "expected_algorithm": pending.expected_algorithm,
    }


def _pending_mac(pending: ShapeAPendingConfirmationRequest, integrity_key: bytes) -> str:
    if not isinstance(integrity_key, bytes) or len(integrity_key) < 32:
        raise ArtifactExchangeError("pending confirmation request integrity key is invalid")
    canonical = json.dumps(_pending_payload(pending), sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(integrity_key, _SHAPE_A_PENDING_MAC_DOMAIN + canonical, hashlib.sha256).hexdigest()


def shape_a_pending_confirmation_request_to_bytes(
    pending: ShapeAPendingConfirmationRequest, *, integrity_key: bytes
) -> bytes:
    if not isinstance(pending, ShapeAPendingConfirmationRequest):
        raise ArtifactExchangeError("Expected ShapeAPendingConfirmationRequest.")
    payload = _pending_payload(pending)
    payload["integrity_mac"] = _pending_mac(pending, integrity_key)
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_shape_a_pending_confirmation_request(path: Path, *, integrity_key: bytes) -> ShapeAPendingConfirmationRequest:
    try:
        raw = json.loads(_read_secure(path))
        expected_keys = {
            "schema_version",
            "capability_symbol",
            "contract_id",
            "operation_id",
            "semantic_fields",
            "target_identity_digest",
            "target_fingerprint",
            "intent_digest",
            "expires_at",
            "expected_authority_id",
            "expected_algorithm",
            "integrity_mac",
        }
        if set(raw) != expected_keys or raw["schema_version"] != _SHAPE_A_PENDING_SCHEMA_VERSION:
            raise ValueError
        expires_at = datetime.fromisoformat(raw["expires_at"])
        if not _is_utc(expires_at):
            raise ValueError
        raw_fields = raw["semantic_fields"]
        if not isinstance(raw_fields, list):
            raise ValueError
        semantic_fields = tuple(
            (str(pair[0]), str(pair[1])) for pair in raw_fields if isinstance(pair, list) and len(pair) == 2
        )
        pending = ShapeAPendingConfirmationRequest(
            capability_symbol=raw["capability_symbol"],
            contract_id=raw["contract_id"],
            operation_id=raw["operation_id"],
            semantic_fields=semantic_fields,
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
    except (
        KeyError,
        TypeError,
        ValueError,
        IndexError,
        json.JSONDecodeError,
        UnicodeDecodeError,
        ArtifactExchangeError,
    ):
        raise ArtifactExchangeError(f"pending confirmation request is malformed: {path}") from None

    if not hmac.compare_digest(mac, _pending_mac(pending, integrity_key)):
        raise ArtifactExchangeError(f"pending confirmation request failed integrity verification: {path}")
    return pending


# --------------------------------------------------------------------------
# PlanAuthorizationV2 / ConfirmationEvidence codecs -- byte-identical
# reimplementation of artifact_exchange.py's own (capability-agnostic
# already; no alias-specific field anywhere in either type), not imported
# from there for the same layering reason the rest of this module is kept
# separate.
# --------------------------------------------------------------------------


def plan_authorization_v2_to_bytes(authorization: PlanAuthorizationV2) -> bytes:
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
        "proof": __import__("base64").b64encode(authorization.proof).decode("ascii"),
        "issued_at": authorization.issued_at.isoformat(),
        "expires_at": authorization.expires_at.isoformat(),
        "risk_class": authorization.risk_class.value,
        "evidence_fingerprint": authorization.evidence_fingerprint.to_payload(),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def load_signed_plan_authorization_v2(path: Path) -> PlanAuthorizationV2:
    import base64

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
                step_id=binding["step_id"], execution_intent_digest=binding["execution_intent_digest"]
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


def confirmation_evidence_to_bytes(evidence: ConfirmationEvidence) -> bytes:
    import base64

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
    import base64

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
