"""Deterministic, domain-separated canonicalization for Tier 1 contracts."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from enum import Enum
from typing import TypeAlias

from .errors import CanonicalizationError

CanonicalScalar: TypeAlias = bool | int | str | None
CanonicalValue: TypeAlias = CanonicalScalar | list["CanonicalValue"] | dict[str, "CanonicalValue"]

MAX_CANONICAL_DEPTH = 32
MAX_CANONICAL_NODES = 10_000
MAX_CANONICAL_COLLECTION_ITEMS = 4_096
MAX_CANONICAL_STRING_BYTES = 65_536
MAX_CANONICAL_BYTES = 1_048_576
MIN_CANONICAL_INTEGER = -(2**63)
MAX_CANONICAL_INTEGER = 2**63 - 1


class DigestPurpose(str, Enum):
    TARGET_IDENTITY = "target-identity"
    TARGET_FINGERPRINT = "target-fingerprint"
    INTENT = "intent"
    SNAPSHOT = "snapshot"
    CONFIRMATION = "confirmation"
    IDEMPOTENCY = "idempotency"
    RECONCILIATION = "reconciliation"
    #: ADR-022 Phase B -- binds a `pfsense_mcp.security_plan_digest`
    #: `PlanDigest` to one exact `SecurityPosturePlan`. Domain-separated
    #: from every other purpose above so a plan digest can never be
    #: replayed as, or confused with, a contract/confirmation/
    #: reconciliation digest, or vice versa. Additive only -- does not
    #: change any existing member's meaning; `security_plan_digest.py`
    #: is the only caller.
    PLAN = "plan"
    #: ADR-022 Phase C -- domain-separates a `PlanAuthorization`'s signed
    #: payload from every other purpose above, including `PLAN` itself
    #: and `DEPROVISION_AUTHORIZATION` below. Included as a literal field
    #: inside the canonical payload `security_authorization.py` signs
    #: (not used to compute a `digest_value()` hash for the signature
    #: itself), so a signature produced over one purpose's payload can
    #: never verify against another purpose's payload even if the two
    #: payloads' other fields happened to collide. Additive only.
    PLAN_AUTHORIZATION = "plan-authorization"
    #: ADR-025 Slice B2 -- signed PlanAuthorization v2 payloads, which
    #: bind exact step IDs to B1 execution-intent digests. Kept distinct
    #: from v1 PLAN_AUTHORIZATION in addition to signing schema_version=2,
    #: so neither version's signature can be interpreted as the other.
    PLAN_AUTHORIZATION_V2 = "plan-authorization-v2"
    #: ADR-022 Phase C -- domain-separates `DeprovisionAuthorization`,
    #: a structurally distinct artifact *type* from `PlanAuthorization`
    #: (own schema, own fields, own signing payload) per ADR-022's
    #: "Destructive operations" section -- never a boolean flag on the
    #: routine artifact. Additive only.
    DEPROVISION_AUTHORIZATION = "deprovision-authorization"
    #: ADR-025 Slice B1 -- identifies one complete, versioned prepared
    #: execution/recovery tuple. The prepared-execution-intent module is
    #: the sole semantic owner and sole caller. Distinct from the narrower
    #: INTENT, TARGET_*, SNAPSHOT, IDEMPOTENCY, PLAN, and authorization
    #: domains; none of those digests can be substituted for this one.
    EXECUTION_INTENT = "execution-intent"
    #: `pfsense-mcp-security setup` Slice 1 -- identifies one complete
    #: `SetupPlan` (`security_setup_plan.py`). Domain-separated from
    #: `PLAN` (which identifies a narrower `SecurityPosturePlan`, one of
    #: `SetupPlan`'s own inputs) and every other purpose above; a setup
    #: plan digest and a posture plan digest can never be confused with
    #: each other even where their payloads overlap. Additive only --
    #: does not change any existing member's meaning.
    SETUP_PLAN = "setup-plan"


_DOMAIN_PREFIX = "pfSense-MCP/Tier1/v1"


def _normalized_string(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("Canonical strings must be valid UTF-8 scalar values.") from exc
    if len(encoded) > MAX_CANONICAL_STRING_BYTES:
        raise CanonicalizationError("Canonical string exceeds the safety limit.")
    return normalized


def _normalize(value: object, *, depth: int, nodes: list[int]) -> CanonicalValue:
    if depth > MAX_CANONICAL_DEPTH:
        raise CanonicalizationError("Canonical value exceeds the nesting limit.")
    nodes[0] += 1
    if nodes[0] > MAX_CANONICAL_NODES:
        raise CanonicalizationError("Canonical value exceeds the node limit.")
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        if not MIN_CANONICAL_INTEGER <= value <= MAX_CANONICAL_INTEGER:
            raise CanonicalizationError("Canonical integer exceeds the signed 64-bit range.")
        return value
    if isinstance(value, float):
        raise CanonicalizationError("Floating-point values require a capability-specific exact representation.")
    if isinstance(value, str):
        return _normalized_string(value)
    if isinstance(value, (list, tuple)):
        if len(value) > MAX_CANONICAL_COLLECTION_ITEMS:
            raise CanonicalizationError("Canonical collection exceeds the item limit.")
        return [_normalize(item, depth=depth + 1, nodes=nodes) for item in value]
    if isinstance(value, dict):
        if len(value) > MAX_CANONICAL_COLLECTION_ITEMS:
            raise CanonicalizationError("Canonical collection exceeds the item limit.")
        normalized: dict[str, CanonicalValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("Canonical object keys must be strings.")
            normalized_key = _normalized_string(key)
            if normalized_key in normalized:
                raise CanonicalizationError("Unicode normalization produced duplicate object keys.")
            normalized[normalized_key] = _normalize(item, depth=depth + 1, nodes=nodes)
        return normalized
    raise CanonicalizationError("Value type is not supported by the canonical contract format.")


def canonical_json(value: object) -> bytes:
    """Return normalized deterministic UTF-8 JSON without insignificant whitespace."""

    normalized = _normalize(value, depth=0, nodes=[0])
    encoded = json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > MAX_CANONICAL_BYTES:
        raise CanonicalizationError("Canonical representation exceeds the byte limit.")
    return encoded


def validate_canonical_value(value: object) -> CanonicalValue:
    """Public entry point for `_normalize()` (added 2026-08-09, mypy
    --strict finding): callers that already have a Python object of
    unknown shape (typically from `json.loads()`, which is typed `Any`)
    and need it as a genuine, size/depth-bounded `CanonicalValue` --
    never an unvalidated `Any` reinterpreted as one -- should call this
    rather than trusting the object's shape. `executor.py`'s `_decrypt()`
    is the first caller: a decrypted protected artifact must be a real
    `CanonicalValue`, not merely whatever `json.loads()` happened to
    return, before it re-enters any digest/fingerprint computation."""

    return _normalize(value, depth=0, nodes=[0])


def frame_str(value: str) -> bytes:
    """Length-prefix a UTF-8 string component so it can be concatenated
    with other framed components without delimiter ambiguity. Shared by
    digest construction here and by MAC construction in store.py — do not
    reintroduce a NUL or other ad hoc delimiter anywhere in this package;
    use this (or frame_bytes) instead."""

    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("Digest context must contain valid UTF-8 scalar values.") from exc
    if len(encoded) > MAX_CANONICAL_STRING_BYTES:
        raise CanonicalizationError("Digest context component exceeds the safety limit.")
    return len(encoded).to_bytes(4, "big") + encoded


def frame_bytes(value: bytes) -> bytes:
    """Length-prefix an arbitrary bytes component. See frame_str."""

    return len(value).to_bytes(4, "big") + value


def digest_value(purpose: DigestPurpose, value: object, *, context: tuple[str, ...] = ()) -> str:
    """Hash one canonical value with a non-interchangeable purpose/context domain."""

    if len(context) > 16:
        raise CanonicalizationError("Digest context has too many components.")
    hasher = hashlib.sha256()
    for part in (_DOMAIN_PREFIX, purpose.value, *context):
        if not isinstance(part, str):
            raise CanonicalizationError("Digest context components must be strings.")
        hasher.update(frame_str(part))
    hasher.update(frame_bytes(canonical_json(value)))
    return hasher.hexdigest()
