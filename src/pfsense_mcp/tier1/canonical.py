"""Deterministic, domain-separated canonicalization for Tier 1 contracts."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from enum import Enum
from typing import TypeAlias

from .errors import CanonicalizationError

CanonicalScalar: TypeAlias = None | bool | int | str
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


def _framed(value: str) -> bytes:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise CanonicalizationError("Digest context must contain valid UTF-8 scalar values.") from exc
    if len(encoded) > MAX_CANONICAL_STRING_BYTES:
        raise CanonicalizationError("Digest context component exceeds the safety limit.")
    return len(encoded).to_bytes(4, "big") + encoded


def _framed_bytes(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def digest_value(purpose: DigestPurpose, value: object, *, context: tuple[str, ...] = ()) -> str:
    """Hash one canonical value with a non-interchangeable purpose/context domain."""

    if len(context) > 16:
        raise CanonicalizationError("Digest context has too many components.")
    hasher = hashlib.sha256()
    for part in (_DOMAIN_PREFIX, purpose.value, *context):
        if not isinstance(part, str):
            raise CanonicalizationError("Digest context components must be strings.")
        hasher.update(_framed(part))
    hasher.update(_framed_bytes(canonical_json(value)))
    return hasher.hexdigest()
