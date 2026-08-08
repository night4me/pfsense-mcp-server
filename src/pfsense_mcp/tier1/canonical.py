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


class DigestPurpose(str, Enum):
    TARGET_IDENTITY = "target-identity"
    TARGET_FINGERPRINT = "target-fingerprint"
    INTENT = "intent"
    SNAPSHOT = "snapshot"
    CONFIRMATION = "confirmation"
    IDEMPOTENCY = "idempotency"


_DOMAIN_PREFIX = "pfSense-MCP/Tier1/v1"


def _normalize(value: object) -> CanonicalValue:
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        raise CanonicalizationError("Floating-point values require a capability-specific exact representation.")
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        normalized: dict[str, CanonicalValue] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("Canonical object keys must be strings.")
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise CanonicalizationError("Unicode normalization produced duplicate object keys.")
            normalized[normalized_key] = _normalize(item)
        return normalized
    raise CanonicalizationError("Value type is not supported by the canonical contract format.")


def canonical_json(value: object) -> bytes:
    """Return normalized deterministic UTF-8 JSON without insignificant whitespace."""

    normalized = _normalize(value)
    return json.dumps(normalized, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest_value(purpose: DigestPurpose, value: object, *, context: tuple[str, ...] = ()) -> str:
    """Hash one canonical value with a non-interchangeable purpose/context domain."""

    hasher = hashlib.sha256()
    for part in (_DOMAIN_PREFIX, purpose.value, *context):
        hasher.update(part.encode("utf-8"))
        hasher.update(b"\0")
    hasher.update(canonical_json(value))
    return hasher.hexdigest()
