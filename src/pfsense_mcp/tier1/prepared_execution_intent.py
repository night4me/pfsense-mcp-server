"""Immutable ADR-025 B1 execution/recovery intent and digest.

This pure, inert module owns exactly one semantic object and its digest. It
does not authorize, consume, persist, confirm, execute, or register anything.
Every canonical value is validated by :mod:`pfsense_mcp.tier1.canonical` and
then deeply frozen; payload generation returns fresh copies so caller mutation
cannot change the prepared object after a digest has been computed.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TypeAlias, cast

from pfsense_mcp.capabilities import Capability

from .canonical import CanonicalValue, DigestPurpose, digest_value, validate_canonical_value
from .errors import CanonicalizationError, PreparedExecutionIntentError

PREPARED_EXECUTION_INTENT_SCHEMA_VERSION = 1

_DIGEST_CONTEXT = ("PreparedExecutionIntentV1",)
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, slots=True)
class _FrozenCanonicalList:
    items: tuple[_FrozenCanonicalValue, ...]


@dataclass(frozen=True, slots=True)
class _FrozenCanonicalObject:
    items: tuple[tuple[str, _FrozenCanonicalValue], ...]


_FrozenCanonicalScalar: TypeAlias = bool | int | str | None
_FrozenCanonicalValue: TypeAlias = _FrozenCanonicalScalar | _FrozenCanonicalList | _FrozenCanonicalObject


def _freeze(value: CanonicalValue) -> _FrozenCanonicalValue:
    if isinstance(value, list):
        return _FrozenCanonicalList(tuple(_freeze(item) for item in value))
    if isinstance(value, dict):
        return _FrozenCanonicalObject(tuple((key, _freeze(item)) for key, item in sorted(value.items())))
    return value


def _thaw(value: _FrozenCanonicalValue) -> CanonicalValue:
    if isinstance(value, _FrozenCanonicalList):
        return [_thaw(item) for item in value.items]
    if isinstance(value, _FrozenCanonicalObject):
        return {key: _thaw(item) for key, item in value.items}
    return value


def _validated_frozen(value: object, *, field_name: str, require_object: bool = False) -> _FrozenCanonicalValue:
    try:
        canonical = validate_canonical_value(value)
    except CanonicalizationError as exc:
        raise PreparedExecutionIntentError(f"{field_name} is not a supported canonical value.") from exc
    if canonical is None:
        raise PreparedExecutionIntentError(f"{field_name} must be explicit and non-null.")
    if require_object and not isinstance(canonical, dict):
        raise PreparedExecutionIntentError(f"{field_name} must be a canonical object.")
    return _freeze(canonical)


@dataclass(frozen=True, slots=True, init=False)
class PreparedExecutionIntentV1:
    """One complete, immutable Tier 1 execution/recovery intent.

    ``resource_target`` is the resource-level natural identity used by a
    capability adapter, not appliance identity. ``target_precondition`` is
    the exact fingerprint input expected before send. The normalized mutation
    intent is the full canonical object the sealed executor binds (including
    any capability-specific target hint). ``adapter_version`` pins the code
    semantics that turn that intent into a request and verify its post-state;
    ``rollback_snapshot`` and ``rollback_plan_version`` pin recovery meaning.

    All fields are mandatory. Unsupported schema versions fail closed. Nested
    canonical containers are deeply frozen internally; properties return fresh
    canonical copies and cannot mutate this object.
    """

    schema_version: int
    capability: Capability
    endpoint_symbol: str
    http_method: str
    adapter_version: str
    rollback_plan_version: str
    _resource_target: _FrozenCanonicalValue
    _target_precondition: _FrozenCanonicalValue
    _normalized_mutation_intent: _FrozenCanonicalValue
    _rollback_snapshot: _FrozenCanonicalValue

    def __init__(
        self,
        *,
        schema_version: int,
        capability: Capability,
        endpoint_symbol: str,
        http_method: str,
        adapter_version: str,
        resource_target: object,
        target_precondition: object,
        normalized_mutation_intent: object,
        rollback_snapshot: object,
        rollback_plan_version: str,
    ) -> None:
        if type(schema_version) is not int or schema_version != PREPARED_EXECUTION_INTENT_SCHEMA_VERSION:
            raise PreparedExecutionIntentError("Unsupported prepared execution-intent schema version.")
        if not isinstance(capability, Capability) or not capability.name.endswith("_WRITE"):
            raise PreparedExecutionIntentError("Prepared execution intent requires a WRITE capability.")
        identifiers = (endpoint_symbol, adapter_version, rollback_plan_version)
        if not all(isinstance(value, str) and _IDENTIFIER.fullmatch(value) for value in identifiers):
            raise PreparedExecutionIntentError("Prepared execution-intent identifier is invalid.")
        if not isinstance(http_method, str) or http_method not in _MUTATING_METHODS:
            raise PreparedExecutionIntentError("Prepared execution-intent HTTP method is invalid.")

        frozen_target = _validated_frozen(resource_target, field_name="resource_target")
        frozen_precondition = _validated_frozen(target_precondition, field_name="target_precondition")
        frozen_intent = _validated_frozen(
            normalized_mutation_intent,
            field_name="normalized_mutation_intent",
            require_object=True,
        )
        frozen_snapshot = _validated_frozen(rollback_snapshot, field_name="rollback_snapshot")

        object.__setattr__(self, "schema_version", schema_version)
        object.__setattr__(self, "capability", capability)
        object.__setattr__(self, "endpoint_symbol", endpoint_symbol)
        object.__setattr__(self, "http_method", http_method)
        object.__setattr__(self, "adapter_version", adapter_version)
        object.__setattr__(self, "rollback_plan_version", rollback_plan_version)
        object.__setattr__(self, "_resource_target", frozen_target)
        object.__setattr__(self, "_target_precondition", frozen_precondition)
        object.__setattr__(self, "_normalized_mutation_intent", frozen_intent)
        object.__setattr__(self, "_rollback_snapshot", frozen_snapshot)

    @property
    def resource_target(self) -> CanonicalValue:
        return _thaw(self._resource_target)

    @property
    def target_precondition(self) -> CanonicalValue:
        return _thaw(self._target_precondition)

    @property
    def normalized_mutation_intent(self) -> dict[str, CanonicalValue]:
        return cast(dict[str, CanonicalValue], _thaw(self._normalized_mutation_intent))

    @property
    def rollback_snapshot(self) -> CanonicalValue:
        return _thaw(self._rollback_snapshot)


def prepared_execution_intent_payload_of(intent: PreparedExecutionIntentV1) -> dict[str, CanonicalValue]:
    """Return the sole canonical semantic payload for ``intent``.

    The explicit construction avoids ``repr()``, ``__dict__``, dataclass
    serialization, or caller-provided digests. Generated contract/lifecycle
    and authorization/provenance values are intentionally absent.
    """

    if not isinstance(intent, PreparedExecutionIntentV1):
        raise PreparedExecutionIntentError("Expected PreparedExecutionIntentV1.")
    return {
        "schema_version": intent.schema_version,
        "capability": intent.capability.name,
        "endpoint_symbol": intent.endpoint_symbol,
        "http_method": intent.http_method,
        "adapter_version": intent.adapter_version,
        "resource_target": intent.resource_target,
        "target_precondition": intent.target_precondition,
        "normalized_mutation_intent": intent.normalized_mutation_intent,
        "rollback_snapshot": intent.rollback_snapshot,
        "rollback_plan_version": intent.rollback_plan_version,
    }


def compute_execution_intent_digest(intent: PreparedExecutionIntentV1) -> str:
    """Recompute the v1 execution-intent digest from the prepared object."""

    return digest_value(
        DigestPurpose.EXECUTION_INTENT,
        prepared_execution_intent_payload_of(intent),
        context=_DIGEST_CONTEXT,
    )
