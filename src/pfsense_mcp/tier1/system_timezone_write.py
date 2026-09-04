"""Closed ADR-037 Batch 1 semantics for the system timezone (the single
field `PATCH /api/v2/system/timezone` exposes).

This module is inert: it registers no tool, endpoint, policy, capability or
runtime. `SystemTimezone` is a true singleton -- see
`write_adapter_support.SINGLETON_LOCATOR`'s docstring.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictStr, field_validator

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.models.system_timezone import SystemTimezone

from .alias_description import ConfiguredApplianceTargetV1
from .canonical import CanonicalValue
from .errors import PreparedExecutionIntentError
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget
from .write_adapter_support import SINGLETON_LOCATOR, read_appliance_target_digest

SEMANTIC_UNIT = "set_system_timezone_v1"
ENDPOINT_SYMBOL = "SYSTEM_TIMEZONE"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "system-timezone-v1"
ROLLBACK_VERSION = "system-timezone-rollback-v1"

_IDENTITY: dict[str, CanonicalValue] = {"resource": "system_timezone"}

#: No enum is declared anywhere in the schema for this field (it is a
#: general IANA-style "Continent/Location" string, per the schema's own
#: description) -- this is a light structural sanity check, not a
#: fabricated allow-list of specific zone names. Matches the character
#: set every real IANA zone name and the literal "Etc/UTC"/"UTC" use.
_TIMEZONE = re.compile(r"[A-Za-z0-9_+\-/]{1,64}")


class SystemTimezoneChangeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    timezone: StrictStr

    @field_validator("timezone")
    @classmethod
    def _valid_timezone(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not _TIMEZONE.fullmatch(normalized):
            raise ValueError("timezone is invalid")
        return normalized


class SystemTimezonePatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    timezone: StrictStr


@dataclass(frozen=True, slots=True)
class SystemTimezoneStateV1:
    timezone: str
    numeric_locator: int = SINGLETON_LOCATOR

    @classmethod
    def from_model(cls, value: SystemTimezone) -> SystemTimezoneStateV1:
        if not isinstance(value.timezone, str) or not _TIMEZONE.fullmatch(unicodedata.normalize("NFC", value.timezone)):
            raise PreparedExecutionIntentError("Authoritative system timezone state is incomplete or unsupported.")
        return cls(unicodedata.normalize("NFC", value.timezone))

    def identity(self) -> dict[str, CanonicalValue]:
        return dict(_IDENTITY)

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return {"timezone": self.timezone}

    def raw_target_hint(self) -> dict[str, CanonicalValue]:
        return self.fingerprint()


class SystemTimezoneReadClient(Protocol):
    def get_system_timezone(self) -> SystemTimezone: ...
    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedSystemTimezoneExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: SystemTimezoneStateV1
    appliance_target_digest: str


class SystemTimezoneAdapterV1:
    capability = Capability.SYSTEM_TIMEZONE_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(
        self, read_client: SystemTimezoneReadClient, natural_identity: CanonicalValue
    ) -> SystemTimezoneStateV1:
        if natural_identity != _IDENTITY:
            raise PreparedExecutionIntentError("Semantic system timezone identity is malformed.")
        return SystemTimezoneStateV1.from_model(read_client.get_system_timezone())

    def natural_identity(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).identity()

    def fingerprint(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).fingerprint()

    def transport_locator(self, raw_target: object) -> int:
        return self._state(raw_target).numeric_locator

    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel:
        normalized = self._intent(intent)
        timezone = normalized["timezone"]
        if not isinstance(timezone, str):
            raise PreparedExecutionIntentError("Protected system timezone intent is malformed.")
        return SystemTimezonePatchV1(timezone=timezone)

    def parse_response(self, raw_response: object) -> object:
        return {"accepted_status": getattr(raw_response, "status_code", None)}

    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool:
        after = self._state(post)
        normalized = self._intent(intent)
        return after.timezone == normalized["timezone"]

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        fingerprint = self._fingerprint(pre)
        timezone = fingerprint["timezone"]
        if not isinstance(timezone, str):
            raise PreparedExecutionIntentError("System timezone rollback value is malformed.")
        return SystemTimezonePatchV1(timezone=timezone)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return self._fingerprint(pre) == self._state(post_rollback).fingerprint()

    @staticmethod
    def _state(raw_target: object) -> SystemTimezoneStateV1:
        if isinstance(raw_target, SystemTimezoneStateV1):
            return raw_target
        if not isinstance(raw_target, dict) or set(raw_target) != {"timezone"}:
            raise PreparedExecutionIntentError("System timezone target is malformed.")
        try:
            value = SystemTimezone.model_validate(raw_target, strict=True)
        except Exception:
            raise PreparedExecutionIntentError("System timezone target is malformed.") from None
        return SystemTimezoneStateV1.from_model(value)

    @staticmethod
    def _fingerprint(value: object) -> dict[str, CanonicalValue]:
        if not isinstance(value, dict) or set(value) != {"timezone"}:
            raise PreparedExecutionIntentError("System timezone fingerprint is malformed.")
        timezone = value["timezone"]
        if not isinstance(timezone, str) or not _TIMEZONE.fullmatch(timezone):
            raise PreparedExecutionIntentError("System timezone fingerprint is malformed.")
        return value

    @staticmethod
    def _intent(value: object) -> dict[str, CanonicalValue]:
        expected = {"operation", "raw_target_hint", "timezone", "appliance_target_digest"}
        if not isinstance(value, dict) or set(value) != expected:
            raise PreparedExecutionIntentError("Protected system timezone intent is malformed.")
        if (
            value["operation"] != SEMANTIC_UNIT
            or value["raw_target_hint"] != _IDENTITY
            or not isinstance(value["timezone"], str)
            or not _TIMEZONE.fullmatch(value["timezone"])
            or not isinstance(value["appliance_target_digest"], str)
        ):
            raise PreparedExecutionIntentError("Protected system timezone intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "timezone": value["timezone"],
            "appliance_target_digest": value["appliance_target_digest"],
        }


class SystemTimezonePreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(self, *, read_client: SystemTimezoneReadClient, configured_target: ConfiguredApplianceTargetV1):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = SystemTimezoneAdapterV1()

    @property
    def adapter(self) -> SystemTimezoneAdapterV1:
        return self._adapter

    def prepare(self, request: SystemTimezoneChangeV1) -> PreparedSystemTimezoneExecutionV1:
        if not isinstance(request, SystemTimezoneChangeV1):
            raise PreparedExecutionIntentError("Expected SystemTimezoneChangeV1.")
        state = self._adapter.read_target(self._read_client, _IDENTITY)
        if state.timezone == request.timezone:
            raise PreparedExecutionIntentError("System timezone change is a no-op.")
        appliance_digest = read_appliance_target_digest(self._read_client, self._configured_target)
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": dict(_IDENTITY),
            "timezone": request.timezone,
            "appliance_target_digest": appliance_digest,
        }
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.SYSTEM_TIMEZONE_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedSystemTimezoneExecutionV1(prepared, state, appliance_digest)
