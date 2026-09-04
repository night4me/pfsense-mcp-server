"""Closed ADR-037 Batch 1 semantics for the five local log DISPLAY
preference fields only (`format`, `reverseorder`, `nentries`,
`filterdescriptions`, `rawfilter`) -- presentation, never which events are
logged, retained, or forwarded.

This module is inert: it registers no tool, endpoint, policy, capability or
runtime. `LogSettings` is a true singleton, like `NTPSettings` -- see
`write_adapter_support.SINGLETON_LOCATOR`'s docstring for why a fixed
transport locator (rather than a fabricated numeric id) is correct here.

`LOG_RETENTION_SETTINGS` (`log_retention_settings.py`) targets the SAME
underlying pfREST endpoint with a disjoint field projection. Each is its
own distinct capability/endpoint_symbol/adapter/execution-core instance
(owner instruction: "Capabilities sharing one pfREST endpoint must remain
semantically distinct") -- `_FORBIDDEN_FIELDS` here includes every one of
`log_retention_settings.py`'s allowed fields, and vice versa, so neither
capability can ever mutate a field the other one owns without both this
adapter's own postcondition check AND the executor's independent
precondition-fingerprint rebinding catching it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr, field_validator

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.log_settings import LogSettings
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync

from .alias_description import ConfiguredApplianceTargetV1
from .canonical import CanonicalValue
from .errors import PreparedExecutionIntentError
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget
from .write_adapter_support import SINGLETON_LOCATOR, fields_equal, fields_match, read_appliance_target_digest

SEMANTIC_UNIT = "set_log_display_preferences_v1"
ENDPOINT_SYMBOL = "LOG_DISPLAY_PREFERENCES"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "log-display-preferences-v1"
ROLLBACK_VERSION = "log-display-preferences-rollback-v1"

_IDENTITY: dict[str, CanonicalValue] = {"resource": "status_logs_settings"}

_ALL_FIELDS: tuple[str, ...] = tuple(LogSettings.model_fields.keys())
_FORMAT_VALUES = frozenset({"rfc3164", "rfc5424"})

#: Purely presentational -- how log entries are displayed in the WebGUI.
#: Never which events are captured (nolog*), never retention (logfilesize/
#: rotatecount/logcompressiontype -- LOG_RETENTION_SETTINGS's own
#: projection), never remote destinations, never `disablelocallogging`
#: (which the schema warns also disables Login Protection) or
#: `logconfigchanges` (a self-referential config-change audit toggle).
_ALLOWED_FIELDS = ("format", "reverseorder", "nentries", "filterdescriptions", "rawfilter")
_FORBIDDEN_FIELDS = tuple(field for field in _ALL_FIELDS if field not in _ALLOWED_FIELDS)


class LogDisplayPreferencesChangeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    format: StrictStr
    reverseorder: StrictBool
    nentries: StrictInt
    filterdescriptions: StrictInt
    rawfilter: StrictBool

    @field_validator("format")
    @classmethod
    def _valid_format(cls, value: str) -> str:
        if value not in _FORMAT_VALUES:
            raise ValueError("format must be rfc3164 or rfc5424")
        return value

    @field_validator("filterdescriptions")
    @classmethod
    def _valid_filterdescriptions(cls, value: int) -> int:
        if value not in (0, 1, 2):
            raise ValueError("filterdescriptions must be 0, 1, or 2")
        return value

    @field_validator("nentries")
    @classmethod
    def _valid_nentries(cls, value: int) -> int:
        if not 0 <= value <= 1_000_000:
            raise ValueError("nentries is out of the supported range")
        return value


class LogDisplayPreferencesPatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    format: StrictStr
    reverseorder: StrictBool
    nentries: StrictInt
    filterdescriptions: StrictInt
    rawfilter: StrictBool


@dataclass(frozen=True, slots=True)
class LogSettingsStateV1:
    """Wraps the complete 34-field `LogSettings` snapshot as an immutable,
    sorted key/value tuple -- deliberately not one hand-typed dataclass
    field per key (both `LogDisplayPreferencesAdapterV1` and
    `LogRetentionSettingsAdapterV1` need the FULL snapshot for their own
    forbidden-field comparison; deriving the field set from
    `LogSettings.model_fields` rather than retyping all 34 names a second
    or third time removes the risk of the two capabilities' hand-typed
    lists silently drifting apart or missing a newly-added model field)."""

    values: tuple[tuple[str, CanonicalValue], ...]
    numeric_locator: int = SINGLETON_LOCATOR

    @classmethod
    def from_model(cls, settings: LogSettings) -> LogSettingsStateV1:
        data = settings.model_dump()
        if set(data) != set(_ALL_FIELDS):
            raise PreparedExecutionIntentError("Authoritative log settings state is incomplete or unsupported.")
        return cls(tuple(sorted(data.items())))

    def as_dict(self) -> dict[str, CanonicalValue]:
        return dict(self.values)

    def identity(self) -> dict[str, CanonicalValue]:
        return dict(_IDENTITY)

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return self.as_dict()

    def raw_target_hint(self) -> dict[str, CanonicalValue]:
        return self.as_dict()


class LogDisplayPreferencesReadClient(Protocol):
    def get_status_logs_settings(self) -> LogSettings: ...
    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedLogDisplayPreferencesExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: LogSettingsStateV1
    appliance_target_digest: str


class LogDisplayPreferencesAdapterV1:
    capability = Capability.LOG_DISPLAY_PREFERENCES_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(
        self, read_client: LogDisplayPreferencesReadClient, natural_identity: CanonicalValue
    ) -> LogSettingsStateV1:
        if natural_identity != _IDENTITY:
            raise PreparedExecutionIntentError("Semantic log settings identity is malformed.")
        return LogSettingsStateV1.from_model(read_client.get_status_logs_settings())

    def natural_identity(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).identity()

    def fingerprint(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).fingerprint()

    def transport_locator(self, raw_target: object) -> int:
        return self._state(raw_target).numeric_locator

    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel:
        normalized = self._intent(intent)
        return self._patch_from_values(normalized)

    def parse_response(self, raw_response: object) -> object:
        return {"accepted_status": getattr(raw_response, "status_code", None)}

    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool:
        before, after = self._state(pre).as_dict(), self._state(post).as_dict()
        normalized = self._intent(intent)
        requested = {field: normalized[field] for field in _ALLOWED_FIELDS}
        return fields_match(after, requested) and fields_equal(before, after, fields=_FORBIDDEN_FIELDS)

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        fingerprint = self._fingerprint(pre)
        return self._patch_from_values(fingerprint)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return self._fingerprint(pre) == self._state(post_rollback).as_dict()

    @staticmethod
    def _patch_from_values(values: Mapping[str, CanonicalValue]) -> LogDisplayPreferencesPatchV1:
        format_, reverseorder, nentries, filterdescriptions, rawfilter = (
            values["format"],
            values["reverseorder"],
            values["nentries"],
            values["filterdescriptions"],
            values["rawfilter"],
        )
        if (
            not isinstance(format_, str)
            or not isinstance(reverseorder, bool)
            or not isinstance(nentries, int)
            or isinstance(nentries, bool)
            or not isinstance(filterdescriptions, int)
            or isinstance(filterdescriptions, bool)
            or not isinstance(rawfilter, bool)
        ):
            raise PreparedExecutionIntentError("Log display preference values are malformed.")
        return LogDisplayPreferencesPatchV1(
            format=format_,
            reverseorder=reverseorder,
            nentries=nentries,
            filterdescriptions=filterdescriptions,
            rawfilter=rawfilter,
        )

    @staticmethod
    def _state(raw_target: object) -> LogSettingsStateV1:
        if isinstance(raw_target, LogSettingsStateV1):
            return raw_target
        if not isinstance(raw_target, dict) or set(raw_target) != set(_ALL_FIELDS):
            raise PreparedExecutionIntentError("Log settings target is malformed.")
        try:
            settings = LogSettings.model_validate(raw_target, strict=True)
        except Exception:
            raise PreparedExecutionIntentError("Log settings target is malformed.") from None
        return LogSettingsStateV1.from_model(settings)

    @staticmethod
    def _fingerprint(value: object) -> dict[str, CanonicalValue]:
        if not isinstance(value, dict) or set(value) != set(_ALL_FIELDS):
            raise PreparedExecutionIntentError("Log settings fingerprint is malformed.")
        return value

    @staticmethod
    def _intent(value: object) -> dict[str, CanonicalValue]:
        expected = {"operation", "raw_target_hint", *_ALLOWED_FIELDS, "appliance_target_digest"}
        if not isinstance(value, dict) or set(value) != expected:
            raise PreparedExecutionIntentError("Protected log display intent is malformed.")
        if value["operation"] != SEMANTIC_UNIT or value["raw_target_hint"] != _IDENTITY:
            raise PreparedExecutionIntentError("Protected log display intent is malformed.")
        if not isinstance(value["appliance_target_digest"], str):
            raise PreparedExecutionIntentError("Protected log display intent is malformed.")
        if (
            value["format"] not in _FORMAT_VALUES
            or not isinstance(value["reverseorder"], bool)
            or not isinstance(value["nentries"], int)
            or isinstance(value["nentries"], bool)
            or value["filterdescriptions"] not in (0, 1, 2)
            or not isinstance(value["rawfilter"], bool)
        ):
            raise PreparedExecutionIntentError("Protected log display intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "appliance_target_digest": value["appliance_target_digest"],
            **{field: value[field] for field in _ALLOWED_FIELDS},
        }


class LogDisplayPreferencesPreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(self, *, read_client: LogDisplayPreferencesReadClient, configured_target: ConfiguredApplianceTargetV1):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = LogDisplayPreferencesAdapterV1()

    @property
    def adapter(self) -> LogDisplayPreferencesAdapterV1:
        return self._adapter

    def prepare(self, request: LogDisplayPreferencesChangeV1) -> PreparedLogDisplayPreferencesExecutionV1:
        if not isinstance(request, LogDisplayPreferencesChangeV1):
            raise PreparedExecutionIntentError("Expected LogDisplayPreferencesChangeV1.")
        state = self._adapter.read_target(self._read_client, _IDENTITY)
        requested = {field: getattr(request, field) for field in _ALLOWED_FIELDS}
        current = {field: state.as_dict()[field] for field in _ALLOWED_FIELDS}
        if requested == current:
            raise PreparedExecutionIntentError("Log display preference change is a no-op.")
        appliance_digest = read_appliance_target_digest(self._read_client, self._configured_target)
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": dict(_IDENTITY),
            "appliance_target_digest": appliance_digest,
            **requested,
        }
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.LOG_DISPLAY_PREFERENCES_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedLogDisplayPreferencesExecutionV1(prepared, state, appliance_digest)
