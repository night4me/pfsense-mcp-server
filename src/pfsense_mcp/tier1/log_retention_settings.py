"""Closed ADR-037 Batch 1 semantics for the three local log RETENTION
fields only (`logfilesize`, `rotatecount`, `logcompressiontype`) --
storage/rotation policy, never which events are captured or how they are
displayed.

This module is inert: it registers no tool, endpoint, policy, capability or
runtime. Targets the same `LogSettings` singleton as
`log_display_preferences.py` -- see that module's docstring for why the
two capabilities are kept fully distinct despite sharing one pfREST
endpoint, and `write_adapter_support.SINGLETON_LOCATOR` for the transport
locator rationale.

**Minor audit-retention risk (carried from the ADR-037 Batch 1 proposal,
not silently dropped)**: reducing `logfilesize`/`rotatecount` shrinks how
much local log history survives before rotation -- a mild forensic/
evidence-retention implication, not a Lockout/Routing/DNS-DHCP/Firewall/
Credential/VPN/Cert/Service-interruption risk. `NtpTimeServerPreferChangeV1`-
style field validators below apply a conservative non-negative sanity floor
(this codebase has no evidenced pfSense-side minimum for either field to
enforce a stronger one against); a caller reducing retention is still
permitted -- this is a policy/visibility note for the owner and any future
LAB qualification review, not a hard block this pass invents on its own.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictInt, StrictStr, field_validator

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.log_settings import LogSettings
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync

from .alias_description import ConfiguredApplianceTargetV1
from .canonical import CanonicalValue
from .errors import PreparedExecutionIntentError
from .log_display_preferences import LogSettingsStateV1
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget
from .write_adapter_support import fields_equal, fields_match, read_appliance_target_digest

SEMANTIC_UNIT = "set_log_retention_settings_v1"
ENDPOINT_SYMBOL = "LOG_RETENTION_SETTINGS"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "log-retention-settings-v1"
ROLLBACK_VERSION = "log-retention-settings-rollback-v1"

_IDENTITY: dict[str, CanonicalValue] = {"resource": "status_logs_settings"}

_ALL_FIELDS: tuple[str, ...] = tuple(LogSettings.model_fields.keys())
_COMPRESSION_VALUES = frozenset({"bzip2", "gzip", "xz", "zstd", "none"})

_ALLOWED_FIELDS = ("logfilesize", "rotatecount", "logcompressiontype")
_FORBIDDEN_FIELDS = tuple(field for field in _ALL_FIELDS if field not in _ALLOWED_FIELDS)


class LogRetentionSettingsChangeV1(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    logfilesize: StrictInt
    rotatecount: StrictInt
    logcompressiontype: StrictStr

    @field_validator("logfilesize")
    @classmethod
    def _valid_logfilesize(cls, value: int) -> int:
        if not 1 <= value <= 2_147_483_647:
            raise ValueError("logfilesize is out of the supported range")
        return value

    @field_validator("rotatecount")
    @classmethod
    def _valid_rotatecount(cls, value: int) -> int:
        if not 0 <= value <= 100_000:
            raise ValueError("rotatecount is out of the supported range")
        return value

    @field_validator("logcompressiontype")
    @classmethod
    def _valid_logcompressiontype(cls, value: str) -> str:
        if value not in _COMPRESSION_VALUES:
            raise ValueError("logcompressiontype is not a supported codec")
        return value


class LogRetentionSettingsPatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    logfilesize: StrictInt
    rotatecount: StrictInt
    logcompressiontype: StrictStr


class LogRetentionSettingsReadClient(Protocol):
    def get_status_logs_settings(self) -> LogSettings: ...
    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedLogRetentionSettingsExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: LogSettingsStateV1
    appliance_target_digest: str


class LogRetentionSettingsAdapterV1:
    capability = Capability.LOG_RETENTION_SETTINGS_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(
        self, read_client: LogRetentionSettingsReadClient, natural_identity: CanonicalValue
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
    def _patch_from_values(values: Mapping[str, CanonicalValue]) -> LogRetentionSettingsPatchV1:
        logfilesize, rotatecount, logcompressiontype = (
            values["logfilesize"],
            values["rotatecount"],
            values["logcompressiontype"],
        )
        if (
            not isinstance(logfilesize, int)
            or isinstance(logfilesize, bool)
            or not isinstance(rotatecount, int)
            or isinstance(rotatecount, bool)
            or not isinstance(logcompressiontype, str)
        ):
            raise PreparedExecutionIntentError("Log retention setting values are malformed.")
        return LogRetentionSettingsPatchV1(
            logfilesize=logfilesize, rotatecount=rotatecount, logcompressiontype=logcompressiontype
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
            raise PreparedExecutionIntentError("Protected log retention intent is malformed.")
        if value["operation"] != SEMANTIC_UNIT or value["raw_target_hint"] != _IDENTITY:
            raise PreparedExecutionIntentError("Protected log retention intent is malformed.")
        if not isinstance(value["appliance_target_digest"], str):
            raise PreparedExecutionIntentError("Protected log retention intent is malformed.")
        logfilesize, rotatecount, codec = value["logfilesize"], value["rotatecount"], value["logcompressiontype"]
        if (
            not isinstance(logfilesize, int)
            or isinstance(logfilesize, bool)
            or not isinstance(rotatecount, int)
            or isinstance(rotatecount, bool)
            or codec not in _COMPRESSION_VALUES
        ):
            raise PreparedExecutionIntentError("Protected log retention intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "appliance_target_digest": value["appliance_target_digest"],
            **{field: value[field] for field in _ALLOWED_FIELDS},
        }


class LogRetentionSettingsPreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(self, *, read_client: LogRetentionSettingsReadClient, configured_target: ConfiguredApplianceTargetV1):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = LogRetentionSettingsAdapterV1()

    @property
    def adapter(self) -> LogRetentionSettingsAdapterV1:
        return self._adapter

    def prepare(self, request: LogRetentionSettingsChangeV1) -> PreparedLogRetentionSettingsExecutionV1:
        if not isinstance(request, LogRetentionSettingsChangeV1):
            raise PreparedExecutionIntentError("Expected LogRetentionSettingsChangeV1.")
        state = self._adapter.read_target(self._read_client, _IDENTITY)
        requested = {field: getattr(request, field) for field in _ALLOWED_FIELDS}
        current = {field: state.as_dict()[field] for field in _ALLOWED_FIELDS}
        if requested == current:
            raise PreparedExecutionIntentError("Log retention setting change is a no-op.")
        appliance_digest = read_appliance_target_digest(self._read_client, self._configured_target)
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": dict(_IDENTITY),
            "appliance_target_digest": appliance_digest,
            **requested,
        }
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.LOG_RETENTION_SETTINGS_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedLogRetentionSettingsExecutionV1(prepared, state, appliance_digest)
