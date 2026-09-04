"""Closed ADR-037 Batch 1 semantics for the six NTP logging/statistics
observability toggles only (`logpeer`, `logsys`, `clockstats`, `loopstats`,
`peerstats`, `statsgraph`).

This module is inert: it registers no tool, endpoint, policy, capability or
runtime. `NTPSettings` is a true singleton -- there is exactly one such
object, with no natural numeric identifier -- so this adapter uses the
shared `SINGLETON_LOCATOR` constant (`write_adapter_support.py`) rather
than inventing a fake id, and a fixed, constant semantic identity.

**Known schema ambiguity, deliberately documented rather than silently
assumed** (owner instruction: "if the source differs from the proposal,
stop or narrow; do not silently broaden"): the pinned OpenAPI schema's
merged `PATCH /services/ntp/settings` request body declares `serverauthkey`
in its top-level `required` array. Read in isolation this could be
mistaken for an unconditional requirement -- but `serverauthkey`'s own
field description states the actual rule: "This field is only available
when the following conditions are met: `serverauth` must be equal to
`true`". This flattening of a conditional (`requireif`-style) rule into a
top-level `required` array during OpenAPI generation is a documented
pattern elsewhere in this same schema (see `LogSettings`' `ipprotocol`/
`sourceip`, similarly gated). This adapter's PATCH body never includes
`serverauth` or `serverauthkey` at all (see `_ALLOWED_FIELDS` below) --
under pfSense's own `requireif` convention this condition is evaluated
against the REQUEST's own fields, not the persisted server state, so
omitting `serverauth` entirely should mean the condition is never
triggered. This cannot be verified without a live LAB call, which this
offline implementation pass does not perform (owner instruction: no LAB
contact). **This is an explicit, documented open item for the LAB
qualification gate this capability requires before `verified=True` can
ever be set** -- not a silent assumption.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictBool

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.ntp_settings import NtpSettings
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync

from .alias_description import ConfiguredApplianceTargetV1
from .canonical import CanonicalValue
from .errors import PreparedExecutionIntentError
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget
from .write_adapter_support import SINGLETON_LOCATOR, fields_equal, fields_match, read_appliance_target_digest

SEMANTIC_UNIT = "set_ntp_settings_observability_v1"
ENDPOINT_SYMBOL = "NTP_SETTINGS_OBSERVABILITY_TOGGLES"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "ntp-settings-observability-v1"
ROLLBACK_VERSION = "ntp-settings-observability-rollback-v1"

_IDENTITY: dict[str, CanonicalValue] = {"resource": "ntp_settings"}

#: The six fields this capability may set. Deliberately excludes `enable`
#: (service enable/disable), `interface` (interface-domain), `serverauth`/
#: `serverauthkey`/`serverauthalgo` (authentication/secret-adjacent), and
#: every poll/orphan/dnsresolv/leapsec tuning field (deferred, per the
#: owner's Batch 1 approval, to a separate NTP_SETTINGS_POLL_TUNING
#: decision never authorized here).
_ALLOWED_FIELDS = ("logpeer", "logsys", "clockstats", "loopstats", "peerstats", "statsgraph")

#: Every other NtpSettings field -- compared byte-identical before/after
#: by `is_semantically_verified()` so this capability can never silently
#: ride along with, or cause, a change to anything outside its projection.
_FORBIDDEN_FIELDS = (
    "enable",
    "interface",
    "leapsec",
    "dnsresolv",
    "ntpmaxpeers",
    "ntpmaxpoll",
    "ntpminpoll",
    "orphan",
    "serverauth",
    "serverauthalgo",
)


class NtpSettingsObservabilityChangeV1(BaseModel):
    """The complete model-facing request: all six observability fields,
    always supplied together (never a partial subset of the projection --
    this avoids any "which of the six did the caller intend to touch"
    ambiguity, mirroring how `AliasDescriptionChangeV1` always supplies
    its one field in full)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    logpeer: StrictBool
    logsys: StrictBool
    clockstats: StrictBool
    loopstats: StrictBool
    peerstats: StrictBool
    statsgraph: StrictBool


class NtpSettingsObservabilityPatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing. Contains only the six
    projected fields -- no `id` (this is a singleton endpoint with no id
    parameter in its own schema)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    logpeer: StrictBool
    logsys: StrictBool
    clockstats: StrictBool
    loopstats: StrictBool
    peerstats: StrictBool
    statsgraph: StrictBool


@dataclass(frozen=True, slots=True)
class NtpSettingsStateV1:
    logpeer: bool
    logsys: bool
    clockstats: bool
    loopstats: bool
    peerstats: bool
    statsgraph: bool
    enable: bool
    interface: tuple[str, ...] | None
    leapsec: str | None
    dnsresolv: str
    ntpmaxpeers: int
    ntpmaxpoll: str | None
    ntpminpoll: str | None
    orphan: int
    serverauth: bool
    serverauthalgo: str

    numeric_locator: int = SINGLETON_LOCATOR

    @classmethod
    def from_model(cls, settings: NtpSettings) -> NtpSettingsStateV1:
        return cls(
            logpeer=settings.logpeer,
            logsys=settings.logsys,
            clockstats=settings.clockstats,
            loopstats=settings.loopstats,
            peerstats=settings.peerstats,
            statsgraph=settings.statsgraph,
            enable=settings.enable,
            interface=tuple(settings.interface) if settings.interface is not None else None,
            leapsec=settings.leapsec,
            dnsresolv=settings.dnsresolv,
            ntpmaxpeers=settings.ntpmaxpeers,
            ntpmaxpoll=settings.ntpmaxpoll,
            ntpminpoll=settings.ntpminpoll,
            orphan=settings.orphan,
            serverauth=settings.serverauth,
            serverauthalgo=settings.serverauthalgo,
        )

    def identity(self) -> dict[str, CanonicalValue]:
        return dict(_IDENTITY)

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return {
            "logpeer": self.logpeer,
            "logsys": self.logsys,
            "clockstats": self.clockstats,
            "loopstats": self.loopstats,
            "peerstats": self.peerstats,
            "statsgraph": self.statsgraph,
            "enable": self.enable,
            "interface": list(self.interface) if self.interface is not None else None,
            "leapsec": self.leapsec,
            "dnsresolv": self.dnsresolv,
            "ntpmaxpeers": self.ntpmaxpeers,
            "ntpmaxpoll": self.ntpmaxpoll,
            "ntpminpoll": self.ntpminpoll,
            "orphan": self.orphan,
            "serverauth": self.serverauth,
            "serverauthalgo": self.serverauthalgo,
        }

    def raw_target_hint(self) -> dict[str, CanonicalValue]:
        return self.fingerprint()


class NtpSettingsObservabilityReadClient(Protocol):
    def get_ntp_settings(self) -> NtpSettings: ...
    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedNtpSettingsObservabilityExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: NtpSettingsStateV1
    appliance_target_digest: str


class NtpSettingsObservabilityAdapterV1:
    capability = Capability.NTP_SETTINGS_OBSERVABILITY_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(
        self, read_client: NtpSettingsObservabilityReadClient, natural_identity: CanonicalValue
    ) -> NtpSettingsStateV1:
        if natural_identity != _IDENTITY:
            raise PreparedExecutionIntentError("Semantic NTP settings identity is malformed.")
        return NtpSettingsStateV1.from_model(read_client.get_ntp_settings())

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
        before, after = self._state(pre).fingerprint(), self._state(post).fingerprint()
        normalized = self._intent(intent)
        requested = {field: normalized[field] for field in _ALLOWED_FIELDS}
        return fields_match(after, requested) and fields_equal(before, after, fields=_FORBIDDEN_FIELDS)

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        fingerprint = self._fingerprint(pre)
        return self._patch_from_values(fingerprint)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return self._fingerprint(pre) == self._state(post_rollback).fingerprint()

    @staticmethod
    def _patch_from_values(values: Mapping[str, CanonicalValue]) -> NtpSettingsObservabilityPatchV1:
        logpeer, logsys, clockstats, loopstats, peerstats, statsgraph = (
            values["logpeer"],
            values["logsys"],
            values["clockstats"],
            values["loopstats"],
            values["peerstats"],
            values["statsgraph"],
        )
        if (
            not isinstance(logpeer, bool)
            or not isinstance(logsys, bool)
            or not isinstance(clockstats, bool)
            or not isinstance(loopstats, bool)
            or not isinstance(peerstats, bool)
            or not isinstance(statsgraph, bool)
        ):
            raise PreparedExecutionIntentError("NTP settings observability values are malformed.")
        return NtpSettingsObservabilityPatchV1(
            logpeer=logpeer,
            logsys=logsys,
            clockstats=clockstats,
            loopstats=loopstats,
            peerstats=peerstats,
            statsgraph=statsgraph,
        )

    @staticmethod
    def _state(raw_target: object) -> NtpSettingsStateV1:
        if isinstance(raw_target, NtpSettingsStateV1):
            return raw_target
        if not isinstance(raw_target, dict) or set(raw_target) != {
            "logpeer",
            "logsys",
            "clockstats",
            "loopstats",
            "peerstats",
            "statsgraph",
            "enable",
            "interface",
            "leapsec",
            "dnsresolv",
            "ntpmaxpeers",
            "ntpmaxpoll",
            "ntpminpoll",
            "orphan",
            "serverauth",
            "serverauthalgo",
        }:
            raise PreparedExecutionIntentError("NTP settings target is malformed.")
        try:
            settings = NtpSettings.model_validate(raw_target, strict=True)
        except Exception:
            raise PreparedExecutionIntentError("NTP settings target is malformed.") from None
        return NtpSettingsStateV1.from_model(settings)

    @staticmethod
    def _fingerprint(value: object) -> dict[str, CanonicalValue]:
        if not isinstance(value, dict) or set(value) != set(NtpSettingsObservabilityAdapterV1._all_fields()):
            raise PreparedExecutionIntentError("NTP settings fingerprint is malformed.")
        return value

    @staticmethod
    def _all_fields() -> tuple[str, ...]:
        return _ALLOWED_FIELDS + _FORBIDDEN_FIELDS

    @staticmethod
    def _intent(value: object) -> dict[str, CanonicalValue]:
        expected = {"operation", "raw_target_hint", *_ALLOWED_FIELDS, "appliance_target_digest"}
        if not isinstance(value, dict) or set(value) != expected:
            raise PreparedExecutionIntentError("Protected NTP settings intent is malformed.")
        hint = value["raw_target_hint"]
        if (
            value["operation"] != SEMANTIC_UNIT
            or hint != _IDENTITY
            or not isinstance(value["appliance_target_digest"], str)
        ):
            raise PreparedExecutionIntentError("Protected NTP settings intent is malformed.")
        if any(not isinstance(value[field], bool) for field in _ALLOWED_FIELDS):
            raise PreparedExecutionIntentError("Protected NTP settings intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "appliance_target_digest": value["appliance_target_digest"],
            **{field: value[field] for field in _ALLOWED_FIELDS},
        }


class NtpSettingsObservabilityPreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(
        self, *, read_client: NtpSettingsObservabilityReadClient, configured_target: ConfiguredApplianceTargetV1
    ):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = NtpSettingsObservabilityAdapterV1()

    @property
    def adapter(self) -> NtpSettingsObservabilityAdapterV1:
        return self._adapter

    def prepare(self, request: NtpSettingsObservabilityChangeV1) -> PreparedNtpSettingsObservabilityExecutionV1:
        if not isinstance(request, NtpSettingsObservabilityChangeV1):
            raise PreparedExecutionIntentError("Expected NtpSettingsObservabilityChangeV1.")
        state = self._adapter.read_target(self._read_client, _IDENTITY)
        requested = {field: getattr(request, field) for field in _ALLOWED_FIELDS}
        current = {field: getattr(state, field) for field in _ALLOWED_FIELDS}
        if requested == current:
            raise PreparedExecutionIntentError("NTP settings observability change is a no-op.")
        appliance_digest = read_appliance_target_digest(self._read_client, self._configured_target)
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": dict(_IDENTITY),
            "appliance_target_digest": appliance_digest,
            **requested,
        }
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.NTP_SETTINGS_OBSERVABILITY_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedNtpSettingsObservabilityExecutionV1(prepared, state, appliance_digest)
