"""Closed ADR-037 Batch 1 semantics for one configured NTP time server's
`prefer` flag only.

This module is inert: it registers no tool, endpoint, policy, capability or
runtime. It contains the product-specific request, authoritative preparer
and pure CapabilityAdapter projection for
`PATCH /api/v2/services/ntp/time_server`, exposing exactly one field
(`prefer`). Structurally mirrors `alias_description.py` -- the accepted W1
template for this shape of capability (existing-target update, natural
identity resolved from a collection, narrow field projection) -- adapted
for this operation's own target/field shape.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass
from typing import Protocol

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr, field_validator

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.ntp_time_server import NtpTimeServer
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync

from .alias_description import ConfiguredApplianceTargetV1
from .canonical import CanonicalValue
from .errors import PreparedExecutionIntentError
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget
from .write_adapter_support import read_appliance_target_digest

SEMANTIC_UNIT = "set_ntp_time_server_prefer_v1"
ENDPOINT_SYMBOL = "NTP_TIME_SERVER_PREFER"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "ntp-time-server-prefer-v1"
ROLLBACK_VERSION = "ntp-time-server-prefer-rollback-v1"

#: The live schema declares no uniqueness constraint on `timeserver`
#: (verified 2026-09-04 against the pinned OpenAPI schema) -- duplicates
#: are structurally possible. `read_target()` below fails closed on
#: anything other than exactly one match, exactly like
#: `AliasDescriptionAdapterV1.read_target()`.
_MAX_ENUMERATION = 100  # NTP_TIME_SERVERS_MAX_LIMIT
_NTP_TYPES = frozenset({"server", "pool", "peer"})


class NtpTimeServerPreferChangeV1(BaseModel):
    """The complete model-facing request: which configured time server
    (identified by its own `timeserver` string, never a caller-supplied
    numeric id -- the numeric `id` is a transport locator only, never an
    authorization identity, matching every other capability in this
    codebase), and the single boolean value to set."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    timeserver: StrictStr
    prefer: StrictBool

    @field_validator("timeserver")
    @classmethod
    def _valid_timeserver(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not normalized or len(normalized) > 255:
            raise ValueError("timeserver is invalid")
        return normalized


class NtpTimeServerPreferPatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing. Only `id` and `prefer`
    are ever sent -- `timeserver`/`type`/`noselect` are never included, so
    a PATCH under this capability can never touch them even if the
    caller-facing model somehow carried extra data (it cannot: `extra=
    "forbid"` above already rejects anything beyond `timeserver`/`prefer`)."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: StrictInt
    prefer: StrictBool


@dataclass(frozen=True, slots=True)
class NtpTimeServerStateV1:
    numeric_locator: int
    timeserver: str
    server_type: str
    prefer: bool
    noselect: bool

    @classmethod
    def from_model(cls, server: NtpTimeServer) -> NtpTimeServerStateV1:
        if (
            type(server.id) is not int
            or not 0 <= server.id <= 2_147_483_647
            or not isinstance(server.timeserver, str)
            or not server.timeserver
            or server.timeserver != unicodedata.normalize("NFC", server.timeserver)
            or server.type not in _NTP_TYPES
        ):
            raise PreparedExecutionIntentError("Authoritative NTP time-server state is incomplete or unsupported.")
        return cls(server.id, server.timeserver, server.type, server.prefer, server.noselect)

    def identity(self) -> dict[str, CanonicalValue]:
        return {"timeserver": self.timeserver}

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return {
            "timeserver": self.timeserver,
            "type": self.server_type,
            "prefer": self.prefer,
            "noselect": self.noselect,
        }

    def raw_target_hint(self) -> dict[str, CanonicalValue]:
        return {
            "timeserver": self.timeserver,
            "id": self.numeric_locator,
            "type": self.server_type,
            "prefer": self.prefer,
            "noselect": self.noselect,
        }


class NtpTimeServerPreferReadClient(Protocol):
    def get_ntp_time_servers(self, *, limit: int = 100) -> list[NtpTimeServer]: ...
    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...
    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedNtpTimeServerPreferExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: NtpTimeServerStateV1
    appliance_target_digest: str


class NtpTimeServerPreferAdapterV1:
    capability = Capability.NTP_TIME_SERVER_PREFER_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(
        self, read_client: NtpTimeServerPreferReadClient, natural_identity: CanonicalValue
    ) -> NtpTimeServerStateV1:
        if not isinstance(natural_identity, dict) or set(natural_identity) != {"timeserver"}:
            raise PreparedExecutionIntentError("Semantic NTP time-server identity is malformed.")
        timeserver = natural_identity["timeserver"]
        if not isinstance(timeserver, str) or not timeserver:
            raise PreparedExecutionIntentError("Semantic NTP time-server identity is malformed.")
        servers = read_client.get_ntp_time_servers(limit=_MAX_ENUMERATION)
        if len(servers) >= _MAX_ENUMERATION:
            raise PreparedExecutionIntentError("Complete authoritative NTP time-server enumeration cannot be proven.")
        matches = [NtpTimeServerStateV1.from_model(s) for s in servers if s.timeserver == timeserver]
        if len(matches) != 1:
            raise PreparedExecutionIntentError("Semantic NTP time-server target did not resolve exactly once.")
        return matches[0]

    def natural_identity(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).identity()

    def fingerprint(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).fingerprint()

    def transport_locator(self, raw_target: object) -> int:
        return self._state(raw_target).numeric_locator

    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel:
        normalized = self._intent(intent)
        prefer = normalized["prefer"]
        if not isinstance(prefer, bool):
            raise PreparedExecutionIntentError("Protected NTP time-server intent is malformed.")
        return NtpTimeServerPreferPatchV1(id=target.numeric_locator, prefer=prefer)

    def parse_response(self, raw_response: object) -> object:
        return {"accepted_status": getattr(raw_response, "status_code", None)}

    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool:
        before, after = self._state(pre), self._state(post)
        normalized = self._intent(intent)
        return (
            after.prefer == normalized["prefer"]
            and before.timeserver == after.timeserver
            and before.server_type == after.server_type
            and before.noselect == after.noselect
        )

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        fingerprint = self._fingerprint(pre)
        prefer = fingerprint["prefer"]
        if not isinstance(prefer, bool):
            raise PreparedExecutionIntentError("NTP time-server rollback prefer value is malformed.")
        return NtpTimeServerPreferPatchV1(id=target.numeric_locator, prefer=prefer)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return self._fingerprint(pre) == self._state(post_rollback).fingerprint()

    @staticmethod
    def _state(raw_target: object) -> NtpTimeServerStateV1:
        if isinstance(raw_target, NtpTimeServerStateV1):
            return raw_target
        if not isinstance(raw_target, dict) or set(raw_target) != {"timeserver", "id", "type", "prefer", "noselect"}:
            raise PreparedExecutionIntentError("NTP time-server target is malformed.")
        try:
            server = NtpTimeServer.model_validate(
                {
                    "id": raw_target["id"],
                    "timeserver": raw_target["timeserver"],
                    "type": raw_target["type"],
                    "prefer": raw_target["prefer"],
                    "noselect": raw_target["noselect"],
                },
                strict=True,
            )
        except Exception:
            raise PreparedExecutionIntentError("NTP time-server target is malformed.") from None
        return NtpTimeServerStateV1.from_model(server)

    @staticmethod
    def _fingerprint(value: object) -> dict[str, CanonicalValue]:
        if not isinstance(value, dict) or set(value) != {"timeserver", "type", "prefer", "noselect"}:
            raise PreparedExecutionIntentError("NTP time-server fingerprint is malformed.")
        timeserver, server_type, prefer, noselect = (
            value["timeserver"],
            value["type"],
            value["prefer"],
            value["noselect"],
        )
        if (
            not isinstance(timeserver, str)
            or not timeserver
            or server_type not in _NTP_TYPES
            or not isinstance(prefer, bool)
            or not isinstance(noselect, bool)
        ):
            raise PreparedExecutionIntentError("NTP time-server fingerprint is malformed.")
        return value

    @staticmethod
    def _intent(value: object) -> dict[str, CanonicalValue]:
        # `raw_target_hint` here is the MINIMAL identity hint `prepare()`
        # embedded in `normalized_mutation_intent` (`{"timeserver": ...}`)
        # -- distinct from the FULL state dict `NtpTimeServerStateV1.
        # raw_target_hint()` produces, which `WriteExecutionCoreV1`
        # substitutes into the top-level executor intent (used only for
        # `natural_identity()`/`fingerprint()` before this decrypted
        # intent is ever read). Conflating the two shapes here would be a
        # real bug, not a style choice -- this is the exact shape
        # `prepare()` below constructs and the encrypted `protected_intent`
        # therefore actually contains.
        expected = {"operation", "raw_target_hint", "prefer", "appliance_target_digest"}
        if not isinstance(value, dict) or set(value) != expected:
            raise PreparedExecutionIntentError("Protected NTP time-server intent is malformed.")
        hint = value["raw_target_hint"]
        if (
            value["operation"] != SEMANTIC_UNIT
            or not isinstance(hint, dict)
            or set(hint) != {"timeserver"}
            or not isinstance(hint["timeserver"], str)
            or not hint["timeserver"]
            or not isinstance(value["prefer"], bool)
            or not isinstance(value["appliance_target_digest"], str)
        ):
            raise PreparedExecutionIntentError("Protected NTP time-server intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "timeserver": hint["timeserver"],
            "prefer": value["prefer"],
            "appliance_target_digest": value["appliance_target_digest"],
        }


class NtpTimeServerPreferPreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(self, *, read_client: NtpTimeServerPreferReadClient, configured_target: ConfiguredApplianceTargetV1):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = NtpTimeServerPreferAdapterV1()

    @property
    def adapter(self) -> NtpTimeServerPreferAdapterV1:
        return self._adapter

    def prepare(self, request: NtpTimeServerPreferChangeV1) -> PreparedNtpTimeServerPreferExecutionV1:
        if not isinstance(request, NtpTimeServerPreferChangeV1):
            raise PreparedExecutionIntentError("Expected NtpTimeServerPreferChangeV1.")
        state = self._adapter.read_target(self._read_client, {"timeserver": request.timeserver})
        if state.prefer == request.prefer:
            raise PreparedExecutionIntentError("NTP time-server prefer change is a no-op.")
        appliance_digest = read_appliance_target_digest(self._read_client, self._configured_target)
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": {"timeserver": request.timeserver},
            "prefer": request.prefer,
            "appliance_target_digest": appliance_digest,
        }
        # raw_target_hint carries only the semantic identity here; the
        # executor never trusts its content (only its digest) -- the
        # authoritative re-read (adapter.read_target) is what actually
        # establishes pre/post state, exactly as executor.py's own
        # docstring states. A bare {"timeserver": ...} hint (rather than
        # the full raw_target_hint() dict) is intentionally sufficient:
        # execute()'s target_identity/target_precondition are derived from
        # adapter.natural_identity()/adapter.fingerprint() applied to this
        # hint, and natural_identity() only ever reads "timeserver".
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.NTP_TIME_SERVER_PREFER_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedNtpTimeServerPreferExecutionV1(prepared, state, appliance_digest)
