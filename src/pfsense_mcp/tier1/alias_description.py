"""Closed first-WRITE semantics for one existing alias description.

This module is inert: it registers no tool, endpoint, policy, capability or
runtime.  It contains the product-specific request, authoritative preparer and
pure CapabilityAdapter projection accepted by ADR-025/026.
"""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Protocol
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, StrictBool, StrictInt, StrictStr, field_validator

from pfsense_mcp.capabilities import Capability
from pfsense_mcp.models.firewall_alias import FirewallAlias
from pfsense_mcp.models.system import SystemStatus
from pfsense_mcp.models.system_ha_sync import SystemHaSync
from pfsense_mcp.tls import TLSMode

from .canonical import CanonicalValue, DigestPurpose, digest_value
from .errors import PreparedExecutionIntentError
from .prepared_execution_intent import PREPARED_EXECUTION_INTENT_SCHEMA_VERSION, PreparedExecutionIntentV1
from .transport_target import ResolvedTransportTarget

SEMANTIC_UNIT = "set_firewall_alias_description_v1"
ENDPOINT_SYMBOL = "FIREWALL_ALIAS_DESCRIPTION"
HTTP_METHOD = "PATCH"
ADAPTER_VERSION = "firewall-alias-description-v1"
ROLLBACK_VERSION = "firewall-alias-description-rollback-v1"

_ALIAS_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_]{0,31}")
_ALIAS_TYPES = frozenset({"host", "network", "port"})
_HEX_64 = re.compile(r"[0-9a-f]{64}")


def _normalize_description(value: str) -> str:
    normalized = unicodedata.normalize("NFC", value)
    if len(normalized) > 1024:
        raise ValueError("description exceeds the evidenced 1024-character boundary")
    if any(character in {"\x00", "\x01"} or 0xD800 <= ord(character) <= 0xDFFF for character in normalized):
        raise ValueError("description contains an unsupported control or Unicode value")
    return normalized


class AliasDescriptionChangeV1(BaseModel):
    """The complete model-facing first-WRITE request: exactly two fields."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    alias_name: StrictStr
    description: StrictStr

    @field_validator("alias_name")
    @classmethod
    def _valid_alias_name(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value)
        if not _ALIAS_NAME.fullmatch(normalized):
            raise ValueError("alias_name is invalid")
        return normalized

    @field_validator("description")
    @classmethod
    def _valid_description(cls, value: str) -> str:
        return _normalize_description(value)


class AliasDescriptionPatchV1(BaseModel):
    """Exact sealed PATCH body; never model-facing."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    id: StrictInt
    descr: StrictStr
    apply: StrictBool = False


@dataclass(frozen=True, slots=True)
class AliasStateV1:
    name: str
    numeric_locator: int
    alias_type: str
    descr: str
    address: tuple[str, ...]
    detail: tuple[str, ...]

    @classmethod
    def from_model(cls, alias: FirewallAlias) -> AliasStateV1:
        if (
            alias.name != unicodedata.normalize("NFC", alias.name)
            or not _ALIAS_NAME.fullmatch(alias.name)
            or alias.type not in _ALIAS_TYPES
            or alias.address is None
            or alias.detail is None
            or len(alias.address) != len(alias.detail)
            or type(alias.id) is not int
            or not 0 <= alias.id <= 2_147_483_647
        ):
            raise PreparedExecutionIntentError("Authoritative alias state is incomplete or unsupported.")
        values = (alias.descr, *alias.address, *alias.detail)
        if any(not isinstance(item, str) or item != unicodedata.normalize("NFC", item) for item in values):
            raise PreparedExecutionIntentError("Authoritative alias state is not canonical.")
        return cls(alias.name, alias.id, alias.type, alias.descr, tuple(alias.address), tuple(alias.detail))

    def identity(self) -> dict[str, CanonicalValue]:
        return {"alias_name": self.name}

    def fingerprint(self) -> dict[str, CanonicalValue]:
        return {
            "name": self.name,
            "type": self.alias_type,
            "descr": self.descr,
            "address": list(self.address),
            "detail": list(self.detail),
        }


@dataclass(frozen=True, slots=True)
class ConfiguredApplianceTargetV1:
    """Non-model-facing configured TLS target facts used in the binding."""

    base_url: str
    tls_mode: TLSMode
    ca_certificate_digest: str | None = None

    def __post_init__(self) -> None:
        try:
            parsed = urlsplit(self.base_url)
            parsed_port = parsed.port
        except ValueError:
            raise PreparedExecutionIntentError("Configured appliance TLS target is invalid.") from None
        normalized = f"https://{parsed.netloc}"
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
            or normalized != self.base_url
            or (parsed_port is not None and not 1 <= parsed_port <= 65_535)
            or self.tls_mode is TLSMode.INSECURE
        ):
            raise PreparedExecutionIntentError("Configured appliance TLS target is invalid.")
        if (self.tls_mode is TLSMode.AUTO) != (self.ca_certificate_digest is not None):
            raise PreparedExecutionIntentError("Configured appliance CA binding is invalid.")
        if self.ca_certificate_digest is not None and not _HEX_64.fullmatch(self.ca_certificate_digest):
            raise PreparedExecutionIntentError("Configured appliance CA binding is invalid.")


class AliasDescriptionReadClient(Protocol):
    def get_firewall_aliases(
        self, *, include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]: ...

    def get_system_status(self, *, include_identifying_metadata: bool = False) -> SystemStatus: ...

    def get_system_hasync(self, *, include_identifying_metadata: bool = False) -> SystemHaSync: ...


@dataclass(frozen=True, slots=True)
class PreparedAliasDescriptionExecutionV1:
    intent: PreparedExecutionIntentV1
    authoritative_a: AliasStateV1
    appliance_target_digest: str


class AliasDescriptionAdapterV1:
    capability = Capability.ALIAS_WRITE
    endpoint_symbol = ENDPOINT_SYMBOL
    http_method = HTTP_METHOD

    def read_target(self, read_client: AliasDescriptionReadClient, natural_identity: CanonicalValue) -> AliasStateV1:
        if not isinstance(natural_identity, dict) or set(natural_identity) != {"alias_name"}:
            raise PreparedExecutionIntentError("Semantic alias identity is malformed.")
        name = natural_identity["alias_name"]
        if not isinstance(name, str) or not _ALIAS_NAME.fullmatch(name):
            raise PreparedExecutionIntentError("Semantic alias identity is malformed.")
        aliases = read_client.get_firewall_aliases(include_identifying_metadata=True, limit=500)
        if len(aliases) >= 500:
            raise PreparedExecutionIntentError("Complete authoritative alias enumeration cannot be proven.")
        matches = [AliasStateV1.from_model(alias) for alias in aliases if alias.name == name]
        if len(matches) != 1:
            raise PreparedExecutionIntentError("Semantic alias target did not resolve exactly once.")
        return matches[0]

    def natural_identity(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).identity()

    def fingerprint(self, raw_target: object) -> CanonicalValue:
        return self._state(raw_target).fingerprint()

    def transport_locator(self, raw_target: object) -> int:
        return self._state(raw_target).numeric_locator

    def build_request(self, intent: object, target: ResolvedTransportTarget) -> BaseModel:
        normalized = self._intent(intent)
        return AliasDescriptionPatchV1(id=target.numeric_locator, descr=normalized["new_description"], apply=False)

    def parse_response(self, raw_response: object) -> object:
        return {"accepted_status": getattr(raw_response, "status_code", None)}

    def is_semantically_verified(self, pre: object, post: object, intent: object) -> bool:
        before, after = self._state(pre), self._state(post)
        normalized = self._intent(intent)
        return (
            after.descr == normalized["new_description"]
            and before.name == after.name
            and before.alias_type == after.alias_type
            and before.address == after.address
            and before.detail == after.detail
        )

    def build_rollback_request(self, pre: object, target: ResolvedTransportTarget) -> BaseModel:
        fingerprint = self._fingerprint(pre)
        description = fingerprint["descr"]
        if not isinstance(description, str):
            raise PreparedExecutionIntentError("Alias rollback description is malformed.")
        return AliasDescriptionPatchV1(id=target.numeric_locator, descr=description, apply=False)

    def is_rollback_verified(self, pre: object, post_rollback: object) -> bool:
        return self._fingerprint(pre) == self._state(post_rollback).fingerprint()

    @staticmethod
    def _state(raw_target: object) -> AliasStateV1:
        if isinstance(raw_target, AliasStateV1):
            return raw_target
        if not isinstance(raw_target, dict) or set(raw_target) != {"name", "id", "type", "descr", "address", "detail"}:
            raise PreparedExecutionIntentError("Alias target is malformed.")
        try:
            alias = FirewallAlias.model_validate(raw_target, strict=True)
        except Exception:
            raise PreparedExecutionIntentError("Alias target is malformed.") from None
        return AliasStateV1.from_model(alias)

    @staticmethod
    def _fingerprint(value: object) -> dict[str, CanonicalValue]:
        if not isinstance(value, dict) or set(value) != {"name", "type", "descr", "address", "detail"}:
            raise PreparedExecutionIntentError("Alias fingerprint is malformed.")
        name, alias_type, description = value["name"], value["type"], value["descr"]
        address, detail = value["address"], value["detail"]
        if (
            not isinstance(name, str)
            or not _ALIAS_NAME.fullmatch(name)
            or alias_type not in _ALIAS_TYPES
            or not isinstance(description, str)
            or not isinstance(address, list)
            or not isinstance(detail, list)
            or len(address) != len(detail)
            or not all(isinstance(item, str) for item in (*address, *detail))
            or any(item != unicodedata.normalize("NFC", item) for item in (name, description, *address, *detail))
        ):
            raise PreparedExecutionIntentError("Alias fingerprint is malformed.")
        return value

    @staticmethod
    def _intent(value: object) -> dict[str, str]:
        expected = {"operation", "raw_target_hint", "new_description", "appliance_target_digest"}
        if not isinstance(value, dict) or set(value) != expected:
            raise PreparedExecutionIntentError("Protected alias-description intent is malformed.")
        hint = value["raw_target_hint"]
        if (
            value["operation"] != SEMANTIC_UNIT
            or not isinstance(hint, dict)
            or set(hint) != {"alias_name"}
            or not isinstance(hint["alias_name"], str)
            or not _ALIAS_NAME.fullmatch(hint["alias_name"])
            or not isinstance(value["new_description"], str)
            or _normalize_description(value["new_description"]) != value["new_description"]
            or not isinstance(value["appliance_target_digest"], str)
            or not _HEX_64.fullmatch(value["appliance_target_digest"])
        ):
            raise PreparedExecutionIntentError("Protected alias-description intent is malformed.")
        return {
            "operation": SEMANTIC_UNIT,
            "alias_name": hint["alias_name"],
            "new_description": value["new_description"],
            "appliance_target_digest": value["appliance_target_digest"],
        }


class AliasDescriptionPreparerV1:
    """Fresh-read-only preparation for the fixed semantic unit."""

    def __init__(self, *, read_client: AliasDescriptionReadClient, configured_target: ConfiguredApplianceTargetV1):
        self._read_client = read_client
        self._configured_target = configured_target
        self._adapter = AliasDescriptionAdapterV1()

    @property
    def adapter(self) -> AliasDescriptionAdapterV1:
        return self._adapter

    def prepare(self, request: AliasDescriptionChangeV1) -> PreparedAliasDescriptionExecutionV1:
        if not isinstance(request, AliasDescriptionChangeV1):
            raise PreparedExecutionIntentError("Expected AliasDescriptionChangeV1.")
        state = self._adapter.read_target(self._read_client, {"alias_name": request.alias_name})
        if state.descr == request.description:
            raise PreparedExecutionIntentError("Alias description change is a no-op.")
        appliance_digest = self._read_appliance_target_digest()
        normalized_intent: dict[str, CanonicalValue] = {
            "operation": SEMANTIC_UNIT,
            "raw_target_hint": {"alias_name": request.alias_name},
            "new_description": request.description,
            "appliance_target_digest": appliance_digest,
        }
        prepared = PreparedExecutionIntentV1(
            schema_version=PREPARED_EXECUTION_INTENT_SCHEMA_VERSION,
            capability=Capability.ALIAS_WRITE,
            endpoint_symbol=ENDPOINT_SYMBOL,
            http_method=HTTP_METHOD,
            adapter_version=ADAPTER_VERSION,
            resource_target=state.identity(),
            target_precondition=state.fingerprint(),
            normalized_mutation_intent=normalized_intent,
            rollback_snapshot=state.fingerprint(),
            rollback_plan_version=ROLLBACK_VERSION,
        )
        return PreparedAliasDescriptionExecutionV1(prepared, state, appliance_digest)

    def _read_appliance_target_digest(self) -> str:
        status = self._read_client.get_system_status(include_identifying_metadata=True)
        identity_kind = "netgate_id"
        identity = status.netgate_id
        if not identity:
            identity_kind = "pfhostid"
            identity = self._read_client.get_system_hasync(include_identifying_metadata=True).pfhostid
        if not isinstance(identity, str) or not identity:
            raise PreparedExecutionIntentError("Stable appliance identity is unavailable.")
        return digest_value(
            DigestPurpose.TARGET_IDENTITY,
            {
                "configured_base_url": self._configured_target.base_url,
                "tls_mode": self._configured_target.tls_mode.value,
                "ca_certificate_digest": self._configured_target.ca_certificate_digest,
                "installation_identity_kind": identity_kind,
                "installation_identity": identity,
            },
            context=("configured-pfsense-appliance-v1",),
        )
