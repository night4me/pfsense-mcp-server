"""Value-free audit event model for future Tier 1 execution."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime

from pfsense_mcp.capabilities import Capability

from .state_machine import RecoveryState

_SAFE_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_SAFE_CLASS = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
_HEX_64 = re.compile(r"[0-9a-f]{64}")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Tier1AuditEvent:
    timestamp: datetime
    event_id: str
    contract_id: str
    operation_id: str
    capability: Capability
    endpoint_symbol: str
    http_method: str
    target_identity_digest: str
    intent_digest: str
    outcome: str
    previous_state: RecoveryState | None = None
    current_state: RecoveryState | None = None
    failure_class: str | None = None
    exception_class: str | None = None

    def __post_init__(self) -> None:
        tokens = (
            self.event_id,
            self.contract_id,
            self.operation_id,
            self.endpoint_symbol,
            self.outcome,
        )
        optional_tokens = tuple(value for value in (self.failure_class,) if value is not None)
        if self.timestamp.tzinfo is None:
            raise ValueError("Tier 1 audit timestamp must be timezone-aware.")
        if not all(_SAFE_TOKEN.fullmatch(value) for value in (*tokens, *optional_tokens)):
            raise ValueError("Tier 1 audit metadata contains an unsafe token.")
        if not self.capability.name.endswith("_WRITE") or self.http_method not in _MUTATING_METHODS:
            raise ValueError("Tier 1 audit authority metadata is invalid.")
        if not _HEX_64.fullmatch(self.target_identity_digest) or not _HEX_64.fullmatch(self.intent_digest):
            raise ValueError("Tier 1 audit digest metadata is invalid.")
        if self.exception_class is not None and not _SAFE_CLASS.fullmatch(self.exception_class):
            raise ValueError("Exception class is not safe for audit serialization.")

    def to_json(self) -> str:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        payload["capability"] = self.capability.name
        payload["previous_state"] = self.previous_state.value if self.previous_state else None
        payload["current_state"] = self.current_state.value if self.current_state else None
        return json.dumps(payload, sort_keys=True, separators=(",", ":"))
