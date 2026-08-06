"""Shared write-domain types. Pure data, no behavior, no imports of
write_api_client/recovery/rollback — every other write module depends
on this one, not the other way around.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from .capabilities import Capability


class ContractStatus(str, Enum):
    OPEN = "open"
    COMMITTED = "committed"
    ROLLED_BACK = "rolled_back"
    EXPIRED = "expired"


@dataclass(frozen=True)
class MutationPlan:
    capability: Capability
    endpoint_symbol: str  # a WriteEndpoints attribute name, looked up by string
    http_method: str  # "POST" | "PUT" | "PATCH" | "DELETE"
    payload: dict[str, Any]
    description: str


@dataclass(frozen=True)
class DryRunResult:
    allowed: bool
    reasons: tuple[str, ...]
    predicted_diff: dict[str, Any] | None


@dataclass(frozen=True)
class ExecutionResult:
    contract_id: str
    status_code: int
    committed_at_utc: str  # ISO 8601, UTC


@dataclass(frozen=True)
class RollbackResult:
    contract_id: str
    success: bool
    detail: str
