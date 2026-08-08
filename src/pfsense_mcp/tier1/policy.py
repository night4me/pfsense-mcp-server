"""Exact capability/endpoint/method policy for future Tier 1 execution."""

from __future__ import annotations

import re
from dataclasses import dataclass

from pfsense_mcp.capabilities import Capability

from .errors import MutationPolicyError

_ENDPOINT_SYMBOL = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True, order=True)
class MutationRule:
    capability: Capability
    endpoint_symbol: str
    http_method: str

    def __post_init__(self) -> None:
        if not self.capability.name.endswith("_WRITE"):
            raise MutationPolicyError("Tier 1 policy rule requires a WRITE capability.")
        if not _ENDPOINT_SYMBOL.fullmatch(self.endpoint_symbol):
            raise MutationPolicyError("Tier 1 policy endpoint symbol is invalid.")
        if self.http_method not in _MUTATING_METHODS:
            raise MutationPolicyError("Tier 1 policy HTTP method is not mutating.")


@dataclass(frozen=True)
class MutationPolicy:
    rules: frozenset[MutationRule]

    def __post_init__(self) -> None:
        if not isinstance(self.rules, frozenset):
            raise MutationPolicyError("Tier 1 policy rules must be immutable.")

    def authorize(self, *, capability: Capability, endpoint_symbol: str, http_method: str) -> None:
        requested = MutationRule(capability, endpoint_symbol, http_method)
        if requested not in self.rules:
            raise MutationPolicyError("Mutation is not authorized by the exact Tier 1 policy.")


INACTIVE_TIER1_POLICY = MutationPolicy(frozenset())
