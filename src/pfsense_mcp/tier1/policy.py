"""Exact capability/endpoint/method policy for future Tier 1 execution."""

from __future__ import annotations

from dataclasses import dataclass

from pfsense_mcp.capabilities import Capability

from .errors import MutationPolicyError


@dataclass(frozen=True, order=True)
class MutationRule:
    capability: Capability
    endpoint_symbol: str
    http_method: str


@dataclass(frozen=True)
class MutationPolicy:
    rules: frozenset[MutationRule]

    def authorize(self, *, capability: Capability, endpoint_symbol: str, http_method: str) -> None:
        requested = MutationRule(capability, endpoint_symbol, http_method)
        if requested not in self.rules:
            raise MutationPolicyError("Mutation is not authorized by the exact Tier 1 policy.")


INACTIVE_TIER1_POLICY = MutationPolicy(frozenset())
