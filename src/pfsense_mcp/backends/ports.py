"""Typed, capability-specific READ port definitions (ADR-030, "option C").

Each `Protocol` below is scoped to exactly one existing domain model,
matching this project's own established one-model-per-tool convention
(see `pfsense_client.py`). Deliberately NOT a generic
`request(method, path)`-shaped interface -- this project's transport
and write layers are exactly two reviewed chokepoints
(`RestApiClient`, `WriteApiClient`; see `scripts/get_only_check.py`'s
allow-list), and a generic dispatch surface here would create a third,
unreviewed one.

Scoped to the 3 highest-confidence ADAPTABLE rows in
`docs/NEXUS_COMPATIBILITY_MATRIX.md` (gateway status, firewall
aliases, system packages) rather than all 32 ADAPTABLE tools --
ADR-030's own "avoid unnecessary rewrite" / "smallest safe
abstraction" reasoning: implementing every port before any concrete
backend exists to satisfy them is premature. Add more as, and only
as, a real backend implementation is ready to satisfy them honestly.

No implementation of these Protocols exists in this repository. A
class satisfies a Protocol structurally (PEP 544) -- nothing about
defining these interfaces requires, authorizes, or wires in any
concrete reader.
"""

from __future__ import annotations

from typing import Protocol

from ..models.firewall_alias import FirewallAlias
from ..models.gateways import GatewayStatus
from ..models.system_package import SystemPackage


class GatewayStatusReader(Protocol):
    def get_gateway_status(self) -> list[GatewayStatus]: ...


class FirewallAliasReader(Protocol):
    def get_firewall_aliases(self) -> list[FirewallAlias]: ...


class SystemPackageReader(Protocol):
    def get_system_packages(self) -> list[SystemPackage]: ...
