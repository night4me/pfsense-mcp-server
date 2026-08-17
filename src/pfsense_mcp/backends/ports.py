"""Typed, capability-specific READ port definitions (ADR-030, "option C").

Each `Protocol` below is scoped to exactly one existing domain model,
matching this project's own established one-model-per-tool convention
(see `pfsense_client.py`). Deliberately NOT a generic
`request(method, path)`-shaped interface -- this project's transport
and write layers are exactly two reviewed chokepoints
(`RestApiClient`, `WriteApiClient`; see `scripts/get_only_check.py`'s
allow-list), and a generic dispatch surface here would create a third,
unreviewed one.

Scoped to the highest-confidence rows in
`docs/NEXUS_COMPATIBILITY_MATRIX.md` (gateway status, firewall
aliases, system packages, CARP status) rather than all 30 ADAPTABLE
tools -- ADR-030's own "avoid unnecessary rewrite" / "smallest safe
abstraction" reasoning: implementing every port before any concrete
backend exists to satisfy them is premature. Add more as, and only
as, a real backend implementation is ready to satisfy them honestly.

`CarpStatusReader` (Phase D, 2026-08-17) is the first of these with a
concrete implementation -- see `nexus/carp_status.py` -- because it is
the first capability whose field-by-field diff against Nexus actually
passed the "complete, deterministic, semantically equivalent,
fail-closed" bar (gateway status and firewall aliases did not; both
remain unimplemented, PARTIAL). The other three Protocols here still
have no implementation.
"""

from __future__ import annotations

from typing import Protocol

from ..models.carp_status import CarpStatus
from ..models.firewall_alias import FirewallAlias
from ..models.gateways import GatewayStatus
from ..models.system_package import SystemPackage


class GatewayStatusReader(Protocol):
    def get_gateway_status(self) -> list[GatewayStatus]: ...


class FirewallAliasReader(Protocol):
    def get_firewall_aliases(self) -> list[FirewallAlias]: ...


class SystemPackageReader(Protocol):
    def get_system_packages(self) -> list[SystemPackage]: ...


class CarpStatusReader(Protocol):
    def get_carp_status(self) -> CarpStatus: ...
