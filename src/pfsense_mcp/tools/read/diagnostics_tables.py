"""pfsense_get_diagnostics_tables tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.diagnostics_table import DiagnosticsTable
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DiagnosticsTable]]:
    def pfsense_get_diagnostics_tables(limit: int = 100) -> list[DiagnosticsTable]:
        """List pfSense pf firewall tables (name and member IP/CIDR
        entries), e.g. bogons, DHCP pools, and network aliases.
        Read-only."""
        return client.get_diagnostics_tables(limit=limit)

    return pfsense_get_diagnostics_tables
