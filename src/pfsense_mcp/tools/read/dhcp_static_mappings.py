"""pfsense_get_dhcp_static_mappings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_static_mapping import DhcpStaticMapping
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DhcpStaticMapping]]:
    def pfsense_get_dhcp_static_mappings(limit: int = 100) -> list[DhcpStaticMapping]:
        """List pfSense DHCP static mappings: MAC, IP, hostname,
        description, parent interface, and per-mapping DHCP option
        overrides. Read-only.

        limit: maximum number of mappings to return (1-100, default
        100)."""
        return client.get_dhcp_static_mappings(limit=limit)

    return pfsense_get_dhcp_static_mappings
