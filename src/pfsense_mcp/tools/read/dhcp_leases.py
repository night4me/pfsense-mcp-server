"""pfsense_get_dhcp_leases tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_lease import DhcpLease
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DhcpLease]]:
    def pfsense_get_dhcp_leases(limit: int = 100) -> list[DhcpLease]:
        """List pfSense DHCP leases: IP, MAC, hostname, description,
        interface, lease window, and online/active status. Read-only.

        limit: maximum number of leases to return (1-100, default
        100)."""
        return client.get_dhcp_leases(limit=limit)

    return pfsense_get_dhcp_leases
