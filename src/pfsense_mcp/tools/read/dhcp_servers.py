"""pfsense_get_dhcp_servers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_server import DhcpServer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DhcpServer]]:
    def pfsense_get_dhcp_servers(limit: int = 100) -> list[DhcpServer]:
        """List pfSense DHCP server (scope) configuration per
        interface: address range, gateway, DNS/NTP/WINS servers,
        MAC allow/deny lists, address pools, custom options, and
        embedded static mappings. Read-only.

        limit: maximum number of DHCP servers to return (1-100,
        default 100)."""
        return client.get_dhcp_servers(limit=limit)

    return pfsense_get_dhcp_servers
