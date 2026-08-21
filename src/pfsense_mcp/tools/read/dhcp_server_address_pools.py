"""pfsense_get_dhcp_server_address_pools tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_server_address_pool import DHCPServerAddressPool
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DHCPServerAddressPool]]:
    def pfsense_get_dhcp_server_address_pools(limit: int = 100) -> list[DHCPServerAddressPool]:
        """List DHCP server address pools (additional scopes) across
        all configured DHCP servers: range, gateway, DNS/NTP/WINS
        servers, and MAC allow/deny lists. Read-only.

        limit: maximum number of address pools to return (1-100,
        default 100)."""
        return client.get_dhcp_server_address_pools(limit=limit)

    return pfsense_get_dhcp_server_address_pools
