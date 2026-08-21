"""pfsense_get_dhcp_server_custom_options tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_server_custom_option import DHCPServerCustomOption
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DHCPServerCustomOption]]:
    def pfsense_get_dhcp_server_custom_options(limit: int = 100) -> list[DHCPServerCustomOption]:
        """List DHCP server custom options across all configured DHCP
        servers: option number, type, and value. Read-only.

        limit: maximum number of custom options to return (1-100,
        default 100)."""
        return client.get_dhcp_server_custom_options(limit=limit)

    return pfsense_get_dhcp_server_custom_options
