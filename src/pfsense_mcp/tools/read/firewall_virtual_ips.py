"""pfsense_get_firewall_virtual_ips tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_virtual_ip import FirewallVirtualIp
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallVirtualIp]]:
    def pfsense_get_firewall_virtual_ips(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallVirtualIp]:
        """List pfSense virtual IPs (CARP/IP alias/proxy ARP/other):
        interface, type, mode, and CARP status. The CARP shared secret
        is never returned by this tool under any argument. Read-only.

        include_identifying_metadata: if True, includes the literal
        virtual IP address and CARP peer address. Defaults to False.

        limit: maximum number of virtual IPs to return (1-100, default
        100)."""
        return client.get_firewall_virtual_ips(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_firewall_virtual_ips
