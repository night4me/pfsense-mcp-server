"""pfsense_get_firewall_nat_outbound_mappings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_nat_outbound_mapping import FirewallNatOutboundMapping
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallNatOutboundMapping]]:
    def pfsense_get_firewall_nat_outbound_mappings(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatOutboundMapping]:
        """List pfSense outbound NAT mappings: interface, protocol,
        NAT port behavior, and pool options. Read-only.

        include_identifying_metadata: if True, includes the literal
        source/destination/target addresses. Defaults to False.

        limit: maximum number of mappings to return (1-500, default
        100)."""
        return client.get_firewall_nat_outbound_mappings(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_firewall_nat_outbound_mappings
