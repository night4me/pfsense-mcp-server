"""pfsense_get_firewall_nat_one_to_one_mappings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_nat_one_to_one_mapping import FirewallNatOneToOneMapping
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallNatOneToOneMapping]]:
    def pfsense_get_firewall_nat_one_to_one_mappings(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatOneToOneMapping]:
        """List pfSense 1:1 NAT mappings: interface, protocol family,
        NAT reflection, and bi-directional NAT state. Read-only.

        include_identifying_metadata: if True, includes the literal
        external/source/destination addresses. Defaults to False.

        limit: maximum number of mappings to return (1-500, default
        100)."""
        return client.get_firewall_nat_one_to_one_mappings(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_firewall_nat_one_to_one_mappings
