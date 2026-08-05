"""pfsense_get_firewall_nat_port_forwards tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_nat_port_forward import FirewallNatPortForward
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallNatPortForward]]:
    def pfsense_get_firewall_nat_port_forwards(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallNatPortForward]:
        """List pfSense NAT port-forward rules: interface, protocol,
        external/internal ports, and target. Read-only.

        include_identifying_metadata: if True, includes the literal
        source/destination/target addresses and rule author. Defaults
        to False.

        limit: maximum number of rules to return (1-500, default
        100)."""
        return client.get_firewall_nat_port_forwards(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_firewall_nat_port_forwards
