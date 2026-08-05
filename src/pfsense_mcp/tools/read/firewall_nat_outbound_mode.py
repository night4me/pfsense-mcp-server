"""pfsense_get_firewall_nat_outbound_mode tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_nat_outbound_mode import FirewallNatOutboundMode
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., FirewallNatOutboundMode]:
    def pfsense_get_firewall_nat_outbound_mode() -> FirewallNatOutboundMode:
        """Get pfSense's outbound NAT mode: automatic, hybrid,
        advanced, or disabled. Read-only."""
        return client.get_firewall_nat_outbound_mode()

    return pfsense_get_firewall_nat_outbound_mode
