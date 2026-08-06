"""pfsense_get_firewall_traffic_shaper_limiters tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_traffic_shaper_limiter import FirewallTrafficShaperLimiter
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallTrafficShaperLimiter]]:
    def pfsense_get_firewall_traffic_shaper_limiters(limit: int = 100) -> list[FirewallTrafficShaperLimiter]:
        """List pfSense firewall traffic shaper limiters: bandwidth
        caps, scheduler algorithm, and queue configuration.
        Read-only."""
        return client.get_firewall_traffic_shaper_limiters(limit=limit)

    return pfsense_get_firewall_traffic_shaper_limiters
