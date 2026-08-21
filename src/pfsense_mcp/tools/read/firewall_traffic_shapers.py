"""pfsense_get_firewall_traffic_shapers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.traffic_shaper import TrafficShaper
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[TrafficShaper]]:
    def pfsense_get_firewall_traffic_shapers(limit: int = 100) -> list[TrafficShaper]:
        """List traffic shapers: interface, scheduler algorithm,
        bandwidth, and child queues. Read-only.

        limit: maximum number of traffic shapers to return (1-100,
        default 100)."""
        return client.get_firewall_traffic_shapers(limit=limit)

    return pfsense_get_firewall_traffic_shapers
