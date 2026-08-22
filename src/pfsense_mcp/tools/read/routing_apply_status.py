"""pfsense_get_routing_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.routing_apply import RoutingApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], RoutingApply]:
    def pfsense_get_routing_apply_status() -> RoutingApply:
        """Get pfSense pending routing change status: whether all
        routing changes are applied. Read-only. Contains no
        identifying metadata."""
        return client.get_routing_apply_status()

    return pfsense_get_routing_apply_status
