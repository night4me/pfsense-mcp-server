"""pfsense_get_routing_gateway_groups tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.routing_gateway_group import RoutingGatewayGroup
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[RoutingGatewayGroup]]:
    def pfsense_get_routing_gateway_groups(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RoutingGatewayGroup]:
        """List gateway groups: name, failover trigger, description,
        and prioritized member gateways. Read-only.

        include_identifying_metadata: if True, includes the literal
        gateway names and virtual IPs in each group's priority list.
        Defaults to False.

        limit: maximum number of gateway groups to return (1-100,
        default 100)."""
        return client.get_routing_gateway_groups(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_routing_gateway_groups
