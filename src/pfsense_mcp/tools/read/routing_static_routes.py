"""pfsense_get_routing_static_routes tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.routing_static_route import RoutingStaticRoute
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[RoutingStaticRoute]]:
    def pfsense_get_routing_static_routes(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[RoutingStaticRoute]:
        """List pfSense static routes: destination network, gateway,
        and description. Read-only.

        include_identifying_metadata: if True, includes the literal
        network/gateway addresses. Defaults to False.

        limit: maximum number of static routes to return (1-100,
        default 100)."""
        return client.get_routing_static_routes(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_routing_static_routes
