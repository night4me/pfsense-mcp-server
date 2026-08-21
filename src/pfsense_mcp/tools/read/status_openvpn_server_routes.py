"""pfsense_get_status_openvpn_server_routes tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_server_route_status import OpenVpnServerRouteStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnServerRouteStatus]]:
    def pfsense_get_status_openvpn_server_routes(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerRouteStatus]:
        """List live, flat, all-servers OpenVPN client route status.
        Read-only.

        include_identifying_metadata: if True, includes the literal
        client common name and remote/virtual addresses. Defaults to
        False.

        limit: maximum number of routes to return (1-100, default
        100)."""
        return client.get_status_openvpn_server_routes(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_status_openvpn_server_routes
