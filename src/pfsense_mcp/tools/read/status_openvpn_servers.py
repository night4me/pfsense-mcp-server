"""pfsense_get_status_openvpn_servers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_server_status import OpenVpnServerStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnServerStatus]]:
    def pfsense_get_status_openvpn_servers(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerStatus]:
        """List live OpenVPN server status: mode, port, and nested
        connection/route status. Read-only.

        include_identifying_metadata: if True, includes literal client
        identity/address fields nested under each server's connections
        and routes. Defaults to False.

        limit: maximum number of servers to return (1-100, default
        100)."""
        return client.get_status_openvpn_servers(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_status_openvpn_servers
