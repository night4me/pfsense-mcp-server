"""pfsense_get_status_openvpn_server_connections tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.openvpn_server_connection_status import OpenVpnServerConnectionStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[OpenVpnServerConnectionStatus]]:
    def pfsense_get_status_openvpn_server_connections(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[OpenVpnServerConnectionStatus]:
        """List live, flat, all-servers OpenVPN client connection
        status: cipher, byte counters, and connect time. Read-only.

        include_identifying_metadata: if True, includes the literal
        client common name, username, and remote/virtual addresses.
        Defaults to False.

        limit: maximum number of connections to return (1-100, default
        100)."""
        return client.get_status_openvpn_server_connections(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_status_openvpn_server_connections
