"""pfsense_get_status_wireguard_tunnels tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_tunnel_status import WireGuardTunnelStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[WireGuardTunnelStatus]]:
    def pfsense_get_status_wireguard_tunnels(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardTunnelStatus]:
        """List live WireGuard tunnel status: link state, traffic
        counters, and nested peer status. Private/preshared key
        material is never returned by this tool under any argument.
        Read-only.

        include_identifying_metadata: if True, includes literal peer
        endpoint/allowed-IP addresses nested under each tunnel.
        Defaults to False.

        limit: maximum number of tunnels to return (1-100, default
        100)."""
        return client.get_status_wireguard_tunnels(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_status_wireguard_tunnels
