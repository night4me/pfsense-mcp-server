"""pfsense_get_vpn_wireguard_tunnel_addresses tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_tunnel_address import WireGuardTunnelAddress
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[WireGuardTunnelAddress]]:
    def pfsense_get_vpn_wireguard_tunnel_addresses(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardTunnelAddress]:
        """List WireGuard tunnel address assignments: description and
        (optionally) the tunnel's own address/subnet mask. Read-only.
        Requires pfSense-pkg-WireGuard.

        include_identifying_metadata: if True, includes the literal
        address/mask. Defaults to False.

        limit: maximum number of tunnel addresses to return (1-100,
        default 100)."""
        return client.get_vpn_wireguard_tunnel_addresses(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_vpn_wireguard_tunnel_addresses
