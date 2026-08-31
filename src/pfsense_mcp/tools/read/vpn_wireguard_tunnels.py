"""pfsense_get_vpn_wireguard_tunnels tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_tunnel import WireGuardTunnel
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[WireGuardTunnel]]:
    def pfsense_get_vpn_wireguard_tunnels(limit: int = 100) -> list[WireGuardTunnel]:
        """List WireGuard tunnel configurations: name, enabled state,
        description, listen port, public key, and MTU. Requires
        pfSense-pkg-WireGuard. Read-only. Does not include the
        tunnel's private key or its embedded addresses list (use
        pfsense_get_vpn_wireguard_tunnel_addresses for the latter).

        limit: maximum number of tunnels to return (1-100, default
        100)."""
        return client.get_vpn_wireguard_tunnels(limit=limit)

    return pfsense_get_vpn_wireguard_tunnels
