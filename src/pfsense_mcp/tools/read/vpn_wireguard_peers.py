"""pfsense_get_vpn_wireguard_peers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_peer import WireGuardPeer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[WireGuardPeer]]:
    def pfsense_get_vpn_wireguard_peers(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardPeer]:
        """List WireGuard peer configurations: enabled state, parent
        tunnel, listen port, description, persistent-keepalive
        interval, and public key. Requires pfSense-pkg-WireGuard.
        Read-only. Does not include the peer's pre-shared key or its
        allowed-IPs list (already exposed, redacted, via
        pfsense_get_status_wireguard_peers).

        include_identifying_metadata: if True, includes the peer's
        literal endpoint address. Defaults to False.

        limit: maximum number of peers to return (1-100, default
        100)."""
        return client.get_vpn_wireguard_peers(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_vpn_wireguard_peers
