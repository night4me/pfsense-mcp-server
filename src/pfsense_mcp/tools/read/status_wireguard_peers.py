"""pfsense_get_status_wireguard_peers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_peer_status import WireGuardPeerStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[WireGuardPeerStatus]]:
    def pfsense_get_status_wireguard_peers(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[WireGuardPeerStatus]:
        """List live WireGuard peer status: handshake time, traffic
        counters, and public key. The preshared key is never returned
        by this tool under any argument. Read-only.

        include_identifying_metadata: if True, includes the literal
        peer endpoint address and allowed-IP ranges. Defaults to False.

        limit: maximum number of peers to return (1-100, default
        100)."""
        return client.get_status_wireguard_peers(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_status_wireguard_peers
