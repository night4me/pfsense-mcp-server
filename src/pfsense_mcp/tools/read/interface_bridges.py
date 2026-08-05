"""pfsense_get_interface_bridges tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_bridge import InterfaceBridge
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceBridge]]:
    def pfsense_get_interface_bridges(limit: int = 100) -> list[InterfaceBridge]:
        """List pfSense bridge interfaces: bridge interface
        identifier, member interfaces, and description. Read-only.

        limit: maximum number of bridge interfaces to return (1-100,
        default 100)."""
        return client.get_interface_bridges(limit=limit)

    return pfsense_get_interface_bridges
