"""pfsense_get_interface_vlans tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_vlan import InterfaceVlan
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceVlan]]:
    def pfsense_get_interface_vlans(limit: int = 100) -> list[InterfaceVlan]:
        """List pfSense 802.1Q VLAN interfaces: parent interface, VLAN
        tag, priority code point, resulting VLAN interface identifier,
        and description. Read-only.

        limit: maximum number of VLAN interfaces to return (1-100,
        default 100)."""
        return client.get_interface_vlans(limit=limit)

    return pfsense_get_interface_vlans
