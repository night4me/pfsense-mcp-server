"""pfsense_get_interface_laggs tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_lagg import InterfaceLAGG
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceLAGG]]:
    def pfsense_get_interface_laggs(limit: int = 100) -> list[InterfaceLAGG]:
        """List pfSense LAGG (link aggregation) interfaces: LAGG
        interface identifier, member interfaces, protocol, and
        description. Read-only.

        limit: maximum number of LAGG interfaces to return (1-100,
        default 100)."""
        return client.get_interface_laggs(limit=limit)

    return pfsense_get_interface_laggs
