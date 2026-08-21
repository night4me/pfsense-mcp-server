"""pfsense_get_interface_gres tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_gre import InterfaceGRE
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceGRE]]:
    def pfsense_get_interface_gres(include_identifying_metadata: bool = False, limit: int = 100) -> list[InterfaceGRE]:
        """List pfSense GRE tunnel interfaces: interface identifier
        and description. Read-only.

        include_identifying_metadata: if True, includes the literal
        tunnel-endpoint addresses (remote address, local/remote tunnel
        addresses and networks, IPv4 and IPv6). Defaults to False.

        limit: maximum number of GRE interfaces to return (1-100,
        default 100)."""
        return client.get_interface_gres(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_interface_gres
