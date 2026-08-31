"""pfsense_get_haproxy_frontend_addresses tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_frontend_address import HAProxyFrontendAddress
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFrontendAddress]]:
    def pfsense_get_haproxy_frontend_addresses(limit: int = 100) -> list[HAProxyFrontendAddress]:
        """List pfSense HAProxy frontend listen addresses across all
        frontends: interface/address selection, port, and whether SSL
        offloading is enabled. Requires pfSense-pkg-haproxy. Read-only.
        Does not include each address's custom pass-through config.

        limit: maximum number of addresses to return (1-100, default
        100)."""
        return client.get_haproxy_frontend_addresses(limit=limit)

    return pfsense_get_haproxy_frontend_addresses
