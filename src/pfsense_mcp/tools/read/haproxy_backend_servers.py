"""pfsense_get_haproxy_backend_servers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_backend_server import HAProxyBackendServer
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyBackendServer]]:
    def pfsense_get_haproxy_backend_servers(limit: int = 100) -> list[HAProxyBackendServer]:
        """List pfSense HAProxy backend servers across all backends:
        name, status, address, port, weight, and SSL settings.
        Requires pfSense-pkg-haproxy. Read-only. Does not include each
        server's custom pass-through config.

        limit: maximum number of servers to return (1-100, default
        100)."""
        return client.get_haproxy_backend_servers(limit=limit)

    return pfsense_get_haproxy_backend_servers
