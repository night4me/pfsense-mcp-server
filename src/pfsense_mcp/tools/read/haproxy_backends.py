"""pfsense_get_haproxy_backends tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_backend import HAProxyBackend
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyBackend]]:
    def pfsense_get_haproxy_backends(limit: int = 100) -> list[HAProxyBackend]:
        """List pfSense HAProxy backends: name, load-balancing
        algorithm, health-check and persistence settings. Requires
        pfSense-pkg-haproxy. Read-only. Does not include each
        backend's stats password, dynamic-cookie key, custom
        pass-through config, or nested servers/ACLs/actions/error-file
        associations (use the dedicated pfsense_get_haproxy_backend_*
        tools for those).

        limit: maximum number of backends to return (1-100, default
        100)."""
        return client.get_haproxy_backends(limit=limit)

    return pfsense_get_haproxy_backends
