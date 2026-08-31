"""pfsense_get_haproxy_frontends tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_frontend import HAProxyFrontend
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyFrontend]]:
    def pfsense_get_haproxy_frontends(limit: int = 100) -> list[HAProxyFrontend]:
        """List pfSense HAProxy frontends: name, description, status,
        type, backend pool association, and logging settings.
        Requires pfSense-pkg-haproxy. Read-only. Does not include
        custom pass-through config or nested
        addresses/ACLs/actions/certificates/error-file associations
        (use the dedicated pfsense_get_haproxy_frontend_* tools for
        those).

        limit: maximum number of frontends to return (1-100, default
        100)."""
        return client.get_haproxy_frontends(limit=limit)

    return pfsense_get_haproxy_frontends
