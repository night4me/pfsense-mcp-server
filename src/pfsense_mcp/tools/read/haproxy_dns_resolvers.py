"""pfsense_get_haproxy_dns_resolvers tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.haproxy_dns_resolver import HAProxyDnsResolver
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[HAProxyDnsResolver]]:
    def pfsense_get_haproxy_dns_resolvers(limit: int = 100) -> list[HAProxyDnsResolver]:
        """List pfSense HAProxy DNS resolvers: name, server address,
        and port. Requires pfSense-pkg-haproxy. Read-only. No
        credential fields exist on this resource.

        limit: maximum number of resolvers to return (1-100, default
        100)."""
        return client.get_haproxy_dns_resolvers(limit=limit)

    return pfsense_get_haproxy_dns_resolvers
