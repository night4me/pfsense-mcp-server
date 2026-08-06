"""pfsense_get_dns_resolver_host_overrides tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.dns_resolver_host_override import DnsResolverHostOverride
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DnsResolverHostOverride]]:
    def pfsense_get_dns_resolver_host_overrides(limit: int = 100) -> list[DnsResolverHostOverride]:
        """List pfSense DNS Resolver host overrides (host, domain, IP addresses, aliases, and description)."""
        return client.get_dns_resolver_host_overrides(limit=limit)

    return pfsense_get_dns_resolver_host_overrides
