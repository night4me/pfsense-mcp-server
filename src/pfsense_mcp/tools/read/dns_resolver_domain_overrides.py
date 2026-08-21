"""pfsense_get_dns_resolver_domain_overrides tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_resolver_domain_override import DnsResolverDomainOverride
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DnsResolverDomainOverride]]:
    def pfsense_get_dns_resolver_domain_overrides(limit: int = 100) -> list[DnsResolverDomainOverride]:
        """List Unbound (DNS Resolver) domain overrides: forwarding
        target address and DNS-over-TLS settings. Read-only.

        limit: maximum number of overrides to return (1-100, default
        100)."""
        return client.get_dns_resolver_domain_overrides(limit=limit)

    return pfsense_get_dns_resolver_domain_overrides
