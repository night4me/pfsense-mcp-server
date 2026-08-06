"""pfsense_get_dns_resolver_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_resolver_settings import DnsResolverSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., DnsResolverSettings]:
    def pfsense_get_dns_resolver_settings() -> DnsResolverSettings:
        """Get pfSense DNS Resolver (Unbound) service settings: enabled
        state, listening/outgoing interfaces, DNSSEC, forwarding mode,
        and related configuration. Read-only."""
        return client.get_dns_resolver_settings()

    return pfsense_get_dns_resolver_settings
