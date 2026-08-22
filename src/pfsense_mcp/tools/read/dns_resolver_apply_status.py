"""pfsense_get_dns_resolver_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_resolver_apply import DNSResolverApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], DNSResolverApply]:
    def pfsense_get_dns_resolver_apply_status() -> DNSResolverApply:
        """Get pfSense pending DNS Resolver change status: whether all
        DNS Resolver changes are applied. Read-only. Contains no
        identifying metadata."""
        return client.get_dns_resolver_apply_status()

    return pfsense_get_dns_resolver_apply_status
