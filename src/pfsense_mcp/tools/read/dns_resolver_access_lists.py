"""pfsense_get_dns_resolver_access_lists tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_resolver_access_list import DnsResolverAccessList
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DnsResolverAccessList]]:
    def pfsense_get_dns_resolver_access_lists(limit: int = 100) -> list[DnsResolverAccessList]:
        """List Unbound (DNS Resolver) access lists: allow/deny action
        and the network ranges each list applies to. Read-only.

        limit: maximum number of access lists to return (1-100, default
        100)."""
        return client.get_dns_resolver_access_lists(limit=limit)

    return pfsense_get_dns_resolver_access_lists
