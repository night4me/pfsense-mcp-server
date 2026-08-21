"""pfsense_get_system_dns tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_dns import SystemDNS
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemDNS]:
    def pfsense_get_system_dns(include_identifying_metadata: bool = False) -> SystemDNS:
        """Return the current system DNS settings: override policy,
        local-vs-remote resolution preference, and remote DNS servers.
        Read-only.

        include_identifying_metadata: if True, includes the literal
        remote DNS server addresses. Defaults to False."""
        return client.get_system_dns(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_system_dns
