"""pfsense_get_dns_forwarder_host_overrides tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_forwarder_host_override import DnsForwarderHostOverride
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[DnsForwarderHostOverride]]:
    def pfsense_get_dns_forwarder_host_overrides(limit: int = 100) -> list[DnsForwarderHostOverride]:
        """List dnsmasq (DNS Forwarder) host overrides, addresses,
        aliases, and descriptions. Read-only.

        limit: maximum number of overrides to return (1-100, default
        100)."""
        return client.get_dns_forwarder_host_overrides(limit=limit)

    return pfsense_get_dns_forwarder_host_overrides
