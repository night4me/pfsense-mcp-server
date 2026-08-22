"""pfsense_get_dns_forwarder_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dns_forwarder_apply import DNSForwarderApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], DNSForwarderApply]:
    def pfsense_get_dns_forwarder_apply_status() -> DNSForwarderApply:
        """Get pfSense pending DNS Forwarder change status: whether all
        DNS Forwarder changes are applied. Read-only. Contains no
        identifying metadata."""
        return client.get_dns_forwarder_apply_status()

    return pfsense_get_dns_forwarder_apply_status
