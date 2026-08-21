"""pfsense_get_dhcp_relay tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_relay import DHCPRelay
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., DHCPRelay]:
    def pfsense_get_dhcp_relay(include_identifying_metadata: bool = False) -> DHCPRelay:
        """Return the current DHCP Relay configuration: enabled state,
        downstream interfaces, and CARP failover selector. Read-only.

        include_identifying_metadata: if True, includes the literal
        relay target server addresses. Defaults to False."""
        return client.get_dhcp_relay(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_dhcp_relay
