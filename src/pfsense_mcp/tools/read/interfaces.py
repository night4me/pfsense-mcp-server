"""pfsense_get_interfaces tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interfaces import InterfaceStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceStatus]]:
    def pfsense_get_interfaces(include_identifying_metadata: bool = False) -> list[InterfaceStatus]:
        """Get pfSense interface inventory and live status: name,
        description, hardware interface, MTU, enabled state, link
        status, media, DHCP link state, and traffic/error counters.
        Read-only.

        include_identifying_metadata: if True, includes MAC address,
        IPv4/IPv6 addresses, subnets, and gateways in the response.
        Defaults to False."""
        return client.get_interfaces(include_identifying_metadata=include_identifying_metadata)
    return pfsense_get_interfaces
