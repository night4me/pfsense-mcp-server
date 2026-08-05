"""pfsense_get_interface_configs tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_config import InterfaceConfig
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceConfig]]:
    def pfsense_get_interface_configs(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[InterfaceConfig]:
        """List configured pfSense network interfaces: assignment,
        enable state, and IPv4/IPv6 configuration. Read-only.

        include_identifying_metadata: if True, includes the literal
        IP/gateway addresses, MAC override, and DHCP hostname for each
        interface. Defaults to False.

        limit: maximum number of interfaces to return (1-100, default
        100)."""
        return client.get_interface_configs(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_interface_configs
