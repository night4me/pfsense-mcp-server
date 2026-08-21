"""pfsense_get_interface_available_interfaces tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.available_interface import AvailableInterface
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[AvailableInterface]]:
    def pfsense_get_interface_available_interfaces(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[AvailableInterface]:
        """List all interfaces available for assignment on this
        pfSense appliance (not just already-assigned ones): interface
        identifier, in-use status, and hardware boot message. Read-only.

        include_identifying_metadata: if True, includes the literal
        MAC address. Defaults to False.

        limit: maximum number of interfaces to return (1-100, default
        100)."""
        return client.get_interface_available_interfaces(
            include_identifying_metadata=include_identifying_metadata, limit=limit
        )

    return pfsense_get_interface_available_interfaces
