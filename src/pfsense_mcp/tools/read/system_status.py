"""pfsense_get_system_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system import SystemStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemStatus]:
    def pfsense_get_system_status(include_identifying_metadata: bool = False) -> SystemStatus:
        """Get pfSense system status: platform, uptime, CPU, memory,
        disk, and thermal information. Read-only.

        include_identifying_metadata: if True, includes the device's
        Netgate ID in the response. Defaults to False."""
        return client.get_system_status(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_system_status
