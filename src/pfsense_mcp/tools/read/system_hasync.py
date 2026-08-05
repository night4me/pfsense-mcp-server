"""pfsense_get_system_hasync tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_ha_sync import SystemHaSync
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemHaSync]:
    def pfsense_get_system_hasync(include_identifying_metadata: bool = False) -> SystemHaSync:
        """Get pfSense's High Availability (HA) synchronization
        (pfsync/XMLRPC config sync) settings: whether pfsync is
        enabled, the sync interface, peer address, and which
        configuration areas are synchronized. Read-only.

        include_identifying_metadata: if True, includes the HA sync
        username and host ID in the response. Defaults to False."""
        return client.get_system_hasync(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_system_hasync
