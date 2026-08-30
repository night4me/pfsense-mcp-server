"""pfsense_get_bind_sync_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.bind_sync_settings import BindSyncSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., BindSyncSettings]:
    def pfsense_get_bind_sync_settings() -> BindSyncSettings:
        """Get pfSense BIND (DNS server) HA sync settings: sync mode,
        timeout, and master server IP. Requires pfSense-pkg-bind.
        Read-only. Does not include the separate sync remote-host
        credentials."""
        return client.get_bind_sync_settings()

    return pfsense_get_bind_sync_settings
