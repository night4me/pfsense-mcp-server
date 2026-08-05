"""pfsense_get_system_version tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_version import SystemVersion
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemVersion]:
    def pfsense_get_system_version() -> SystemVersion:
        """Get pfSense system version information: installed version
        string, base release, patch level, and build time. Read-only.
        """
        return client.get_system_version()

    return pfsense_get_system_version
