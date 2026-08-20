"""pfsense_get_system_restapi_version tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_restapi_version import SystemRestApiVersion
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemRestApiVersion]:
    def pfsense_get_system_restapi_version() -> SystemRestApiVersion:
        """Return the installed pfSense REST API package's current
        version, latest available version, and update availability.
        Read-only."""
        return client.get_system_restapi_version()

    return pfsense_get_system_restapi_version
