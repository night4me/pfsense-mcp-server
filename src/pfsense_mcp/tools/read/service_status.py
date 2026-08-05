"""pfsense_get_service_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.service_status import ServiceStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[ServiceStatus]]:
    def pfsense_get_service_status(limit: int = 100) -> list[ServiceStatus]:
        """List pfSense service status: name, description, enabled
        state, and running status for each managed service. Read-only.

        limit: maximum number of services to return (1-100, default
        100)."""
        return client.get_service_status(limit=limit)

    return pfsense_get_service_status
