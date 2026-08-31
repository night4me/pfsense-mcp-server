"""pfsense_get_services_service_watchdogs tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.service_watchdog import ServiceWatchdog
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[ServiceWatchdog]]:
    def pfsense_get_services_service_watchdogs(limit: int = 100) -> list[ServiceWatchdog]:
        """List pfSense Service Watchdog entries: which services are
        monitored, whether notifications are sent, and whether each
        entry is enabled. Requires pfSense-pkg-Service_Watchdog.
        Read-only. No secret material or address data; all 4 fields
        are plain scalar toggles/labels.

        limit: maximum number of entries to return (1-100, default
        100)."""
        return client.get_services_service_watchdogs(limit=limit)

    return pfsense_get_services_service_watchdogs
