"""pfsense_get_firewall_schedules tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_schedule import FirewallSchedule
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallSchedule]]:
    def pfsense_get_firewall_schedules(limit: int = 100) -> list[FirewallSchedule]:
        """List pfSense time-based firewall schedules: name,
        description, active state, and configured time ranges.
        Read-only.

        limit: maximum number of schedules to return (1-100, default
        100)."""
        return client.get_firewall_schedules(limit=limit)

    return pfsense_get_firewall_schedules
