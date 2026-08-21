"""pfsense_get_system_timezone tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_timezone import SystemTimezone
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemTimezone]:
    def pfsense_get_system_timezone() -> SystemTimezone:
        """Return the current system timezone. Read-only."""
        return client.get_system_timezone()

    return pfsense_get_system_timezone
