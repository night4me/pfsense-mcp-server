"""pfsense_get_system_console tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.system_console import SystemConsole
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., SystemConsole]:
    def pfsense_get_system_console() -> SystemConsole:
        """Return whether a password is required to access the system
        console. Read-only."""
        return client.get_system_console()

    return pfsense_get_system_console
