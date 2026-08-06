"""pfsense_get_system_tunables tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.system_tunable import SystemTunable
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[SystemTunable]]:
    def pfsense_get_system_tunables(limit: int = 100) -> list[SystemTunable]:
        """List pfSense system tunables (FreeBSD sysctl name, description, and current value)."""
        return client.get_system_tunables(limit=limit)

    return pfsense_get_system_tunables
