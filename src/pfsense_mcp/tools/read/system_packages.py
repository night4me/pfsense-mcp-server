"""pfsense_get_system_packages tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.system_package import SystemPackage
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[SystemPackage]]:
    def pfsense_get_system_packages(limit: int = 100) -> list[SystemPackage]:
        """List pfSense installed packages (name, description, installed/latest version, and update availability)."""
        return client.get_system_packages(limit=limit)

    return pfsense_get_system_packages
