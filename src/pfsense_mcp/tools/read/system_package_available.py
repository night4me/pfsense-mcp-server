"""pfsense_get_system_package_available tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.available_package import AvailablePackage
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[AvailablePackage]]:
    def pfsense_get_system_package_available(limit: int = 100) -> list[AvailablePackage]:
        """List packages available for installation: name, version,
        description, and installed status. Read-only.

        limit: maximum number of packages to return (1-100, default
        100)."""
        return client.get_system_package_available(limit=limit)

    return pfsense_get_system_package_available
