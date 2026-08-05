"""pfsense_get_carp_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.carp_status import CarpStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., CarpStatus]:
    def pfsense_get_carp_status() -> CarpStatus:
        """Get pfSense's current CARP (Common Address Redundancy
        Protocol) high-availability status: whether CARP is enabled
        and whether maintenance mode is active. Read-only."""
        return client.get_carp_status()

    return pfsense_get_carp_status
