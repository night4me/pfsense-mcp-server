"""pfsense_get_wireguard_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_apply import WireGuardApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], WireGuardApply]:
    def pfsense_get_wireguard_apply_status() -> WireGuardApply:
        """Get pfSense pending WireGuard change status: whether all
        WireGuard changes are applied. Read-only. Contains no
        identifying metadata. Requires pfSense-pkg-WireGuard."""
        return client.get_wireguard_apply_status()

    return pfsense_get_wireguard_apply_status
