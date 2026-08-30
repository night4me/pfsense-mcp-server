"""pfsense_get_vpn_wireguard_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.wireguard_settings import WireGuardSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., WireGuardSettings]:
    def pfsense_get_vpn_wireguard_settings() -> WireGuardSettings:
        """Get global pfSense WireGuard service settings: enabled state,
        config-retention-on-uninstall, endpoint hostname re-resolution
        interval, and interface-group membership mode. Read-only. Does
        not include tunnel/peer configuration or key material."""
        return client.get_vpn_wireguard_settings()

    return pfsense_get_vpn_wireguard_settings
