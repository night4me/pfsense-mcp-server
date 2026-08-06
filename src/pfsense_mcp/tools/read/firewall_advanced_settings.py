"""pfsense_get_firewall_advanced_settings tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_advanced_settings import FirewallAdvancedSettings
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., FirewallAdvancedSettings]:
    def pfsense_get_firewall_advanced_settings() -> FirewallAdvancedSettings:
        """Get pfSense firewall advanced settings (alias URL resolve interval and alias URL certificate checking)."""
        return client.get_firewall_advanced_settings()

    return pfsense_get_firewall_advanced_settings
