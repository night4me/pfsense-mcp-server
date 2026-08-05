"""pfsense_get_firewall_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall import FirewallApplyStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], FirewallApplyStatus]:
    def pfsense_get_firewall_apply_status() -> FirewallApplyStatus:
        """Get pfSense pending firewall change status: whether all
        firewall changes are applied, and which subsystems (if any)
        have pending changes. Read-only. Contains no identifying
        metadata."""
        return client.get_firewall_apply_status()
    return pfsense_get_firewall_apply_status
