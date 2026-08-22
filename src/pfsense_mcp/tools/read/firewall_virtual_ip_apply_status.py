"""pfsense_get_firewall_virtual_ip_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.virtual_ip_apply import VirtualIPApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], VirtualIPApply]:
    def pfsense_get_firewall_virtual_ip_apply_status() -> VirtualIPApply:
        """Get pfSense pending virtual IP change status: whether all
        virtual IP changes are applied. Read-only. Contains no
        identifying metadata."""
        return client.get_firewall_virtual_ip_apply_status()

    return pfsense_get_firewall_virtual_ip_apply_status
