"""pfsense_get_interface_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_apply import InterfaceApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], InterfaceApply]:
    def pfsense_get_interface_apply_status() -> InterfaceApply:
        """Get pfSense pending interface change status: whether all
        interfaces are applied, and which (if any) have pending
        changes. Read-only. Contains no identifying metadata beyond
        interface names."""
        return client.get_interface_apply_status()

    return pfsense_get_interface_apply_status
