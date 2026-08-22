"""pfsense_get_dhcp_server_apply_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.dhcp_server_apply import DHCPServerApply
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], DHCPServerApply]:
    def pfsense_get_dhcp_server_apply_status() -> DHCPServerApply:
        """Get pfSense pending DHCP server change status: whether all
        DHCP server changes are applied. Read-only. Contains no
        identifying metadata."""
        return client.get_dhcp_server_apply_status()

    return pfsense_get_dhcp_server_apply_status
