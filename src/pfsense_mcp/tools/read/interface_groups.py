"""pfsense_get_interface_groups tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.interface_group import InterfaceGroup
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[InterfaceGroup]]:
    def pfsense_get_interface_groups(limit: int = 100) -> list[InterfaceGroup]:
        """List pfSense interface groups: group name, member
        interfaces, and description. Useful for interpreting firewall
        rules that target a group rather than a single interface.
        Read-only.

        limit: maximum number of interface groups to return (1-100,
        default 100)."""
        return client.get_interface_groups(limit=limit)

    return pfsense_get_interface_groups
