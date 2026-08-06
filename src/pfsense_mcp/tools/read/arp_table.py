"""pfsense_get_arp_table tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.arp_table_entry import ArpTableEntry
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[ArpTableEntry]]:
    def pfsense_get_arp_table(limit: int = 100) -> list[ArpTableEntry]:
        """List pfSense ARP table entries (IP address, MAC address, hostname, interface, and entry type)."""
        return client.get_arp_table(limit=limit)

    return pfsense_get_arp_table
