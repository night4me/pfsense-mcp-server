"""pfsense_get_firewall_states_size tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall import FirewallStatesSize
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[[], FirewallStatesSize]:
    def pfsense_get_firewall_states_size() -> FirewallStatesSize:
        """Get pfSense firewall state table capacity: maximum
        configured states, default maximum, and current state
        count. Read-only. Contains no identifying metadata."""
        return client.get_firewall_states_size()
    return pfsense_get_firewall_states_size
