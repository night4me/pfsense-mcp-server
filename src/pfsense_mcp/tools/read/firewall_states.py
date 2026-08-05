"""pfsense_get_firewall_states tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall import FirewallState
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallState]]:
    def pfsense_get_firewall_states(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallState]:
        """Get pfSense live firewall states (the active connection
        table): interface, protocol, direction, status, age, and
        packet/byte counters. Read-only.

        include_identifying_metadata: if True, includes the literal
        source and destination address for each state. Defaults to
        False.

        limit: maximum number of states to return (1-500, default
        100). A firewall can hold millions of states; this must
        stay bounded."""
        return client.get_firewall_states(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_firewall_states
