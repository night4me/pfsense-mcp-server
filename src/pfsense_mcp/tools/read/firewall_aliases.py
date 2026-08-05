"""pfsense_get_firewall_aliases tool definition. GENERATED PROPOSAL — review before use."""

from __future__ import annotations

from typing import Callable

from ...models.firewall_alias import FirewallAlias
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallAlias]]:
    def pfsense_get_firewall_aliases(
        include_identifying_metadata: bool = False, limit: int = 100
    ) -> list[FirewallAlias]:
        """List configured pfSense firewall aliases (host/network/port
        groups): name, description, type, and member entries.
        Read-only.

        include_identifying_metadata: if True, includes the literal
        member addresses and per-entry detail annotations. Defaults
        to False.

        limit: maximum number of aliases to return (1-500, default
        100)."""
        return client.get_firewall_aliases(include_identifying_metadata=include_identifying_metadata, limit=limit)

    return pfsense_get_firewall_aliases
