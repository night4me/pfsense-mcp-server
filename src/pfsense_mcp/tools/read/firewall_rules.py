"""pfsense_get_firewall_rules tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.firewall import FirewallRule
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[FirewallRule]]:
    def pfsense_get_firewall_rules(include_identifying_metadata: bool = False) -> list[FirewallRule]:
        """Get pfSense configured firewall filter rules: action,
        interface, protocol, description, enabled state, and
        matching criteria. Read-only.

        include_identifying_metadata: if True, includes the literal
        source/destination address and the creating/updating admin's
        username+IP in the response. Defaults to False."""
        return client.get_firewall_rules(include_identifying_metadata=include_identifying_metadata)
    return pfsense_get_firewall_rules
