"""pfsense_get_gateways tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.gateways import GatewayConfig
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[GatewayConfig]]:
    def pfsense_get_gateways(include_identifying_metadata: bool = False) -> list[GatewayConfig]:
        """Get pfSense configured gateways: name, description,
        enabled state, protocol, interface, monitoring thresholds,
        and failover behavior. Read-only.

        include_identifying_metadata: if True, includes the gateway
        IP address and monitor IP override in the response. Defaults
        to False."""
        return client.get_gateways(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_gateways
