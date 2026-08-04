"""pfsense_get_gateway_status tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.gateways import GatewayStatus
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[GatewayStatus]]:
    def pfsense_get_gateway_status(include_identifying_metadata: bool = False) -> list[GatewayStatus]:
        """Get pfSense live gateway status/monitoring data: name,
        latency, standard deviation, packet loss, and up/down
        status. Read-only.

        include_identifying_metadata: if True, includes the current
        source IP and monitored target IP in the response. Defaults
        to False."""
        return client.get_gateway_status(include_identifying_metadata=include_identifying_metadata)
    return pfsense_get_gateway_status
