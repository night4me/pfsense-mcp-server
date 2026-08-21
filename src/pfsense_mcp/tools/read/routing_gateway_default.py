"""pfsense_get_routing_gateway_default tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.default_gateway import DefaultGateway
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., DefaultGateway]:
    def pfsense_get_routing_gateway_default(include_identifying_metadata: bool = False) -> DefaultGateway:
        """Return the current default IPv4/IPv6 gateway assignment.
        Read-only.

        include_identifying_metadata: if True, includes the literal
        default gateway names. Defaults to False."""
        return client.get_routing_gateway_default(include_identifying_metadata=include_identifying_metadata)

    return pfsense_get_routing_gateway_default
