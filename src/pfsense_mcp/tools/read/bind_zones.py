"""pfsense_get_bind_zones tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.bind_zone import BindZone
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., list[BindZone]]:
    def pfsense_get_bind_zones(limit: int = 100) -> list[BindZone]:
        """List pfSense BIND (DNS server) zones: name, type, SOA
        settings, and access-list associations. Requires
        pfSense-pkg-bind. Read-only. Does not include each zone's own
        DNS records (use pfsense_get_bind_zone_record for individual
        records) or its custom BIND config-file/zone-file text
        fragments.

        limit: maximum number of zones to return (1-100, default
        100)."""
        return client.get_bind_zones(limit=limit)

    return pfsense_get_bind_zones
