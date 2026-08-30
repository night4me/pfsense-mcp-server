"""pfsense_get_bind_zone_record tool definition."""

from __future__ import annotations

from typing import Callable

from ...models.bind_zone_record import BindZoneRecord
from ...pfsense_client import PfSenseClient


def build(client: PfSenseClient) -> Callable[..., BindZoneRecord]:
    def pfsense_get_bind_zone_record(parent_id: int, id: int) -> BindZoneRecord:
        """Get a single pfSense BIND (DNS server) zone record: name,
        type, data, and (for MX/SRV records) priority. Requires
        pfSense-pkg-bind. Read-only.

        parent_id: the id of the BIND zone this record belongs to
        (from pfsense_get_bind_zones).
        id: the id of the record within that zone."""
        return client.get_bind_zone_record(parent_id=parent_id, id=id)

    return pfsense_get_bind_zone_record
