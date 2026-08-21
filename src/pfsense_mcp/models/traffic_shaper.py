"""Model for the TrafficShaper capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `TrafficShaper` component (already-captured evidence, not a
new live call; no secret material present). `interface` is an
interface identifier, not an address, and stays visible, matching
`InterfaceGroup`'s established convention. `queue` is schema-confirmed
to embed full `TrafficShaperQueue` objects and is constructed through
that model's own `from_api()` for every item.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .traffic_shaper_queue import TrafficShaperQueue


class TrafficShaper(BaseModel):
    enabled: bool
    interface: str
    name: str | None
    scheduler: str
    bandwidthtype: str
    bandwidth: int
    qlimit: int | None
    tbrconfig: int | None
    queue: list[TrafficShaperQueue]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "TrafficShaper":
        return cls(
            enabled=data["enabled"],
            interface=data["interface"],
            name=data["name"],
            scheduler=data["scheduler"],
            bandwidthtype=data["bandwidthtype"],
            bandwidth=data["bandwidth"],
            qlimit=data["qlimit"],
            tbrconfig=data["tbrconfig"],
            queue=[TrafficShaperQueue.from_api(item) for item in data["queue"]],
        )
