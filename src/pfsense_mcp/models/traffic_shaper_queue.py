"""Model for the TrafficShaperQueue nested component.

Field types were derived from the pinned v2.10 OpenAPI schema's
`TrafficShaperQueue` component (already-captured evidence, not a new
live call; no secret material present -- pure QoS/bandwidth-shaping
configuration data). Only `name`/`qlimit`/`bandwidth`/`upperlimit_m2`/
`realtime_m2`/`linkshare_m2` are schema-required on the array item;
every other field is documented as "only available when" a specific
`scheduler` type or sibling boolean flag is set, so all of them are
treated as genuinely possibly-absent via `.get()` (the same
`InterfaceLAGG`-style precedent), falling back to the schema's own
declared default where one exists and `None` otherwise.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class TrafficShaperQueue(BaseModel):
    name: str
    qlimit: int
    bandwidth: int
    upperlimit_m2: str
    realtime_m2: str
    linkshare_m2: str
    interface: str | None
    enabled: bool | None
    priority: int | None
    description: str | None
    default: bool | None
    red: bool | None
    rio: bool | None
    ecn: bool | None
    codel: bool | None
    bandwidthtype: str | None
    buckets: int | None
    hogs: int | None
    borrow: bool | None
    upperlimit: bool | None
    upperlimit_m1: str | None
    upperlimit_d: int | None
    realtime: bool | None
    realtime_m1: str | None
    realtime_d: int | None
    linkshare: bool | None
    linkshare_m1: str | None
    linkshare_d: int | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "TrafficShaperQueue":
        return cls(
            name=data["name"],
            qlimit=data["qlimit"],
            bandwidth=data["bandwidth"],
            upperlimit_m2=data["upperlimit_m2"],
            realtime_m2=data["realtime_m2"],
            linkshare_m2=data["linkshare_m2"],
            interface=data.get("interface"),
            enabled=data.get("enabled"),
            priority=data.get("priority", 1),
            description=data.get("description"),
            default=data.get("default"),
            red=data.get("red"),
            rio=data.get("rio"),
            ecn=data.get("ecn"),
            codel=data.get("codel"),
            bandwidthtype=data.get("bandwidthtype", "Mb"),
            buckets=data.get("buckets"),
            hogs=data.get("hogs"),
            borrow=data.get("borrow"),
            upperlimit=data.get("upperlimit"),
            upperlimit_m1=data.get("upperlimit_m1"),
            upperlimit_d=data.get("upperlimit_d"),
            realtime=data.get("realtime"),
            realtime_m1=data.get("realtime_m1"),
            realtime_d=data.get("realtime_d"),
            linkshare=data.get("linkshare"),
            linkshare_m1=data.get("linkshare_m1"),
            linkshare_d=data.get("linkshare_d"),
        )
