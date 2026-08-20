"""Model for the FirewallSchedule capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `FirewallSchedule` component (already-captured evidence, not
a new live call). `timerange` is modeled as a raw list of dicts rather
than a dedicated nested submodel: this codebase has no established
nested-pydantic-submodel pattern yet (every other model here is flat),
and `FirewallScheduleTimeRange`'s own fields (position/month/day/hour/
rangedescr) carry no secret or address-bearing material either way, so
introducing that pattern for this one field would be scope beyond what
this endpoint needs. No redaction gate is required here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class FirewallSchedule(BaseModel):
    active: bool | None
    descr: str
    name: str
    schedlabel: str | None
    timerange: list[dict[str, Any]]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FirewallSchedule":
        return cls(
            active=data["active"],
            descr=data["descr"],
            name=data["name"],
            schedlabel=data["schedlabel"],
            timerange=data["timerange"],
        )
