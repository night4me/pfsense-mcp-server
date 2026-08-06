"""Model for the CronJob capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class CronJob(BaseModel):
    command: str
    hour: str
    id: int
    mday: str
    minute: str
    month: str
    wday: str
    who: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "CronJob":
        return cls(
            command=data["command"],
            hour=data["hour"],
            id=data["id"],
            mday=data["mday"],
            minute=data["minute"],
            month=data["month"],
            wday=data["wday"],
            who=data["who"],
        )
