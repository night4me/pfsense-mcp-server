"""Model for the PfSenseUserGroup capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class PfSenseUserGroup(BaseModel):
    description: str
    gid: int | None
    id: int
    member: list[str] | None
    name: str
    priv: list[str] | None
    scope: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "PfSenseUserGroup":
        return cls(
            description=data["description"],
            gid=data["gid"],
            id=data["id"],
            member=data["member"],
            name=data["name"],
            priv=data["priv"],
            scope=data["scope"],
        )
