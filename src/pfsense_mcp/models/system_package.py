"""Model for the SystemPackage capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemPackage(BaseModel):
    descr: str | None
    id: int
    installed_version: str | None
    latest_version: str | None
    name: str
    shortname: str | None
    update_available: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemPackage":
        return cls(
            descr=data["descr"],
            id=data["id"],
            installed_version=data["installed_version"],
            latest_version=data["latest_version"],
            name=data["name"],
            shortname=data["shortname"],
            update_available=data["update_available"],
        )
