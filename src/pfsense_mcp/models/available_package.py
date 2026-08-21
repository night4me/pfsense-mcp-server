"""Model for the AvailablePackage capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `AvailablePackage` component (already-captured evidence, not
a new live call; no secret material present). Package catalog metadata
only -- no field is redacted.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class AvailablePackage(BaseModel):
    name: str
    shortname: str | None
    descr: str | None
    version: str | None
    installed: bool | None
    deps: list[str] | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "AvailablePackage":
        return cls(
            name=data["name"],
            shortname=data["shortname"],
            descr=data["descr"],
            version=data["version"],
            installed=data["installed"],
            deps=data["deps"],
        )
