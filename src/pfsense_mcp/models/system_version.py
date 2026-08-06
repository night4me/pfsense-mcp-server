"""Model for the SystemVersion capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemVersion(BaseModel):
    base: str | None
    buildtime: str | None
    patch: str | None
    version: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemVersion":
        return cls(
            base=data["base"],
            buildtime=data["buildtime"],
            patch=data["patch"],
            version=data["version"],
        )
