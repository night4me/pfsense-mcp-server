"""Model for the ServiceStatus capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ServiceStatus(BaseModel):
    description: str | None
    enabled: bool | None
    id: int
    name: str
    status: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "ServiceStatus":
        return cls(
            description=data["description"],
            enabled=data["enabled"],
            id=data["id"],
            name=data["name"],
            status=data["status"],
        )
