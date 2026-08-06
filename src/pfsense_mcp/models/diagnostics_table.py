"""Model for the DiagnosticsTable capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DiagnosticsTable(BaseModel):
    entries: list[str]
    id: str
    name: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DiagnosticsTable":
        return cls(
            entries=data["entries"],
            id=data["id"],
            name=data["name"],
        )
