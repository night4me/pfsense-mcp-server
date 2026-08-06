"""Model for the SystemTunable capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemTunable(BaseModel):
    descr: str
    id: int
    tunable: str
    value: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemTunable":
        return cls(
            descr=data["descr"],
            id=data["id"],
            tunable=data["tunable"],
            value=data["value"],
        )
