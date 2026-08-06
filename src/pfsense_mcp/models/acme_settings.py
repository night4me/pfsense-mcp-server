"""Model for the AcmeSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class AcmeSettings(BaseModel):
    enable: bool
    writecerts: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "AcmeSettings":
        return cls(
            enable=data["enable"],
            writecerts=data["writecerts"],
        )
