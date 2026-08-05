"""Model for the CarpStatus capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: this endpoint only reports whether CARP is
enabled and whether maintenance mode is active, with no
installation-specific values at all.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class CarpStatus(BaseModel):
    enable: bool
    maintenance_mode: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "CarpStatus":
        return cls(
            enable=data["enable"],
            maintenance_mode=data["maintenance_mode"],
        )
