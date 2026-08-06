"""Model for the FirewallAdvancedSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class FirewallAdvancedSettings(BaseModel):
    aliasesresolveinterval: int | None
    checkaliasesurlcert: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "FirewallAdvancedSettings":
        return cls(
            aliasesresolveinterval=data["aliasesresolveinterval"],
            checkaliasesurlcert=data["checkaliasesurlcert"],
        )
