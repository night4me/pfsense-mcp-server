"""Model for the DnsResolverHostOverride capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DnsResolverHostOverride(BaseModel):
    aliases: list[Any] | None
    descr: str
    domain: str
    host: str
    id: int
    ip: list[str]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DnsResolverHostOverride":
        return cls(
            aliases=data["aliases"],
            descr=data["descr"],
            domain=data["domain"],
            host=data["host"],
            id=data["id"],
            ip=data["ip"],
        )
