"""Model for the FirewallAlias capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FIREWALL_ALIAS_IDENTIFYING_FIELDS = (
    "address",
    "detail",
)


class FirewallAlias(BaseModel):
    descr: str
    id: int
    name: str
    type: str
    address: list[str] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    detail: list[str] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FirewallAlias":
        identifying = {field: data[field] for field in _FIREWALL_ALIAS_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            id=data["id"],
            name=data["name"],
            type=data["type"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
