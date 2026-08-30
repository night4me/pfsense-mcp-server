"""Model for the BINDAccessList capability endpoint.

Field types/nullability derived from the live pfrest.org v2.10.2 OpenAPI
document (fetched 2026-08-30, `POST_V1_1_BIND_READ_QUALIFICATION.md`).
`entries` is modeled as `list[Any]` rather than a fully-typed nested
model, matching this project's existing convention for a nested array
whose own dedicated sub-resource endpoint is not separately exposed
(see `DnsResolverHostOverride.aliases`) -- `services/bind/access_list/
entries` and `.../entry` were classified `DEFER_LOW_VALUE` (redundant
with this field) rather than implemented. `id` is the plain internal
array index pfREST assigns every list item, not identifying/sensitive
data -- no redaction needed, consistent with `DhcpStaticMapping.id`.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindAccessList(BaseModel):
    id: int
    name: str
    description: str
    entries: list[Any]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindAccessList":
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            entries=data["entries"],
        )
