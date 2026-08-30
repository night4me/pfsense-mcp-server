"""Model for the BINDZoneRecord capability endpoint.

Field types/nullability derived from the live pfrest.org v2.10.2
OpenAPI document (fetched 2026-08-30,
`POST_V1_1_BIND_READ_QUALIFICATION.md`). This is a singular-by-composite-
key resource (`?parent_id=<zone id>&id=<record id>`) with no plural
sibling in pfREST -- unlike every other BIND resource, the singular
form here is the non-redundant, valuable one (the parent `BindZone`'s
own `records` field is deliberately excluded, see `bind_zone.py`, so
this is the only way to inspect one record's content without an
unbounded bulk fetch). `id`/`parent_id` are the plain internal array
indices pfREST assigns, not identifying/sensitive data.

`priority` is schema-declared `nullable: false` but is documented as
"only available when `type` is one of [ MX, SRV ]" -- conditionally
present for other record types, matching this project's established
handling of the same conditional-availability pattern elsewhere (e.g.
`WireGuardSettings.resolve_interval`). No live-populated record was
observed this session (the qualification ceremony's `zone_record` GET
hit a 404 for lack of any zone to look up), so this is modeled
conservatively from the schema's own documented conditionality, not
guessed.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindZoneRecord(BaseModel):
    id: int
    parent_id: int
    name: str
    type: str
    rdata: str
    priority: int | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindZoneRecord":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data["name"],
            type=data["type"],
            rdata=data["rdata"],
            priority=data.get("priority"),
        )
