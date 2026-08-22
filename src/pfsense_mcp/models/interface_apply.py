"""Model for the InterfaceApply capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`InterfaceApply` component (already-captured evidence, not a new live
call; independently re-verified during v0.6.0 Phase A qualification --
two fields, `writeOnly: false` throughout, no secret material).
`pending_interfaces` is a flat array of interface names, not nested
objects. Both fields are schema-declared `nullable: true`, followed
faithfully here since no live call has confirmed this endpoint's actual
behavior yet (same reasoning as `VirtualIPApply`).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InterfaceApply(BaseModel):
    applied: bool | None
    pending_interfaces: list[str] | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "InterfaceApply":
        return cls(applied=data["applied"], pending_interfaces=data["pending_interfaces"])
