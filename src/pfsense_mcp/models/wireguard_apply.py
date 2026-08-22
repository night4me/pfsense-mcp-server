"""Model for the WireGuardApply capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`WireGuardApply` component (already-captured evidence, not a new live
call; independently re-verified during v0.6.0 Phase A qualification --
a single boolean field, `writeOnly: false`, no secret material). The
schema declares `applied` `nullable: true`, followed faithfully here
since no live call has confirmed this endpoint's actual behavior yet
(same reasoning as `VirtualIPApply`).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class WireGuardApply(BaseModel):
    applied: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "WireGuardApply":
        return cls(applied=data["applied"])
