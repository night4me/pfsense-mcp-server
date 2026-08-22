"""Model for the VirtualIPApply capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`VirtualIPApply` component (already-captured evidence, not a new live
call; independently re-verified during v0.6.0 Phase A qualification --
a single boolean field, `writeOnly: false`, no secret material). The
schema declares `applied` `nullable: true`; unlike this project's
existing `FirewallApplyStatus.applied` (modeled non-nullable on the
strength of a prior live confirmation), no live call has confirmed this
endpoint's actual behavior yet, so the schema's own nullable claim is
followed faithfully rather than assumed away.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class VirtualIPApply(BaseModel):
    applied: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "VirtualIPApply":
        return cls(applied=data["applied"])
