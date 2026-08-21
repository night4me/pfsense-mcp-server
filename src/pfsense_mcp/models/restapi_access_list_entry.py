"""Model for the RESTAPIAccessListEntry capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `RESTAPIAccessListEntry` component (already-captured
evidence, not a new live call; no secret material present) -- this is
the REST API's own IP allow/deny list, a security-posture-relevant
read. `network` (the literal CIDR this entry applies to) is
address-bearing and is redacted by default, matching
`GatewayConfig.gateway`'s established convention. `users`/`sched`/
`type`/`weight`/`descr` are configuration references, not addresses,
and stay visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class RESTAPIAccessListEntry(BaseModel):
    type: str
    weight: int
    network: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    users: list[str]
    sched: str
    descr: str

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "RESTAPIAccessListEntry":
        return cls(
            type=data["type"],
            weight=data["weight"],
            network=data["network"] if include_identifying_metadata else None,
            users=data["users"],
            sched=data["sched"],
            descr=data["descr"],
        )
