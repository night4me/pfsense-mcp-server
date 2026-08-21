"""Model for the RoutingGatewayGroup capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `RoutingGatewayGroup` component (already-captured evidence,
not a new live call; no secret material present). `name`/`trigger`/
`descr`/`ipprotocol` are configuration identifiers, not address data,
and stay visible. `priorities` is schema-confirmed to embed full
`RoutingGatewayGroupPriority` objects and is constructed through that
model's own `from_api()` for every item, so its own `gateway`/
`virtual_ip` redaction gate holds for the nested case too.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .routing_gateway_group_priority import RoutingGatewayGroupPriority


class RoutingGatewayGroup(BaseModel):
    name: str
    trigger: str
    descr: str
    ipprotocol: str | None
    priorities: list[RoutingGatewayGroupPriority]

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "RoutingGatewayGroup":
        return cls(
            name=data["name"],
            trigger=data["trigger"],
            descr=data["descr"],
            ipprotocol=data["ipprotocol"],
            priorities=[
                RoutingGatewayGroupPriority.from_api(item, include_identifying_metadata=include_identifying_metadata)
                for item in data["priorities"]
            ],
        )
