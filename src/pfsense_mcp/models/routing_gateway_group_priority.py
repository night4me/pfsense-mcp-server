"""Model for the RoutingGatewayGroupPriority nested component.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `RoutingGatewayGroupPriority` component (already-captured
evidence, not a new live call; no secret material present). `gateway`
(a gateway name reference) and `virtual_ip` (an address or the
`address` sentinel) are identifying/address-bearing and are redacted
by default, matching `RoutingStaticRoute.gateway`'s established
convention for gateway-name references. `tier` is a priority ordinal,
not identifying, and stays visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_ROUTING_GATEWAY_GROUP_PRIORITY_IDENTIFYING_FIELDS = ("gateway", "virtual_ip")


class RoutingGatewayGroupPriority(BaseModel):
    gateway: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tier: int
    virtual_ip: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "RoutingGatewayGroupPriority":
        identifying = {field: data[field] for field in _ROUTING_GATEWAY_GROUP_PRIORITY_IDENTIFYING_FIELDS}
        return cls(
            tier=data["tier"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
