"""Model for the RoutingStaticRoute capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `StaticRoute` component (already-captured evidence, not a
new live call). Not yet cross-checked against an approved fixture
from a real instance -- see `Endpoints.ROUTING_STATIC_ROUTES.verified`
(`False`). `network`/`gateway` are address-bearing fields and are
redacted by default, matching `GatewayConfig`'s established convention
for its own `gateway` field; no secret material is present in this
component.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_ROUTING_STATIC_ROUTE_IDENTIFYING_FIELDS = ("gateway", "network")


class RoutingStaticRoute(BaseModel):
    descr: str | None
    disabled: bool
    gateway: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    network: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "RoutingStaticRoute":
        identifying = {field: data[field] for field in _ROUTING_STATIC_ROUTE_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            disabled=data["disabled"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
