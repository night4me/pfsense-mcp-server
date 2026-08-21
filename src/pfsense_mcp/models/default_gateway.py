"""Model for the DefaultGateway capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DefaultGateway` component (already-captured evidence, not a
new live call; no secret material present). `defaultgw4`/`defaultgw6`
are gateway name references (or the empty/`-` sentinel) and are
redacted by default, matching `RoutingStaticRoute.gateway`'s
established convention for gateway-name references.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_DEFAULT_GATEWAY_IDENTIFYING_FIELDS = ("defaultgw4", "defaultgw6")


class DefaultGateway(BaseModel):
    defaultgw4: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    defaultgw6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "DefaultGateway":
        identifying = {field: data[field] for field in _DEFAULT_GATEWAY_IDENTIFYING_FIELDS}
        return cls(
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
