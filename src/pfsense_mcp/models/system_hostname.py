"""Model for the SystemHostname capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `SystemHostname` component (already-captured evidence, not a
new live call; no secret material present). `hostname`/`domain`
identify the specific managed appliance/network -- a judgment call,
not a schema-confirmed secret -- and are redacted by default per this
project's conservative posture on identifying data, matching
`RoutingStaticRoute.gateway`'s established convention for other
non-secret-but-identifying fields.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_SYSTEM_HOSTNAME_IDENTIFYING_FIELDS = ("hostname", "domain")


class SystemHostname(BaseModel):
    hostname: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    domain: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "SystemHostname":
        identifying = {field: data[field] for field in _SYSTEM_HOSTNAME_IDENTIFYING_FIELDS}
        return cls(
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
