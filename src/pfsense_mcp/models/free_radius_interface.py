"""Model for the FreeRADIUSInterface capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`FreeRADIUSInterface` component (already-captured evidence, not a new
live call; no secret material present). Requires `pfSense-pkg-freeradius3`
-- not installed on the LAB used for this project's P1 verification
passes, so this candidate is implemented and offline-tested only;
LAB/registration verification is deferred until the package is
available. `addr` (the listening address) is mildly identifying and is
redacted by default, matching `GatewayConfig.gateway`'s established
convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class FreeRADIUSInterface(BaseModel):
    addr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    port: str
    type: str
    ip_version: str
    description: str

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FreeRADIUSInterface":
        return cls(
            addr=data["addr"] if include_identifying_metadata else None,
            port=data["port"],
            type=data["type"],
            ip_version=data["ip_version"],
            description=data["description"],
        )
