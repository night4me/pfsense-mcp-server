"""Model for the SystemDNS capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `SystemDNS` component (already-captured evidence, not a new
live call; no secret material present). `dnsserver` (the literal
remote DNS server addresses) is address-bearing and is redacted by
default, matching `GatewayConfig.gateway`'s established convention.
`dnsallowoverride` (a boolean flag) and `dnslocalhost` (an
enum -- `local`/`remote`/unset, not an address) stay visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class SystemDNS(BaseModel):
    dnsallowoverride: bool
    dnslocalhost: str | None
    dnsserver: list[str] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "SystemDNS":
        return cls(
            dnsallowoverride=data["dnsallowoverride"],
            dnslocalhost=data["dnslocalhost"],
            dnsserver=data["dnsserver"] if include_identifying_metadata else None,
        )
