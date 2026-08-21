"""Model for the DHCPRelay capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DHCPRelay` component (already-captured evidence, not a new
live call; no secret material present). `server` (the literal relay
target IPv4 addresses) is address-bearing and is redacted by default,
matching `GatewayConfig.gateway`'s established convention. `interface`
(downstream interface names, not addresses) and `carpstatusvip` (a CARP
VIP selector reference, not a literal address) stay visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class DHCPRelay(BaseModel):
    enable: bool
    interface: list[str]
    agentoption: bool
    carpstatusvip: str
    server: list[str] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "DHCPRelay":
        return cls(
            enable=data["enable"],
            interface=data["interface"],
            agentoption=data["agentoption"],
            carpstatusvip=data["carpstatusvip"],
            server=data["server"] if include_identifying_metadata else None,
        )
