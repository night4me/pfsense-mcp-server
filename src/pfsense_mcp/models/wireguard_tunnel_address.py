"""Model for the WireGuardTunnelAddress capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`WireGuardTunnelAddress` component (already-captured evidence, not a
new live call; independently re-verified during v0.6.0 Phase A
qualification -- `address`, `mask`, `descr`, all `writeOnly: false`, no
secret material). `address`/`mask` are address-bearing fields and are
redacted by default, matching `RoutingStaticRoute.network`/`.gateway`'s
established convention -- consistent with this project's own original
P1 candidate audit, which already flagged both fields for redaction.

Confirmed NOT redundant with the already-shipped `WireGuardTunnelStatus`:
that model has no address/CIDR field at all (only
`name`/`status`/`public_key`/`listen_port`/`mtu`/transfer
counters/`peers`), so this is genuinely new config-side information,
unlike `WireGuardPeerAllowedIP` (deliberately not implemented -- already
nested as `WireGuardPeerStatus.allowed_ips`).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_WIREGUARD_TUNNEL_ADDRESS_IDENTIFYING_FIELDS = ("address", "mask")


class WireGuardTunnelAddress(BaseModel):
    descr: str
    address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    mask: int | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "WireGuardTunnelAddress":
        identifying = {field: data[field] for field in _WIREGUARD_TUNNEL_ADDRESS_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
