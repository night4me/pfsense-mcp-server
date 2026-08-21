"""Model for the WireGuardPeerStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `WireGuardPeerStatus` component (already-captured evidence),
then re-checked directly during this READ Expansion phase.

`preshared_key` is confirmed present in the schema -- in the *status*
object, not merely the config object -- and is **never modeled at all**,
not even as a conditionally-redacted field, mirroring the established
`VirtualIP.password`/`CertificateAuthority.prv` precedent from this
project's P0 phase. This is an explicit, owner-restated constraint, not
a discretionary judgment call.

`endpoint` (the peer's real-world IP:port) and `allowed_ips` (the
peer's tunnel-internal address ranges) are address-bearing and redacted
by default, matching this project's established convention.
`public_key` stays visible by WireGuard's own design (public keys are
not secrets).

This model is also embedded, unmodified, as `WireGuardTunnelStatus.peers`'s
nested item type -- constructing it via `from_api()` there (rather than
passing through a raw dict) is a security requirement, not a style
choice: a raw-dict passthrough would leak the confirmed `preshared_key`
field verbatim into the tunnel-status tool's output, since the schema
confirms `peers` embeds full `WireGuardPeerStatus` objects.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_WIREGUARD_PEER_STATUS_IDENTIFYING_FIELDS = ("allowed_ips", "endpoint")


class WireGuardPeerStatus(BaseModel):
    descr: str | None
    latest_handshake: int | None
    persistent_keepalive: str | None
    public_key: str | None
    transfer_rx: int | None
    transfer_tx: int | None
    tunnel_device: str | None
    allowed_ips: list[Any] | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    endpoint: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "WireGuardPeerStatus":
        identifying = {field: data[field] for field in _WIREGUARD_PEER_STATUS_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            latest_handshake=data["latest_handshake"],
            persistent_keepalive=data["persistent_keepalive"],
            public_key=data["public_key"],
            transfer_rx=data["transfer_rx"],
            transfer_tx=data["transfer_tx"],
            tunnel_device=data["tunnel_device"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
