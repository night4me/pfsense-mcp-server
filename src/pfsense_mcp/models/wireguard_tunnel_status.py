"""Model for the WireGuardTunnelStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `WireGuardTunnelStatus` component (already-captured evidence).
No secret material on this component itself (`public_key` only, no
`privatekey` -- unlike the config-object `WireGuardTunnel`, which
remains REJECTed separately). No address-bearing top-level field
either, so no redaction gate is required at this level.

`peers` is schema-confirmed (`$ref`) to embed full `WireGuardPeerStatus`
objects -- it is therefore constructed through
`WireGuardPeerStatus.from_api()` for every item, never passed through
as a raw dict. This is a hard security requirement: `WireGuardPeerStatus`
carries a confirmed `preshared_key` field in the underlying API response
that its own model deliberately never exposes; a raw-dict passthrough
here would silently leak that value verbatim into this tool's output.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from .wireguard_peer_status import WireGuardPeerStatus


class WireGuardTunnelStatus(BaseModel):
    descr: str | None
    inpkts: int | None
    listen_port: str | None
    mtu: int | None
    name: str | None
    outpkts: int | None
    public_key: str | None
    status: str | None
    transfer_rx: int | None
    transfer_tx: int | None
    peers: list[WireGuardPeerStatus] | None

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "WireGuardTunnelStatus":
        raw_peers = data["peers"]
        peers = (
            [
                WireGuardPeerStatus.from_api(item, include_identifying_metadata=include_identifying_metadata)
                for item in raw_peers
            ]
            if raw_peers is not None
            else None
        )
        return cls(
            descr=data["descr"],
            inpkts=data["inpkts"],
            listen_port=data["listen_port"],
            mtu=data["mtu"],
            name=data["name"],
            outpkts=data["outpkts"],
            public_key=data["public_key"],
            status=data["status"],
            transfer_rx=data["transfer_rx"],
            transfer_tx=data["transfer_tx"],
            peers=peers,
        )
