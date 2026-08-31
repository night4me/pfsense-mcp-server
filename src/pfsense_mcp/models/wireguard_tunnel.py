"""Model for the WireGuardTunnel capability endpoint (`GET
/vpn/wireguard/tunnels`) -- the tunnel *configuration* list, distinct
from the already-shipped `WireGuardTunnelStatus`
(`pfsense_get_status_wireguard_tunnels`, live runtime state) and
`WireGuardTunnelAddress` (`pfsense_get_vpn_wireguard_tunnel_addresses`,
the address sub-resource).

Field types/nullability derived from a freshly-fetched (not cached)
live `pfrest.org` OpenAPI document during
POST_V1_1_FINAL_READ_CLOSURE_AND_FULL_HARDENING Phase 3 qualification.
No field in this component is schema-documented as conditionally
available ("only available when"), so every field is read via direct
`data[...]` access.

`privatekey` is **never modeled**, not even as a conditionally-redacted
field -- literal WireGuard private key material, the same secret class
as `WireGuardPeer.presharedkey`/`IPsecPhase1.pre_shared_key`.
`publickey` stays visible by WireGuard's own design (public keys are
not secrets, matching the already-established `WireGuardPeerStatus`
precedent).

`addresses` is also excluded, for a different reason: it is redundant,
not sensitive -- this component's own `addresses` array embeds full
`WireGuardTunnelAddress`-shaped objects, and that sub-resource already
has its own dedicated, already-shipped tool
(`pfsense_get_vpn_wireguard_tunnel_addresses`), which itself applies
`include_identifying_metadata` redaction to the literal address/mask
values. Re-embedding the same data here unredacted would silently
bypass that existing redaction boundary.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class WireGuardTunnel(BaseModel):
    name: str | None
    enabled: bool
    descr: str
    listenport: str
    publickey: str | None
    mtu: int

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "WireGuardTunnel":
        return cls(
            name=data["name"],
            enabled=data["enabled"],
            descr=data["descr"],
            listenport=data["listenport"],
            publickey=data["publickey"],
            mtu=data["mtu"],
        )
