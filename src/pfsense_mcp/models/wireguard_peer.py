"""Model for the WireGuardPeer capability endpoint (`GET
/vpn/wireguard/peers`) -- the peer *configuration* list, distinct from
the already-shipped `WireGuardPeerStatus`
(`pfsense_get_status_wireguard_peers`, live runtime state).

Field types/nullability derived from a freshly-fetched (not cached)
live `pfrest.org` OpenAPI document during
POST_V1_1_FINAL_READ_CLOSURE_AND_FULL_HARDENING Phase 3 qualification.
`port` is the only field schema-documented as conditionally available
("only available when"); it declares a schema default of `51820` and
is read via `.get()` with that fallback, matching the
`OpenVpnServer`/`WireGuardSettings` established convention for such
fields.

`presharedkey` is **never modeled**, not even as a conditionally-
redacted field -- literal WireGuard pre-shared key material, the same
secret class as `WireGuardTunnel.privatekey`/`IPsecPhase1.pre_shared_key`.
`publickey` stays visible by WireGuard's own design (public keys are
not secrets).

`allowedips` is also excluded, for a different reason: it is
redundant, not sensitive. The already-shipped `WireGuardPeerStatus`
model's own docstring explicitly records that a dedicated
`WireGuardPeerAllowedIP` tool was "deliberately not implemented --
already nested as `WireGuardPeerStatus.allowed_ips`" (itself an
`include_identifying_metadata`-redacted field on the existing
`pfsense_get_status_wireguard_peers` tool); re-exposing the same list
unredacted here would silently bypass that already-established
redaction boundary.

`endpoint` (the peer's real-world IP:port) is address-bearing and
redacted by default via `include_identifying_metadata`, matching
`WireGuardPeerStatus.endpoint`'s own established convention exactly.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_WIREGUARD_PEER_IDENTIFYING_FIELDS = ("endpoint",)


class WireGuardPeer(BaseModel):
    enabled: bool
    tun: str
    port: str
    descr: str
    persistentkeepalive: int | None
    publickey: str
    endpoint: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "WireGuardPeer":
        identifying = {field: data.get(field) for field in _WIREGUARD_PEER_IDENTIFYING_FIELDS}
        return cls(
            enabled=data["enabled"],
            tun=data["tun"],
            port=data.get("port", "51820"),
            descr=data["descr"],
            persistentkeepalive=data["persistentkeepalive"],
            publickey=data["publickey"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
