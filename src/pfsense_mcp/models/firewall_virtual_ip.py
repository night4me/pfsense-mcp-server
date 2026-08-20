"""Model for the FirewallVirtualIp capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `VirtualIP` component (already-captured evidence, not a new
live call), then re-checked directly during this READ Expansion phase.

`password` (the CARP VHID shared advertisement secret between HA
peers) is confirmed present in the schema and is **never modeled at
all** -- not even as a conditionally-redacted field -- matching the
established `CertificateAuthority.prv`/`SystemCertificate` precedent
of omitting genuine secret material entirely rather than hiding it
behind a caller-supplied flag. `subnet` (the virtual IP address itself)
and `carp_peer` (the CARP unicast peer address) are address-bearing
identifying fields and are redacted by default, matching
`GatewayConfig`'s established convention. `interface`/`type`/`mode`/
`carp_mode`/`carp_status` are non-address operational fields and stay
visible, matching existing unredacted `interface` field treatment
elsewhere in this codebase.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FIREWALL_VIRTUAL_IP_IDENTIFYING_FIELDS = ("carp_peer", "subnet")


class FirewallVirtualIp(BaseModel):
    advbase: int
    advskew: int
    carp_mode: str
    carp_status: str | None
    descr: str
    interface: str
    mode: str
    noexpand: bool
    subnet_bits: int
    type: str
    uniqid: str | None
    vhid: int
    carp_peer: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    subnet: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FirewallVirtualIp":
        identifying = {field: data[field] for field in _FIREWALL_VIRTUAL_IP_IDENTIFYING_FIELDS}
        return cls(
            advbase=data["advbase"],
            advskew=data["advskew"],
            carp_mode=data["carp_mode"],
            carp_status=data["carp_status"],
            descr=data["descr"],
            interface=data["interface"],
            mode=data["mode"],
            noexpand=data["noexpand"],
            subnet_bits=data["subnet_bits"],
            type=data["type"],
            uniqid=data["uniqid"],
            vhid=data["vhid"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
