"""Model for the FreeRADIUSMAC capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `FreeRADIUSMAC` component (already-captured evidence, not a
new live call; no secret material present). Requires
`pfSense-pkg-freeradius3` -- not installed on the LAB used for this
project's P1 verification passes, so this candidate is implemented and
offline-tested only; LAB/registration verification is deferred until
the package is available. `mac` and the five `framed_*` fields
(literal client MAC/IP/route data) are identifying and are redacted by
default, matching `InterfaceStatus.macaddr`/`GatewayConfig.gateway`'s
established conventions -- the largest identifying-field set in this
project's admin/config category.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FREE_RADIUS_MAC_IDENTIFYING_FIELDS = (
    "mac",
    "framed_ip_address",
    "framed_ip_netmask",
    "framed_route",
    "framed_ipv6_address",
    "framed_ipv6_route",
)


class FreeRADIUSMAC(BaseModel):
    mac: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    description: str
    framed_ip_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    framed_ip_netmask: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    framed_route: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    framed_ipv6_address: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    framed_ipv6_route: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    vlan_id: str
    wispr_redirection_url: str
    simultaneous_connect: int | None
    expiration: str
    session_timeout: int | None
    login_time: str
    amount_of_time: int | None
    point_of_time: str
    max_total_octets: int | None
    max_total_octets_time_range: str
    max_bandwidth_down: int | None
    max_bandwidth_up: int | None
    acct_interim_interval: int | None
    top_additional_options: list[Any]
    check_items_additional_options: list[Any]
    reply_items_additional_options: list[Any]

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FreeRADIUSMAC":
        identifying = {field: data[field] for field in _FREE_RADIUS_MAC_IDENTIFYING_FIELDS}
        return cls(
            description=data["description"],
            vlan_id=data["vlan_id"],
            wispr_redirection_url=data["wispr_redirection_url"],
            simultaneous_connect=data["simultaneous_connect"],
            expiration=data["expiration"],
            session_timeout=data["session_timeout"],
            login_time=data["login_time"],
            amount_of_time=data["amount_of_time"],
            point_of_time=data["point_of_time"],
            max_total_octets=data["max_total_octets"],
            max_total_octets_time_range=data["max_total_octets_time_range"],
            max_bandwidth_down=data["max_bandwidth_down"],
            max_bandwidth_up=data["max_bandwidth_up"],
            acct_interim_interval=data["acct_interim_interval"],
            top_additional_options=data["top_additional_options"],
            check_items_additional_options=data["check_items_additional_options"],
            reply_items_additional_options=data["reply_items_additional_options"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
