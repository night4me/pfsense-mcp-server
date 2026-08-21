"""Model for the OpenVpnClientSpecificOverride capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNClientSpecificOverride` component (already-captured
evidence, not a new live call; no secret material present -- no field
is marked `writeOnly`). `common_name` is real per-client identity data
and, along with `local_network`/`local_networkv6`/`remote_network`/
`remote_networkv6`/`tunnel_network`/`tunnel_networkv6`/`dns_server1-4`/
`ntp_server1-2`/`wins_server1-2` (literal network/address data), is
redacted by default, matching `RoutingStaticRoute.gateway`'s
established convention -- the network-list fields redact to an empty
list, the scalar fields redact to `None`. Of this component's 27
fields, 5 are schema-documented as "only available when" a specific
condition is met and are treated as genuinely possibly-absent via
`.get()`, matching the `InterfaceLAGG` precedent.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_CSO_IDENTIFYING_SCALAR_FIELDS = (
    "common_name",
    "tunnel_network",
    "tunnel_networkv6",
    "dns_server1",
    "dns_server2",
    "dns_server3",
    "dns_server4",
    "ntp_server1",
    "ntp_server2",
    "wins_server1",
    "wins_server2",
)
_OPENVPN_CSO_IDENTIFYING_LIST_FIELDS = (
    "local_network",
    "local_networkv6",
    "remote_network",
    "remote_networkv6",
)


def _redacted_scalar() -> Any:
    return Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


def _redacted_list() -> Any:
    return Field(
        default_factory=list,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )


class OpenVpnClientSpecificOverride(BaseModel):
    common_name: str | None = _redacted_scalar()
    disable: bool
    block: bool
    description: str
    server_list: list[str]
    tunnel_network: str | None = _redacted_scalar()
    tunnel_networkv6: str | None = _redacted_scalar()
    local_network: list[str] = _redacted_list()
    local_networkv6: list[str] = _redacted_list()
    remote_network: list[str] = _redacted_list()
    remote_networkv6: list[str] = _redacted_list()
    gwredir: bool
    push_reset: bool
    dns_domain: str
    dns_server1: str | None = _redacted_scalar()
    dns_server2: str | None = _redacted_scalar()
    dns_server3: str | None = _redacted_scalar()
    dns_server4: str | None = _redacted_scalar()
    ntp_server1: str | None = _redacted_scalar()
    ntp_server2: str | None = _redacted_scalar()
    netbios_enable: bool
    custom_options: list[str]

    remove_options: list[str]
    netbios_ntype: int | None
    netbios_scope: str | None
    wins_server1: str | None = _redacted_scalar()
    wins_server2: str | None = _redacted_scalar()

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "OpenVpnClientSpecificOverride":
        identifying_scalars: dict[str, Any] = (
            {field: data.get(field) for field in _OPENVPN_CSO_IDENTIFYING_SCALAR_FIELDS}
            if include_identifying_metadata
            else dict.fromkeys(_OPENVPN_CSO_IDENTIFYING_SCALAR_FIELDS)
        )
        identifying_lists: dict[str, Any] = (
            {field: data.get(field, []) for field in _OPENVPN_CSO_IDENTIFYING_LIST_FIELDS}
            if include_identifying_metadata
            else {field: [] for field in _OPENVPN_CSO_IDENTIFYING_LIST_FIELDS}
        )
        return cls(
            disable=data["disable"],
            block=data["block"],
            description=data["description"],
            server_list=data["server_list"],
            gwredir=data["gwredir"],
            push_reset=data["push_reset"],
            dns_domain=data["dns_domain"],
            netbios_enable=data["netbios_enable"],
            custom_options=data["custom_options"],
            remove_options=data.get("remove_options", []),
            netbios_ntype=data.get("netbios_ntype"),
            netbios_scope=data.get("netbios_scope"),
            **identifying_scalars,
            **identifying_lists,
        )
