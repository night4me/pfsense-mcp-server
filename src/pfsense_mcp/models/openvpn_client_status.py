"""Model for the OpenVpnClientStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNClientStatus` component (already-captured evidence,
re-verified during this READ Expansion phase). No secret material is
present. `local_host`/`remote_host`/`virtual_addr`/`virtual_addr6` are
address-bearing and redacted by default, matching this project's
established convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_CLIENT_STATUS_IDENTIFYING_FIELDS = ("local_host", "remote_host", "virtual_addr", "virtual_addr6")


class OpenVpnClientStatus(BaseModel):
    connect_time: str | None
    local_port: str | None
    mgmt: str | None
    name: str | None
    port: str | None
    remote_port: str | None
    state: str | None
    state_detail: str | None
    status: str | None
    vpnid: int | None
    local_host: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remote_host: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    virtual_addr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    virtual_addr6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "OpenVpnClientStatus":
        identifying = {field: data[field] for field in _OPENVPN_CLIENT_STATUS_IDENTIFYING_FIELDS}
        return cls(
            connect_time=data["connect_time"],
            local_port=data["local_port"],
            mgmt=data["mgmt"],
            name=data["name"],
            port=data["port"],
            remote_port=data["remote_port"],
            state=data["state"],
            state_detail=data["state_detail"],
            status=data["status"],
            vpnid=data["vpnid"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
