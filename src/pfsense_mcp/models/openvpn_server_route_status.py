"""Model for the OpenVpnServerRouteStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNServerRouteStatus` component (already-captured
evidence, re-verified during this READ Expansion phase). No secret
material is present. `common_name`/`remote_host`/`virtual_addr` are
real per-connection human/device identity data and are redacted by
default, matching `OpenVpnServerConnectionStatus`'s treatment of the
identical fields.

This model is also embedded, unmodified, as `OpenVpnServerStatus.routes`'s
nested item type -- constructed via `from_api()` there so this
redaction gate stays in effect for the nested case too.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_SERVER_ROUTE_STATUS_IDENTIFYING_FIELDS = ("common_name", "remote_host", "virtual_addr")


class OpenVpnServerRouteStatus(BaseModel):
    last_time: str | None
    common_name: str | None = Field(
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

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "OpenVpnServerRouteStatus":
        identifying = {field: data[field] for field in _OPENVPN_SERVER_ROUTE_STATUS_IDENTIFYING_FIELDS}
        return cls(
            last_time=data["last_time"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
