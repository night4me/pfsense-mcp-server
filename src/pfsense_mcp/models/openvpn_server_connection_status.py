"""Model for the OpenVpnServerConnectionStatus capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OpenVPNServerConnectionStatus` component (already-captured
evidence, re-verified during this READ Expansion phase). No secret
material is present. `common_name`/`remote_host`/`virtual_addr`/
`virtual_addr6`/`user_name` are real per-connection human/device
identity data -- not merely network topology -- and are redacted by
default like other identifying fields, matching this project's
established convention, with the extra care this class of field
warrants noted explicitly (owner-flagged elevated care, not a schema-
driven distinction).

This model is also embedded, unmodified, as `OpenVpnServerStatus.conns`'s
nested item type -- constructed via `from_api()` there so this
redaction gate stays in effect for the nested case too.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_OPENVPN_SERVER_CONNECTION_STATUS_IDENTIFYING_FIELDS = (
    "common_name",
    "remote_host",
    "user_name",
    "virtual_addr",
    "virtual_addr6",
)


class OpenVpnServerConnectionStatus(BaseModel):
    bytes_recv: int | None
    bytes_sent: int | None
    cipher: str | None
    client_id: int | None
    connect_time: str | None
    connect_time_unix: int | None
    peer_id: int | None
    common_name: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    remote_host: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    user_name: str | None = Field(
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
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "OpenVpnServerConnectionStatus":
        identifying = {field: data[field] for field in _OPENVPN_SERVER_CONNECTION_STATUS_IDENTIFYING_FIELDS}
        return cls(
            bytes_recv=data["bytes_recv"],
            bytes_sent=data["bytes_sent"],
            cipher=data["cipher"],
            client_id=data["client_id"],
            connect_time=data["connect_time"],
            connect_time_unix=data["connect_time_unix"],
            peer_id=data["peer_id"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
