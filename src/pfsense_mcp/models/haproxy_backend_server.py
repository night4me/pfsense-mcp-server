"""Model for the HAProxyBackendServer capability endpoint
(`/services/haproxy/backend/servers`).

One upstream field deliberately excluded from this model entirely:

- `advanced` -- "custom HAProxy server settings", a `StringField`
  raw-config-injection channel (same class of finding as
  `HAProxyBackend.advanced`/`.advanced_backend`).

`id`/`parent_id` are the plain internal array indices pfREST assigns
(`parent_id` identifies which backend this server belongs to), not
identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyBackendServer(BaseModel):
    id: int
    parent_id: int
    name: str | None
    status: str | None
    address: str | None
    port: str | None
    weight: int | None
    ssl: bool | None
    sslserververify: bool | None
    serverid: int | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyBackendServer":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data.get("name"),
            status=data.get("status"),
            address=data.get("address"),
            port=data.get("port"),
            weight=data.get("weight"),
            ssl=data.get("ssl"),
            sslserververify=data.get("sslserververify"),
            serverid=data.get("serverid"),
        )
