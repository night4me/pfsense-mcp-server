"""Model for the HAProxyDNSResolver capability endpoint
(`/services/haproxy/settings/dns_resolvers`).

All 3 upstream fields retained -- a name plus an IP/FQDN-validated
server address and port, no credential fields exist on this model at
all. `id`/`parent_id` are the plain internal array indices pfREST
assigns (`parent_id` identifies the parent `HAProxySettings` singleton
-- always the same value in practice), not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyDnsResolver(BaseModel):
    id: int
    parent_id: int
    name: str | None
    server: str | None
    port: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyDnsResolver":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            name=data.get("name"),
            server=data.get("server"),
            port=data.get("port"),
        )
