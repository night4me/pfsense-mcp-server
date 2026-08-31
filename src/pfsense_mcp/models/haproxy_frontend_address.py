"""Model for the HAProxyFrontendAddress capability endpoint
(`/services/haproxy/frontend/addresses`).

One upstream field deliberately excluded from this model entirely:

- `exaddr_advanced` -- "advanced configuration to apply to this
  address", a `StringField` raw-config-injection channel.

`id`/`parent_id` are the plain internal array indices pfREST assigns
(`parent_id` identifies which frontend this address belongs to), not
identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFrontendAddress(BaseModel):
    id: int
    parent_id: int
    extaddr: str | None
    extaddr_custom: str | None
    extaddr_port: str | None
    extaddr_ssl: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFrontendAddress":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            extaddr=data.get("extaddr"),
            extaddr_custom=data.get("extaddr_custom"),
            extaddr_port=data.get("extaddr_port"),
            extaddr_ssl=data.get("extaddr_ssl"),
        )
