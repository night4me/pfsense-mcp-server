"""Model for the HAProxyFile capability endpoint (`/services/haproxy/files`).

One upstream field deliberately excluded from this model entirely:

- `content` -- the actual bytes of a Lua script, an arbitrary
  `writetodisk`-type file, or an errorfile body (`Base64Field`, no
  length bound). This is genuine file-content retrieval, not metadata
  -- `name`/`type` alone provide a safe, bounded inventory listing.

`id` is the plain internal array index pfREST assigns every list
item, not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFile(BaseModel):
    id: int
    name: str | None
    type: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFile":
        return cls(
            id=data["id"],
            name=data.get("name"),
            type=data.get("type"),
        )
