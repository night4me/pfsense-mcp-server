"""Model for the HAProxyBackendErrorFile capability endpoint
(`/services/haproxy/backend/errorfiles`).

Metadata-only mapping (an HTTP status code plus a `ForeignModelField`
name-reference to a `HAProxyFile`) -- no file content. `id`/`parent_id`
are the plain internal array indices pfREST assigns, not
identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyBackendErrorFile(BaseModel):
    id: int
    parent_id: int
    errorcode: int | None
    errorfile: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyBackendErrorFile":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            errorcode=data.get("errorcode"),
            errorfile=data.get("errorfile"),
        )
