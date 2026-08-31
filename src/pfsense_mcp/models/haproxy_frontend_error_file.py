"""Model for the HAProxyFrontendErrorFile capability endpoint
(`/services/haproxy/frontend/error_files`).

Identical shape/risk analysis to `HAProxyBackendErrorFile` -- see that
model's docstring. Metadata-only mapping, no file content.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyFrontendErrorFile(BaseModel):
    id: int
    parent_id: int
    errorcode: int | None
    errorfile: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyFrontendErrorFile":
        return cls(
            id=data["id"],
            parent_id=data["parent_id"],
            errorcode=data.get("errorcode"),
            errorfile=data.get("errorfile"),
        )
