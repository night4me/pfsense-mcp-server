"""Model for the SystemTimezone capability endpoint.

Field type was derived from the pinned v2.10 OpenAPI schema's
`SystemTimezone` component (already-captured evidence, not a new live
call; no secret material present). `timezone` is a general
configuration value, not address/device-identifying data, and stays
visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SystemTimezone(BaseModel):
    timezone: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SystemTimezone":
        return cls(timezone=data["timezone"])
