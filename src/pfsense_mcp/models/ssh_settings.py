"""Model for the SshSettings capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class SshSettings(BaseModel):
    enable: bool
    port: str
    sshdagentforwarding: bool
    sshdkeyonly: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "SshSettings":
        return cls(
            enable=data["enable"],
            port=data["port"],
            sshdagentforwarding=data["sshdagentforwarding"],
            sshdkeyonly=data["sshdkeyonly"],
        )
