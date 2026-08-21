"""Model for the ServiceWatchdog capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `ServiceWatchdog` component (already-captured evidence, not a
new live call; no secret material present). Requires
`pfSense-pkg-Service_Watchdog` -- not installed on the LAB used for
this project's P1 verification passes, so this candidate is
implemented and offline-tested only; LAB/registration verification is
deferred until the package is available. No field is redacted: this is
simple service-monitoring configuration, not address/device-identifying
data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ServiceWatchdog(BaseModel):
    name: str
    description: str | None
    notify: bool
    enabled: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "ServiceWatchdog":
        return cls(
            name=data["name"],
            description=data["description"],
            notify=data["notify"],
            enabled=data["enabled"],
        )
