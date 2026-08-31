"""Model for the ServiceWatchdog capability endpoint (`GET
/services/service_watchdogs`).

Field types/nullability derived from a freshly-fetched (not cached)
live `pfrest.org` OpenAPI document during
POST_V1_1_FINAL_READ_CLOSURE_AND_FULL_HARDENING Phase 3 qualification.
All 4 fields (`name`, `description`, `notify`, `enabled`) are plain
scalar toggles/labels -- no secret material, no address/network data,
no free-text config-injection field. No exclusion or redaction is
needed; this is a trivial SAFE_READ candidate.
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
