"""Model for the HAProxyApply capability endpoint (`/services/haproxy/apply`).

Single field, source-confirmed safe (a filesystem dirty-marker
boolean, package-independent). Live-verified 2026-08-30
(`POST_V1_1_HAPROXY_READ_QUALIFICATION.md` live-ceremony addendum):
`{"applied": true}` with HAProxy absent from LAB.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class HAProxyApplyStatus(BaseModel):
    applied: bool | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "HAProxyApplyStatus":
        return cls(applied=data.get("applied"))
