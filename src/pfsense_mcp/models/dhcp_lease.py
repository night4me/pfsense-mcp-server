"""Model for the DhcpLease capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: ip/mac/hostname/descr are the whole point of a
DHCP lease inventory capability and stay visible per
administrative-usefulness policy. The committed test fixture
synthesizes descr (this install's real per-device labels) via a
stricter capture policy; ip/mac/hostname are synthesized by the
sanitizer's generic substitution regardless of identifying status.
Runtime behavior is unaffected.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DhcpLease(BaseModel):
    active_status: str | None
    descr: str | None
    ends: str | None
    hostname: str | None
    id: int
    if_: str | None
    ip: str | None
    mac: str | None
    online_status: str | None
    starts: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DhcpLease":
        return cls(
            active_status=data["active_status"],
            descr=data["descr"],
            ends=data["ends"],
            hostname=data["hostname"],
            id=data["id"],
            if_=data["if"],
            ip=data["ip"],
            mac=data["mac"],
            online_status=data["online_status"],
            starts=data["starts"],
        )
