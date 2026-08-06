"""Model for the ArpTableEntry capability endpoint.

Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class ArpTableEntry(BaseModel):
    dnsresolve: str | None
    expires: str | None
    hostname: str | None
    id: int
    interface: str | None
    ip_address: str | None
    mac_address: str | None
    permanent: bool | None
    type: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "ArpTableEntry":
        return cls(
            dnsresolve=data["dnsresolve"],
            expires=data["expires"],
            hostname=data["hostname"],
            id=data["id"],
            interface=data["interface"],
            ip_address=data["ip_address"],
            mac_address=data["mac_address"],
            permanent=data["permanent"],
            type=data["type"],
        )
