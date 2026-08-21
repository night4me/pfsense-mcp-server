"""Model for the DHCPServerAddressPool capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `DHCPServerAddressPool` component (already-captured evidence,
not a new live call; no secret material present). This resource's
schema-declared `Parent model` is `DHCPServer` -- the identical
relationship already resolved for `DhcpServer` itself, whose own
docstring establishes that range/gateway/DNS/NTP/WINS/MAC-allow-deny
data is "the whole point of a DHCP server (scope) configuration
capability" and stays visible per administrative-usefulness policy, no
redaction. Applied identically here for consistency: no field is
redacted. `domain`/`domainsearchlist`/`gateway`/`mac_allow`/`mac_deny`
are widened to also accept `None`, matching the exact set of fields
`DhcpServer` itself needed widening for after the CE 2.8.1 -> 2.9.0
platform-upgrade regression finding (an unconfigured optional field
can genuinely return `null` on this LAB baseline despite the pinned
schema's `nullable: false` claim).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DHCPServerAddressPool(BaseModel):
    range_from: str
    range_to: str
    domain: str | None
    mac_allow: list[str] | None
    mac_deny: list[str] | None
    domainsearchlist: list[str] | None
    defaultleasetime: int | None
    maxleasetime: int | None
    gateway: str | None
    dnsserver: list[str] | None
    winsserver: list[str] | None
    ntpserver: list[str] | None
    ignorebootp: bool
    ignoreclientuids: bool
    denyunknown: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DHCPServerAddressPool":
        return cls(
            range_from=data["range_from"],
            range_to=data["range_to"],
            domain=data["domain"],
            mac_allow=data["mac_allow"],
            mac_deny=data["mac_deny"],
            domainsearchlist=data["domainsearchlist"],
            defaultleasetime=data["defaultleasetime"],
            maxleasetime=data["maxleasetime"],
            gateway=data["gateway"],
            dnsserver=data["dnsserver"],
            winsserver=data["winsserver"],
            ntpserver=data["ntpserver"],
            ignorebootp=data["ignorebootp"],
            ignoreclientuids=data["ignoreclientuids"],
            denyunknown=data["denyunknown"],
        )
