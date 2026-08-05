"""Model for the DhcpServer capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: range/gateway/DNS/NTP/WINS/MAC-allow-deny and the
embedded static-mapping entries are the whole point of a DHCP server
(scope) configuration capability and stay visible per
administrative-usefulness policy. The committed test fixture
synthesizes the nested staticmap `descr` field (this install's real
per-device labels) via a stricter capture policy; IP/MAC/domain values
are synthesized by the sanitizer's generic substitution regardless of
identifying status. Runtime behavior is unaffected.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DhcpServer(BaseModel):
    defaultleasetime: int | None
    denyunknown: str | None
    dhcpleaseinlocaltime: bool
    disablepingcheck: bool
    dnsserver: list[str] | None
    domain: str
    domainsearchlist: list[str]
    enable: bool
    failover_peerip: str
    gateway: str
    id: str
    ignorebootp: bool
    ignoreclientuids: bool
    interface: str
    mac_allow: list[str]
    mac_deny: list[str]
    maxleasetime: int | None
    nonak: bool
    ntpserver: list[str] | None
    numberoptions: list[Any] | None
    pool: list[Any]
    range_from: str
    range_to: str
    staticarp: bool
    staticmap: list[Any]
    statsgraph: bool
    winsserver: list[str] | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DhcpServer":
        return cls(
            defaultleasetime=data["defaultleasetime"],
            denyunknown=data["denyunknown"],
            dhcpleaseinlocaltime=data["dhcpleaseinlocaltime"],
            disablepingcheck=data["disablepingcheck"],
            dnsserver=data["dnsserver"],
            domain=data["domain"],
            domainsearchlist=data["domainsearchlist"],
            enable=data["enable"],
            failover_peerip=data["failover_peerip"],
            gateway=data["gateway"],
            id=data["id"],
            ignorebootp=data["ignorebootp"],
            ignoreclientuids=data["ignoreclientuids"],
            interface=data["interface"],
            mac_allow=data["mac_allow"],
            mac_deny=data["mac_deny"],
            maxleasetime=data["maxleasetime"],
            nonak=data["nonak"],
            ntpserver=data["ntpserver"],
            numberoptions=data["numberoptions"],
            pool=data["pool"],
            range_from=data["range_from"],
            range_to=data["range_to"],
            staticarp=data["staticarp"],
            staticmap=data["staticmap"],
            statsgraph=data["statsgraph"],
            winsserver=data["winsserver"],
        )
