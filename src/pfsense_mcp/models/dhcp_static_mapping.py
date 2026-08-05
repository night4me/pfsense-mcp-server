"""Model for the DhcpStaticMapping capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: mac/ipaddr/hostname/descr are the whole point of
a DHCP static-mapping inventory capability and stay visible per
administrative-usefulness policy; the rest are ordinary DHCP option
overrides. The committed test fixture synthesizes descr (this
install's real per-device labels) via a stricter capture policy;
mac/ipaddr/hostname are synthesized by the sanitizer's generic
substitution regardless of identifying status. Runtime behavior is
unaffected.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class DhcpStaticMapping(BaseModel):
    arp_table_static_entry: bool
    cid: str | None
    defaultleasetime: int | None
    descr: str
    dnsserver: list[str] | None
    domain: str
    domainsearchlist: list[str]
    gateway: str
    hostname: str | None
    id: int
    ipaddr: str | None
    mac: str
    maxleasetime: int | None
    ntpserver: list[str] | None
    parent_id: str
    winsserver: list[str] | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "DhcpStaticMapping":
        return cls(
            arp_table_static_entry=data["arp_table_static_entry"],
            cid=data["cid"],
            defaultleasetime=data["defaultleasetime"],
            descr=data["descr"],
            dnsserver=data["dnsserver"],
            domain=data["domain"],
            domainsearchlist=data["domainsearchlist"],
            gateway=data["gateway"],
            hostname=data["hostname"],
            id=data["id"],
            ipaddr=data["ipaddr"],
            mac=data["mac"],
            maxleasetime=data["maxleasetime"],
            ntpserver=data["ntpserver"],
            parent_id=data["parent_id"],
            winsserver=data["winsserver"],
        )
