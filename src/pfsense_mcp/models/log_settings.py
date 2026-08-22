"""Model for the LogSettings capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`LogSettings` component (already-captured evidence, not a new live
call; independently re-verified during v0.6.0 Phase A qualification --
34 fields total, all `boolean`/`string`/`integer`, `writeOnly: false`
throughout, no `writeOnly` or secret-shaped field anywhere).

Content is entirely: which categories to log (`nologdefaultblock`,
`auth`, `portalauth`, `dhcp`, `vpn`, etc. -- boolean toggles, not log
content or credentials), rotation/retention
(`logfilesize`/`rotatecount`/`logcompressiontype`), and remote syslog
destination (`remoteserver`/`remoteserver2`/`remoteserver3`/`sourceip`/
`ipprotocol`). The remote-syslog-destination fields are server-address
*configuration*, the same sensitivity class as `NtpTimeServer.timeserver`
(this project's existing, unredacted precedent for "where do I send
this to" settings) -- not the tunnel/gateway/peer *topology* fields this
project does redact by default (e.g. `RoutingStaticRoute.gateway`,
`IPsecPhase2.remoteid_address`). No `include_identifying_metadata` gate
is needed here, consistent with that established distinction.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class LogSettings(BaseModel):
    format: str
    reverseorder: bool
    nentries: int
    nologdefaultblock: bool
    nologdefaultpass: bool
    nologbogons: bool
    nologprivatenets: bool
    nolognginx: bool
    rawfilter: bool
    disablelocallogging: bool
    logconfigchanges: bool
    filterdescriptions: int
    logfilesize: int
    rotatecount: int
    logcompressiontype: str
    enableremotelogging: bool
    ipprotocol: str
    sourceip: str
    remoteserver: str
    remoteserver2: str
    remoteserver3: str
    logall: bool
    filter: bool
    dhcp: bool
    auth: bool
    portalauth: bool
    vpn: bool
    dpinger: bool
    hostapd: bool
    system: bool
    resolver: bool
    ppp: bool
    routing: bool
    ntpd: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "LogSettings":
        return cls(
            format=data["format"],
            reverseorder=data["reverseorder"],
            nentries=data["nentries"],
            nologdefaultblock=data["nologdefaultblock"],
            nologdefaultpass=data["nologdefaultpass"],
            nologbogons=data["nologbogons"],
            nologprivatenets=data["nologprivatenets"],
            nolognginx=data["nolognginx"],
            rawfilter=data["rawfilter"],
            disablelocallogging=data["disablelocallogging"],
            logconfigchanges=data["logconfigchanges"],
            filterdescriptions=data["filterdescriptions"],
            logfilesize=data["logfilesize"],
            rotatecount=data["rotatecount"],
            logcompressiontype=data["logcompressiontype"],
            enableremotelogging=data["enableremotelogging"],
            ipprotocol=data["ipprotocol"],
            sourceip=data["sourceip"],
            remoteserver=data["remoteserver"],
            remoteserver2=data["remoteserver2"],
            remoteserver3=data["remoteserver3"],
            logall=data["logall"],
            filter=data["filter"],
            dhcp=data["dhcp"],
            auth=data["auth"],
            portalauth=data["portalauth"],
            vpn=data["vpn"],
            dpinger=data["dpinger"],
            hostapd=data["hostapd"],
            system=data["system"],
            resolver=data["resolver"],
            ppp=data["ppp"],
            routing=data["routing"],
            ntpd=data["ntpd"],
        )
