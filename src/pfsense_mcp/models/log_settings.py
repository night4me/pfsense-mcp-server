"""Model for the LogSettings capability endpoint.

Field types were derived from the pinned v2.10 OpenAPI schema's
`LogSettings` component (already-captured evidence, not a new live
call; independently re-verified during v0.6.0 Phase A qualification --
34 fields total, all `boolean`/`string`/`integer`, `writeOnly: false`
throughout, no `writeOnly` or secret-shaped field anywhere).

**Widened to match a real v0.6.0 Phase B LAB call** (2026-08-22, this
LAB's CE instance): the pinned schema declares
`auth`/`dhcp`/`dpinger`/`filter`/`hostapd`/`ipprotocol`/`logall`/`ntpd`/
`portalauth`/`ppp`/`remoteserver`/`remoteserver2`/`remoteserver3`/
`resolver`/`routing`/`system`/`sourceip`/`vpn` `nullable: false`, but
the live response returns `null` for every one of them on this LAB
(categories never explicitly toggled/configured return unset rather
than a default `false`/`""`). Live server behavior is trusted over the
schema's stale non-nullable claim here, matching this project's own
established precedent (`DnsResolverSettings.sslcertref`/`.tlsport`,
`SystemRestApiVersion.install_version`). Field *set* is unchanged (all
34 keys present in both the schema and the live response, confirmed via
key-set diff, not just spot-checked) -- this is a nullability widening,
not a new/removed field, so it does not implicate the Batch A schema-
drift mechanism, which is name-based, not type-based, by design.
`sourceip` was initially missed in this widening (caught by a second
live parse attempt after the first fix, not assumed correct on the
first pass) -- the concrete `ValidationError` this raised was itself
evidence the fix wasn't yet complete, not a reason to accept a partial
model.

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
is needed here, consistent with that established distinction -- a null
value carries no information to redact in the first place.
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
    ipprotocol: str | None
    sourceip: str | None
    remoteserver: str | None
    remoteserver2: str | None
    remoteserver3: str | None
    logall: bool | None
    filter: bool | None
    dhcp: bool | None
    auth: bool | None
    portalauth: bool | None
    vpn: bool | None
    dpinger: bool | None
    hostapd: bool | None
    system: bool | None
    resolver: bool | None
    ppp: bool | None
    routing: bool | None
    ntpd: bool | None

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
