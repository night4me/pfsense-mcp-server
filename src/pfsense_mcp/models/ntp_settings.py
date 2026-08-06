"""Model for the NtpSettings capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class NtpSettings(BaseModel):
    clockstats: bool
    dnsresolv: str
    enable: bool
    interface: list[str] | None
    leapsec: str | None
    logpeer: bool
    logsys: bool
    loopstats: bool
    ntpmaxpeers: int
    ntpmaxpoll: str | None
    ntpminpoll: str | None
    orphan: int
    peerstats: bool
    serverauth: bool
    serverauthalgo: str
    statsgraph: bool

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "NtpSettings":
        return cls(
            clockstats=data["clockstats"],
            dnsresolv=data["dnsresolv"],
            enable=data["enable"],
            interface=data["interface"],
            leapsec=data["leapsec"],
            logpeer=data["logpeer"],
            logsys=data["logsys"],
            loopstats=data["loopstats"],
            ntpmaxpeers=data["ntpmaxpeers"],
            ntpmaxpoll=data["ntpmaxpoll"],
            ntpminpoll=data["ntpminpoll"],
            orphan=data["orphan"],
            peerstats=data["peerstats"],
            serverauth=data["serverauth"],
            serverauthalgo=data["serverauthalgo"],
            statsgraph=data["statsgraph"],
        )
