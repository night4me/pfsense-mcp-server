"""Model for the SystemHaSync capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. `password` is
declared in the OpenAPI schema but pfSense's own GET response never
includes it (a write-only secret field, same pattern as
system_rest_api_settings' ha_sync_password) -- deliberately excluded
from this model entirely. `username` pairs with that omitted password
field for HA-peer sync authentication, and `pfhostid` is a persistent
per-installation host identifier (same class as netgate_id/serial);
both are identifying and redacted to null by default. Every
`synchronize*` flag and `pfsyncpeerip`/`synchronizetoip` are ordinary
HA-sync configuration and stay visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_SYSTEM_HA_SYNC_IDENTIFYING_FIELDS = (
    "pfhostid",
    "username",
)


class SystemHaSync(BaseModel):
    adminsync: bool
    pfsyncenabled: bool
    pfsyncinterface: str
    pfsyncpeerip: str | None
    synchronizealiases: bool
    synchronizeauthservers: bool
    synchronizecaptiveportal: bool
    synchronizecerts: bool
    synchronizedhcpd: bool
    synchronizedhcpdv6: bool
    synchronizedhcrelay: bool
    synchronizedhcrelay6: bool
    synchronizednsforwarder: bool
    synchronizeipsec: bool
    synchronizekea6: bool
    synchronizenat: bool
    synchronizeopenvpn: bool
    synchronizerules: bool
    synchronizeschedules: bool
    synchronizestaticroutes: bool
    synchronizetoip: str | None
    synchronizetrafficshaper: bool
    synchronizetrafficshaperlimiter: bool
    synchronizeusers: bool
    synchronizevirtualip: bool
    synchronizewol: bool
    pfhostid: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    username: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "SystemHaSync":
        identifying = {field: data[field] for field in _SYSTEM_HA_SYNC_IDENTIFYING_FIELDS}
        return cls(
            adminsync=data["adminsync"],
            pfsyncenabled=data["pfsyncenabled"],
            pfsyncinterface=data["pfsyncinterface"],
            pfsyncpeerip=data["pfsyncpeerip"],
            synchronizealiases=data["synchronizealiases"],
            synchronizeauthservers=data["synchronizeauthservers"],
            synchronizecaptiveportal=data["synchronizecaptiveportal"],
            synchronizecerts=data["synchronizecerts"],
            synchronizedhcpd=data["synchronizedhcpd"],
            synchronizedhcpdv6=data["synchronizedhcpdv6"],
            synchronizedhcrelay=data["synchronizedhcrelay"],
            synchronizedhcrelay6=data["synchronizedhcrelay6"],
            synchronizednsforwarder=data["synchronizednsforwarder"],
            synchronizeipsec=data["synchronizeipsec"],
            synchronizekea6=data["synchronizekea6"],
            synchronizenat=data["synchronizenat"],
            synchronizeopenvpn=data["synchronizeopenvpn"],
            synchronizerules=data["synchronizerules"],
            synchronizeschedules=data["synchronizeschedules"],
            synchronizestaticroutes=data["synchronizestaticroutes"],
            synchronizetoip=data["synchronizetoip"],
            synchronizetrafficshaper=data["synchronizetrafficshaper"],
            synchronizetrafficshaperlimiter=data["synchronizetrafficshaperlimiter"],
            synchronizeusers=data["synchronizeusers"],
            synchronizevirtualip=data["synchronizevirtualip"],
            synchronizewol=data["synchronizewol"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
