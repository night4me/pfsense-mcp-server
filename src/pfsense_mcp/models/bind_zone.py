"""Model for the BINDZone capability endpoint.

Field types/nullability derived from the live pfrest.org v2.10.2
OpenAPI document (fetched 2026-08-30,
`POST_V1_1_BIND_READ_QUALIFICATION.md`). Three fields are deliberately
excluded from this model entirely (matching this project's established
`SystemRestApiSettings.ha_sync_password` precedent for structural
field exclusion), per the qualification report's Phase 3 review:

- `custom`, `customzonerecords` -- raw BIND-config/zone-file text
  fragments injected verbatim into the generated configuration by the
  actual pfrest/pfSense-pkg-RESTAPI implementation; could carry
  arbitrary operator-pasted text, including secrets.
- `records` -- the zone's full nested record list, schema-bounded at
  up to 65535 items per zone with no per-zone pagination on this
  endpoint; excluded to avoid an unbounded response (Class F). Use the
  separate `pfsense_get_bind_zone_record` tool for individual record
  lookups instead.

19 of the remaining 27 fields are schema-documented as conditionally
present, gated on `type` (master/slave/forward/redirect) and a handful
of interdependent flags (e.g. `updatepolicy` requires both
`type == 'master'` and `enable_updatepolicy == true`) -- modeled as
`Optional` with `.get()` rather than required, matching this project's
established handling of the same conditional-availability pattern
elsewhere (e.g. `WireGuardSettings.resolve_interval`). No live-
populated zone of any `type` was observed this session (the
qualification ceremony's `zones` GET returned an empty list, since no
zone has ever been configured on this never-installed-BIND LAB), so
this is modeled from the schema's own documented conditionality, not
guessed. Only `id`, `disabled`, `name`, `description`, `type`, `view`,
`allowquery`, and `regdhcpstatic` are schema-documented as always
present regardless of zone type. `id` is the plain internal array
index pfREST assigns every list item, not identifying/sensitive data.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindZone(BaseModel):
    id: int
    disabled: bool
    name: str
    description: str
    type: str
    view: list[str]
    allowquery: list[str]
    regdhcpstatic: bool
    # Conditional on type in [master, slave]:
    reversev4: bool | None
    reversev6: bool | None
    rpz: bool | None
    dnssec: bool | None
    # Conditional on dnssec == true:
    backupkeys: bool | None
    # Conditional on type == slave:
    slaveip: str | None
    # Conditional on type == forward:
    forwarders: list[str] | None
    # Conditional on type == master:
    ttl: int | None
    baseip: str | None
    enable_updatepolicy: bool | None
    allowtransfer: list[str] | None
    # Conditional on type in [master, redirect]:
    nameserver: str | None
    mail: str | None
    serial: int | None
    refresh: str | None
    retry: str | None
    expire: str | None
    minimum: str | None
    # Conditional on type == master and enable_updatepolicy == true/false:
    updatepolicy: str | None
    allowupdate: list[str] | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindZone":
        return cls(
            id=data["id"],
            disabled=data["disabled"],
            name=data["name"],
            description=data["description"],
            type=data["type"],
            view=data["view"],
            allowquery=data["allowquery"],
            regdhcpstatic=data["regdhcpstatic"],
            reversev4=data.get("reversev4"),
            reversev6=data.get("reversev6"),
            rpz=data.get("rpz"),
            dnssec=data.get("dnssec"),
            backupkeys=data.get("backupkeys"),
            slaveip=data.get("slaveip"),
            forwarders=data.get("forwarders"),
            ttl=data.get("ttl"),
            baseip=data.get("baseip"),
            enable_updatepolicy=data.get("enable_updatepolicy"),
            allowtransfer=data.get("allowtransfer"),
            nameserver=data.get("nameserver"),
            mail=data.get("mail"),
            serial=data.get("serial"),
            refresh=data.get("refresh"),
            retry=data.get("retry"),
            expire=data.get("expire"),
            minimum=data.get("minimum"),
            updatepolicy=data.get("updatepolicy"),
            allowupdate=data.get("allowupdate"),
        )
