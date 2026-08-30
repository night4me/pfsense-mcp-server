"""Model for the BINDSyncSettings capability endpoint.

Field types/nullability were derived from the live pfrest.org v2.10.2
OpenAPI document, then corrected against genuine live-LAB evidence:
`POST_V1_1_BIND_READ_QUALIFICATION.md`'s live read-only ceremony
(2026-08-30, BIND absent) observed `synconchanges` and `masterip` both
returned as `null` despite the schema declaring `nullable: false` for
both -- live server behavior is trusted over the schema's stale claim,
matching this project's own established precedent
(`DnsResolverSettings.sslcertref`/`.tlsport`,
`SystemRestApiVersion.install_version`). `synctimeout` was observed
non-null (`30`, the default) and matches the schema, so it stays a
plain `int`. No secret-bearing fields exist on this resource (the
credential for BIND sync lives on the separate, rejected
`BINDSyncRemoteHost` resource, never here).
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class BindSyncSettings(BaseModel):
    synconchanges: str | None
    synctimeout: int
    masterip: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "BindSyncSettings":
        return cls(
            synconchanges=data["synconchanges"],
            synctimeout=data["synctimeout"],
            masterip=data["masterip"],
        )
