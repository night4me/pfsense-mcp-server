"""Model for the InterfaceLAGG capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `InterfaceLAGG` component (already-captured evidence, not a
new live call). No secret material is present, and no field is
address-bearing -- `members`/`laggif` are ordinary interface
identifiers (core purpose of a LAGG-interface inventory capability)
and stay visible, matching `InterfaceBridge`'s established no-redaction
precedent for its own `members`/`bridgeif` fields. `lacptimeout`,
`lagghash`, and `failovermaster` are each schema-documented as "only
available when" a specific `proto` value is set -- treated as
genuinely possibly-absent keys (`.get()` with the schema's own
declared default), the same `install_version`-style precedent already
established for a field that can be legitimately missing from a live
response rather than merely null.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InterfaceLAGG(BaseModel):
    laggif: str | None
    descr: str
    members: list[str]
    proto: str
    lacptimeout: str
    lagghash: str
    failovermaster: str

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "InterfaceLAGG":
        return cls(
            laggif=data["laggif"],
            descr=data["descr"],
            members=data["members"],
            proto=data["proto"],
            lacptimeout=data.get("lacptimeout", "slow"),
            lagghash=data.get("lagghash", "l2,l3,l4"),
            failovermaster=data.get("failovermaster", "auto"),
        )
