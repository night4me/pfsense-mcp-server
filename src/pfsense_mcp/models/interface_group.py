"""Model for the InterfaceGroup capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `InterfaceGroup` component (already-captured evidence, not a
new live call). No secret material and no address-bearing fields --
`ifname`/`members` are interface identifiers, matching the already-
shipped, unredacted treatment of `InterfaceBridge.bridgeif`/`.members`.
No redaction gate is required here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InterfaceGroup(BaseModel):
    descr: str
    ifname: str
    members: list[str]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "InterfaceGroup":
        return cls(
            descr=data["descr"],
            ifname=data["ifname"],
            members=data["members"],
        )
