"""Model for the InterfaceVlan capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `InterfaceVLAN` component (already-captured evidence, not a
new live call). Not yet cross-checked against an approved fixture
from a real instance -- see `Endpoints.INTERFACE_VLANS.verified`
(`False`). No field in this component carries secret material or
device-identifying address data (`if`/`vlanif` are interface names,
not addresses), so no redaction gate is required here.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InterfaceVlan(BaseModel):
    descr: str | None
    if_: str
    pcp: str | None
    tag: int
    vlanif: str | None

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "InterfaceVlan":
        return cls(
            descr=data["descr"],
            if_=data["if"],
            pcp=data["pcp"],
            tag=data["tag"],
            vlanif=data["vlanif"],
        )
