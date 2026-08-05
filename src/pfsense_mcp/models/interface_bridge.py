"""Model for the InterfaceBridge capability endpoint.

Field types/nullability were derived from a saved OpenAPI discovery
snapshot and cross-checked against an approved fixture. No
identifying_fields: bridgeif/members are ordinary interface
identifiers (core purpose of a bridge-interface inventory capability)
and stay visible in both the model and the committed fixture. descr
is stricter here than at the model layer: it holds this install's
real custom label for the bridge, so only the committed test fixture
synthesizes it — runtime keeps it visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class InterfaceBridge(BaseModel):
    bridgeif: str | None
    descr: str
    id: int
    members: list[str]

    @classmethod
    def from_api(cls, data: dict[str, Any]) -> "InterfaceBridge":
        return cls(
            bridgeif=data["bridgeif"],
            descr=data["descr"],
            id=data["id"],
            members=data["members"],
        )
