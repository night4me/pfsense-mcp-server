"""Model for the InterfaceGRE capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `InterfaceGRE` component (already-captured evidence, not a
new live call). No secret material is present. 7 of 11 fields are
GRE tunnel-endpoint address data -- the heaviest single-candidate
redaction surface in this batch -- and are redacted by default,
matching `RoutingStaticRoute`'s established convention for its own
address fields. `if_` (the schema's `if`, renamed since `if` is a
Python keyword -- matching `InterfaceVlan.if_`'s established
precedent), `greif`, `descr`, and `add_static_route` are ordinary
interface identifiers/config, not address data, and stay visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_INTERFACE_GRE_IDENTIFYING_FIELDS = (
    "remote_addr",
    "tunnel_local_addr",
    "tunnel_remote_addr",
    "tunnel_remote_net",
    "tunnel_local_addr6",
    "tunnel_remote_addr6",
    "tunnel_remote_net6",
)


class InterfaceGRE(BaseModel):
    if_: str
    greif: str | None
    descr: str
    add_static_route: bool
    remote_addr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_local_addr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_remote_addr: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_remote_net: int | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_local_addr6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_remote_addr6: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    tunnel_remote_net6: int | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "InterfaceGRE":
        identifying = {field: data[field] for field in _INTERFACE_GRE_IDENTIFYING_FIELDS}
        return cls(
            if_=data["if"],
            greif=data["greif"],
            descr=data["descr"],
            add_static_route=data["add_static_route"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
