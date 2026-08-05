"""Model for the FirewallNatPortForward capability endpoint.

GENERATED PROPOSAL — review before use. Field types/nullability were
derived from a saved OpenAPI discovery snapshot and cross-checked
against an approved fixture; identifying_fields is exactly what the
capability manifest declared, never inferred.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FIREWALL_NAT_PORT_FORWARD_IDENTIFYING_FIELDS = (
    "created_by",
    "destination",
    "source",
    "target",
    "updated_by",
)


class FirewallNatPortForward(BaseModel):
    associated_rule_id: str | None
    created_time: int | None
    descr: str
    destination_port: str | None
    disabled: bool
    id: int
    interface: str
    ipprotocol: str
    local_port: str
    natreflection: str | None
    nordr: bool
    nosync: bool
    protocol: str
    source_port: str | None
    updated_time: int | None
    created_by: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    destination: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    source: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    target: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    updated_by: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(cls, data: dict[str, Any], *, include_identifying_metadata: bool = False) -> "FirewallNatPortForward":
        identifying = {field: data[field] for field in _FIREWALL_NAT_PORT_FORWARD_IDENTIFYING_FIELDS}
        return cls(
            associated_rule_id=data["associated_rule_id"],
            created_time=data["created_time"],
            descr=data["descr"],
            destination_port=data["destination_port"],
            disabled=data["disabled"],
            id=data["id"],
            interface=data["interface"],
            ipprotocol=data["ipprotocol"],
            local_port=data["local_port"],
            natreflection=data["natreflection"],
            nordr=data["nordr"],
            nosync=data["nosync"],
            protocol=data["protocol"],
            source_port=data["source_port"],
            updated_time=data["updated_time"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
