"""Model for the FirewallNatOneToOneMapping capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OneToOneNATMapping` component (already-captured evidence,
not a new live call). Not yet cross-checked against an approved
fixture from a real instance -- see `Endpoints.FIREWALL_NAT_ONE_TO_
ONE_MAPPINGS.verified` (`False`) and
`docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`. `external`/`source`/
`destination` are network-topology-identifying address/alias fields
and are redacted by default, matching `FirewallNatPortForward`'s
established convention.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FIREWALL_NAT_ONE_TO_ONE_MAPPING_IDENTIFYING_FIELDS = ("destination", "external", "source")


class FirewallNatOneToOneMapping(BaseModel):
    descr: str
    disabled: bool
    id: int
    interface: str
    ipprotocol: str
    natreflection: str | None
    nobinat: bool
    destination: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    external: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )
    source: str | None = Field(
        default=None,
        description="Identifying device metadata. Populated only when include_identifying_metadata=True.",
    )

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "FirewallNatOneToOneMapping":
        identifying = {field: data[field] for field in _FIREWALL_NAT_ONE_TO_ONE_MAPPING_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            disabled=data["disabled"],
            id=data["id"],
            interface=data["interface"],
            ipprotocol=data["ipprotocol"],
            natreflection=data["natreflection"],
            nobinat=data["nobinat"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
