"""Model for the FirewallNatOutboundMapping capability endpoint.

Field types/nullability were derived from the pinned v2.10 OpenAPI
schema's `OutboundNATMapping` component (already-captured evidence,
not a new live call). Not yet cross-checked against an approved
fixture from a real instance -- see `Endpoints.FIREWALL_NAT_OUTBOUND_
MAPPINGS.verified` (`False`) and `docs/PFSENSE_LEAST_PRIVILEGE_MATRIX.md`.
`source`/`destination`/`target` are network-topology-identifying
address/alias fields and are redacted by default, matching
`FirewallNatPortForward`'s established convention. `source_hash_key`
is a hash seed used only when `poolopts == 'source-hash'`, not an
address or credential, so it stays visible.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

_FIREWALL_NAT_OUTBOUND_MAPPING_IDENTIFYING_FIELDS = ("destination", "source", "target")


class FirewallNatOutboundMapping(BaseModel):
    descr: str
    destination_port: str | None
    disabled: bool
    id: int
    interface: str
    nat_port: str
    nonat: bool
    nosync: bool
    poolopts: str | None
    protocol: str | None
    source_hash_key: str
    source_port: str | None
    static_nat_port: bool
    target_subnet: int
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

    @classmethod
    def from_api(
        cls, data: dict[str, Any], *, include_identifying_metadata: bool = False
    ) -> "FirewallNatOutboundMapping":
        identifying = {field: data[field] for field in _FIREWALL_NAT_OUTBOUND_MAPPING_IDENTIFYING_FIELDS}
        return cls(
            descr=data["descr"],
            destination_port=data["destination_port"],
            disabled=data["disabled"],
            id=data["id"],
            interface=data["interface"],
            nat_port=data["nat_port"],
            nonat=data["nonat"],
            nosync=data["nosync"],
            poolopts=data["poolopts"],
            protocol=data["protocol"],
            source_hash_key=data["source_hash_key"],
            source_port=data["source_port"],
            static_nat_port=data["static_nat_port"],
            target_subnet=data["target_subnet"],
            **{field: (value if include_identifying_metadata else None) for field, value in identifying.items()},
        )
